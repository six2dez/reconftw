// resolve.go — 6 active DNS resolution Tasks.
//
// STAGING CONTRACT (doc.go): Tasks write raw hostnames to per-source staging
// files at filepath.Join(app.Target.WorkDir, "inputs", "resolved."+toolName+".txt").
// Tasks do NOT call app.Tree.Append directly — MergeStage(ctx, app, "resolved")
// (merge.go) is the single app.Tree.Append caller for the resolved stage.
//
// STREAM PATTERN (XCUT-09): puredns and long-running dnsx calls use
// app.Tools.Stream (not Run) so the heartbeat channel fires during long scans.
//
// BACKEND-AGNOSTIC (D-05): No task branches on cfg.Axiom. AxiomBackend vs
// LocalBackend dispatch is transparent to tasks via the Runner abstraction.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-02-PLAN.md Task 1.
package subdomains

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Helper: staging path helpers for resolved Tasks
// -------------------------------------------------------------------------

// resolvedStagingPath returns the path to the per-tool resolved staging file.
// Pattern: <workDir>/inputs/resolved.<toolName>.txt
func resolvedStagingPath(app *appctx.AppContext, toolName string) string {
	return filepath.Join(app.Target.WorkDir, "inputs", "resolved."+toolName+".txt")
}

// passiveMergedPath returns the path to the merged passive staging file produced
// by MergeStage(ctx, app, "passive"). Resolution tasks read this as their input list.
func passiveMergedPath(app *appctx.AppContext) string {
	return filepath.Join(app.Target.WorkDir, "inputs", "passive.merged.txt")
}

// runStreamTask runs a tool via Stream, collects non-empty stdout lines
// (ignoring stderr), writes them to the resolved staging file, and returns
// the task.Result. Used for puredns and long-running dnsx invocations (XCUT-09).
//
// A tool-execution error degrades to StatusDone (CONTINUE_ON_TOOL_ERROR bash
// parity) via degradeResolveTool; scope/ctx-cancel errors still propagate.
func runStreamTask(ctx context.Context, app *appctx.AppContext, toolName string, args []string) (task.Result, error) {
	ch, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		return degradeResolveTool(ctx, app, toolName, err)
	}

	var lines []string
	for ev := range ch {
		if ev.IsErr {
			continue // skip stderr lines
		}
		line := strings.ToLower(strings.TrimSpace(string(ev.Line)))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writeResolvedStagingFile(app, toolName, lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"resolved_found": len(lines)},
	}, nil
}

// runExecTask runs a tool via Run (buffered), collects stdout lines, writes to
// the resolved staging file, and returns the task.Result. Used for short-lived
// dnsx calls where streaming is unnecessary.
//
// A tool-execution error degrades to StatusDone (CONTINUE_ON_TOOL_ERROR bash
// parity) via degradeResolveTool; scope/ctx-cancel errors still propagate.
func runExecTask(ctx context.Context, app *appctx.AppContext, toolName string, args []string) (task.Result, error) {
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return degradeResolveTool(ctx, app, toolName, err)
	}

	var lines []string
	for _, raw := range strings.Split(string(res.Stdout), "\n") {
		line := strings.ToLower(strings.TrimSpace(raw))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writeResolvedStagingFile(app, toolName, lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"resolved_found": len(lines)},
	}, nil
}

// writeResolvedStagingFile writes hostnames (one per line) to the per-tool
// resolved staging file, or REMOVES that file when lines is empty. Returns the
// staging path in both cases.
//
// F3 (phase 15): write-or-REMOVE via output.StageLines, same contract as
// writeStagingFile (passive) and writeScrapingStagingFile. It previously wrote
// an EMPTY file for zero hostnames, which is equivalent for the glob-based
// MergeAllSubdomains but leaves "the resolver ran and resolved nothing"
// indistinguishable from "the resolver did not run" for anything that stats the
// path.
//
// NOTE this site is NOT reported by internal/modules/staging_contract_test.go:
// its path comes from resolvedStagingPath(), a THIRD level of indirection that
// the detector's two-level filepath.Join tracking does not reach. It is a
// genuine merger-globbed staging write (inputs/resolved.*.txt) all the same, so
// it is migrated by hand rather than left because the detector was silent.
func writeResolvedStagingFile(app *appctx.AppContext, toolName string, lines []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("resolve %s: mkdir inputs/: %w", toolName, err)
	}
	stagingPath := resolvedStagingPath(app, toolName)
	if err := output.StageLines(stagingPath, lines); err != nil {
		return "", fmt.Errorf("resolve %s: write staging file: %w", toolName, err)
	}
	return stagingPath, nil
}

// -------------------------------------------------------------------------
// Shared resolve helpers — hostname/IP hygiene, dnsregs parsing, artefact
// writers, and the CONTINUE_ON_TOOL_ERROR degrade predicate (PAR-01).
// -------------------------------------------------------------------------

// hostnameRE mirrors bash sub_dns's hostname validation grep
// (`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`) — rejects IPs, empty labels,
// and lines with whitespace (e.g. an MX "10 mail.example.com" priority string).
var hostnameRE = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$`)

// normalizeHost lowercases, trims, and strips a leading "*." wildcard label and
// a trailing "." (bash: sed -e 's/^\*\.//' -e 's/\.$//').
func normalizeHost(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimSuffix(s, ".")
	return s
}

// inScope reports whether host is within the configured scope. It reuses the
// canonical app.Tree.InScope check (the same anchored filter MergeStage uses) —
// T-13-01-01 mitigation: reverse-IP/dnsregs output can include off-scope hosts.
// Returns true when no tree/scope filter is configured (tests, unscoped runs);
// MergeStage remains the final authority.
func inScope(app *appctx.AppContext, host string) bool {
	if app.Tree == nil {
		return true
	}
	return app.Tree.InScope(host)
}

// isValidIP reports whether s parses as an IPv4/IPv6 literal.
func isValidIP(s string) bool { return net.ParseIP(s) != nil }

// isPublicIP reports whether s is a routable public address (rejects loopback,
// RFC1918 private, link-local, multicast, unspecified) — bash filters these out
// of the reverse-IP feed and the hosts/ips enrichment.
func isPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast() && !ip.IsUnspecified()
}

// orderedStringSet collects distinct strings preserving first-insertion order
// (deterministic staging output).
type orderedStringSet struct {
	seen  map[string]bool
	items []string
}

func newOrderedStringSet() *orderedStringSet {
	return &orderedStringSet{seen: make(map[string]bool)}
}

func (s *orderedStringSet) add(v string) {
	if v == "" || s.seen[v] {
		return
	}
	s.seen[v] = true
	s.items = append(s.items, v)
}

func (s *orderedStringSet) list() []string { return s.items }
func (s *orderedStringSet) len() int       { return len(s.items) }

// dnsregRecord is the projection of one dnsx -recon -json line SubDNSTask needs:
// the host, its A/AAAA addresses, and every string value in the record (the jq
// `.. | strings` bash uses to harvest in-scope hostnames from cname/ns/mx/host).
type dnsregRecord struct {
	host       string
	a          []string
	aaaa       []string
	allStrings []string
}

// parseDNSRegs parses the dnsx -recon -json JSONL artefact into dnsregRecords.
// Each line is decoded into a generic map so schema variations (mx priority
// strings, nested arrays) never abort the parse — mirroring jq's leniency.
func parseDNSRegs(data []byte) []dnsregRecord {
	var recs []dnsregRecord
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		rec := dnsregRecord{allStrings: collectStrings(m)}
		if h, ok := m["host"].(string); ok {
			rec.host = h
		}
		rec.a = toStringSlice(m["a"])
		rec.aaaa = toStringSlice(m["aaaa"])
		recs = append(recs, rec)
	}
	return recs
}

// collectStrings recursively gathers every string value in v (jq `.. | strings`).
func collectStrings(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, e := range t {
			out = append(out, collectStrings(e)...)
		}
		return out
	case map[string]any:
		var out []string
		for _, e := range t {
			out = append(out, collectStrings(e)...)
		}
		return out
	default:
		return nil
	}
}

// toStringSlice coerces a decoded JSON array into a []string (non-strings dropped).
func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// writeArtefactFile writes data verbatim to <workDir>/artefacts/<name>, creating
// artefacts/ if needed. Used for the raw dnsregs records artefact (PAR-01).
func writeArtefactFile(app *appctx.AppContext, name string, data []byte) (string, error) {
	dir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("resolve: mkdir artefacts/: %w", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("resolve: write artefacts/%s: %w", name, err)
	}
	return p, nil
}

// writeSubdomainsFile writes newline-delimited lines to <workDir>/subdomains/<name>,
// creating subdomains/ if needed. Used for the bash-contract subdomains_ips.txt
// IP-seed consumed by portscan (PAR-04) and geo.
func writeSubdomainsFile(app *appctx.AppContext, name string, lines []string) (string, error) {
	dir := filepath.Join(app.Target.WorkDir, "subdomains")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("resolve: mkdir subdomains/: %w", err)
	}
	p := filepath.Join(dir, name)
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("resolve: write subdomains/%s: %w", name, err)
	}
	return p, nil
}

// isPropagatingError reports whether err from a tool call MUST still propagate
// (return StatusErrored) rather than degrade to StatusDone. Scope violations
// (ErrScope) and context cancellation/deadline are NOT tool degrades — the
// scheduler's ErrScope re-propagation guard and ctx cancellation depend on them
// surfacing. Every other tool-execution error is a non-fatal degrade
// (CONTINUE_ON_TOOL_ERROR bash parity). See degradeResolveTool + SubDNSTask.
func isPropagatingError(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return true
	}
	return stderrors.Is(err, coreerrors.ErrScope) ||
		stderrors.Is(err, context.Canceled) ||
		stderrors.Is(err, context.DeadlineExceeded)
}

// degradeResolveTool implements CONTINUE_ON_TOOL_ERROR (bash) parity for the
// resolve DNS spine (module="subdomains", fail_fast). A tool-EXECUTION error
// from app.Tools.Run/Stream is non-fatal: log a warning and write an (empty)
// staging file so one flaky puredns/dnsx does not abort the whole subs run —
// mirroring the established SubAnalyticsTask best-effort precedent. Scope
// violations (ErrScope) and context cancellation/deadline STILL return
// StatusErrored so the scheduler's ErrScope re-propagation guard (scheduler.go
// errors.Is(ErrScope)) and cancellation keep working. A staging-file WRITE error
// is a real local FS fault and stays fatal (StatusErrored).
//
// Accepted trade-off (checker LOW #5): degrading across all ~6 resolve callers
// means a TOTAL resolver outage yields an empty-but-Done subs run rather than an
// aborted one — the intended bash parity. The resolvers.health gate remains the
// real pre-resolution guard.
func degradeResolveTool(ctx context.Context, app *appctx.AppContext, toolName string, cause error) (task.Result, error) {
	if isPropagatingError(ctx, cause) {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: %w", toolName, cause)
	}
	if app.Log != nil {
		app.Log.Warn("resolve: tool failed (non-fatal degrade)",
			"tool", toolName, "error", cause.Error())
	}
	stagingPath, writeErr := writeResolvedStagingFile(app, toolName, nil)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}
	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"resolved_found": 0},
	}, nil
}

// -------------------------------------------------------------------------
// SubActiveTask — puredns resolve (XCUT-09: Stream)
// -------------------------------------------------------------------------

// SubActiveTask resolves the passive merged subdomain list using puredns.
// Writes staging file: inputs/resolved.active.txt
// Reads input from: inputs/passive.merged.txt (output of MergeStage("passive"))
type SubActiveTask struct{}

func (SubActiveTask) Name() string        { return "subdomains.active" }
func (SubActiveTask) Module() string      { return "subdomains" }
func (SubActiveTask) DependsOn() []string { return nil }

func (SubActiveTask) Description() string {
	return "DNS resolution of passive subdomain set via puredns (wildcard-filtered)"
}

func (SubActiveTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// Run resolves the passive merged subdomain list with puredns, writing resolved
// hostnames to inputs/resolved.active.txt. Uses Stream for XCUT-09 heartbeat.
func (SubActiveTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "puredns"
	cfg := app.Cfg
	inputFile := passiveMergedPath(app)
	args := []string{
		"resolve", inputFile,
		"-r", cfg.Paths.Resolvers,
		"--wildcard-tests", strconv.Itoa(cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit),
		"--wildcard-batch", strconv.Itoa(cfg.Subdomains.DNSResolve.PurednsWildcardbatchLimit),
		"--rate-limit", strconv.Itoa(cfg.Subdomains.DNSResolve.PurednsPublicLimit),
		"--rate-limit-trusted", strconv.Itoa(cfg.Subdomains.DNSResolve.PurednsTrustedLimit),
		"-rt", cfg.Paths.ResolversTrusted,
		"--quiet",
	}
	result, err := runStreamTask(ctx, app, toolName, args)
	if err != nil {
		return result, err
	}
	// Rename the default "active" staging file explicitly.
	defaultPath := resolvedStagingPath(app, toolName)
	activePath := resolvedStagingPath(app, "active")
	if defaultPath != activePath {
		if renameErr := os.Rename(defaultPath, activePath); renameErr != nil {
			// F3 (phase 15): the rename source is ABSENT precisely when this run
			// resolved nothing — writeResolvedStagingFile removed it. Leaving
			// the rename to fail silently would strand a PREVIOUS run's
			// resolved.active.txt for MergeAllSubdomains to republish, which is
			// the exact leak the write-or-remove contract closes one layer down.
			// Clear the destination so run B's empty result is what the merge
			// sees. Any other rename failure is still non-fatal.
			if os.IsNotExist(renameErr) {
				if rmErr := os.Remove(activePath); rmErr != nil && !os.IsNotExist(rmErr) {
					if app.Log != nil {
						app.Log.Debug("subdomains.active: clear stale active staging failed",
							"path", activePath, "err", rmErr)
					}
				}
			}
		}
		result.Outputs = []string{activePath}
	}
	return result, nil
}

// -------------------------------------------------------------------------
// SubTLSTask — tlsx TLS certificate pivot (Stream)
// -------------------------------------------------------------------------

// SubTLSTask harvests subdomains from TLS certificates via tlsx.
// Writes staging file: inputs/resolved.tls.txt
type SubTLSTask struct{}

func (SubTLSTask) Name() string        { return "subdomains.tls" }
func (SubTLSTask) Module() string      { return "subdomains" }
func (SubTLSTask) DependsOn() []string { return nil }

func (SubTLSTask) Description() string {
	return "TLS certificate subdomain pivoting via tlsx (SAN/CN extraction)"
}

func (SubTLSTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.TLSPivot.Enabled
}

// Run runs tlsx against the passive merged domain list, writing TLS-discovered
// hostnames to inputs/resolved.tls.txt.
func (SubTLSTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "tlsx"
	inputFile := passiveMergedPath(app)
	args := []string{
		"-l", inputFile,
		"-silent",
		"-san",
		"-cn",
		"-re", app.Target.Domain,
	}
	return runStreamTask(ctx, app, toolName, args)
}

// -------------------------------------------------------------------------
// SubNoerrorTask — dnsx NOERROR filter (Stream for long runs)
// -------------------------------------------------------------------------

// SubNoerrorTask runs dnsx with -rcode noerror to filter the passive set
// to only hostnames with NOERROR DNS responses.
// Writes staging file: inputs/resolved.noerror.txt
type SubNoerrorTask struct{}

func (SubNoerrorTask) Name() string        { return "subdomains.noerror" }
func (SubNoerrorTask) Module() string      { return "subdomains" }
func (SubNoerrorTask) DependsOn() []string { return nil }

func (SubNoerrorTask) Description() string {
	return "DNS NOERROR filter of passive subdomain set via dnsx"
}

func (SubNoerrorTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// Run runs dnsx -rcode noerror against the passive merged list, writing
// NOERROR-only hostnames to inputs/resolved.noerror.txt. Uses Stream for XCUT-09.
func (SubNoerrorTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dnsx"
	cfg := app.Cfg
	inputFile := passiveMergedPath(app)
	args := []string{
		"-l", inputFile,
		"-silent",
		"-rcode", "noerror",
	}
	if cfg.Subdomains.DNSResolve.DNSXThreads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXThreads))
	}
	if cfg.Subdomains.DNSResolve.DNSXRateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXRateLimit))
	}
	return runStreamTask(ctx, app, toolName, args)
}

// -------------------------------------------------------------------------
// SubDNSTask — dnsx multi-record (Exec, bounded output)
// -------------------------------------------------------------------------

// SubDNSTask mirrors bash sub_dns (modules/subdomains.sh:915-950). It runs dnsx
// in recon multi-record JSON mode and, unlike the previous lossy A/AAAA/CNAME/NS/
// MX text call, PERSISTS the payload:
//
//   - artefacts/subdomains_dnsregs.json — the raw dnsx -recon -json records
//     artefact (PAR-01 records contract; previously discarded).
//   - subdomains/subdomains_ips.txt     — "host - ip" pairs (A/AAAA), the IP-seed
//     consumed by portscan (PAR-04) and geo.
//   - inputs/resolved.dns.txt           — in-scope hostnames harvested from the
//     dnsregs strings AND from the folded hakip2host reverse-IP step (gated by
//     cfg.Subdomains.ReverseIP.Enabled), fed into MergeStage.
type SubDNSTask struct{}

func (SubDNSTask) Name() string        { return "subdomains.dns" }
func (SubDNSTask) Module() string      { return "subdomains" }
func (SubDNSTask) DependsOn() []string { return nil }

func (SubDNSTask) Description() string {
	return "Multi-record DNS resolution of passive subdomain set via dnsx"
}

func (SubDNSTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// Run runs dnsx in recon multi-record JSON mode, persists the records artefact +
// IP-pairs file, harvests in-scope hostnames (records + gated hakip2host
// reverse-IP), and writes them to inputs/resolved.dns.txt for MergeStage.
//
// A dnsx tool-execution error degrades to StatusDone with empty artefacts
// (CONTINUE_ON_TOOL_ERROR bash parity); scope/ctx-cancel errors still propagate.
func (SubDNSTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dnsx"
	cfg := app.Cfg
	inputFile := passiveMergedPath(app)

	// dnsx recon multi-record JSON. bash arg vector (modules/subdomains.sh:922):
	//   dnsx -r <resolvers_trusted> -recon -silent -retry 3 -json < subdomains.txt
	// We pass input via -l (no stdin) and capture stdout as the dnsregs artefact
	// (bash uses -o subdomains/subdomains_dnsregs.json).
	args := []string{
		"-l", inputFile,
		"-r", cfg.Paths.ResolversTrusted,
		"-recon",
		"-silent",
		"-retry", "3",
		"-json",
	}
	if cfg.Subdomains.DNSResolve.DNSXThreads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXThreads))
	}
	if cfg.Subdomains.DNSResolve.DNSXRateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXRateLimit))
	}

	var dnsregs []byte
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		if isPropagatingError(ctx, err) {
			return task.Result{Status: task.StatusErrored}, fmt.Errorf("%s: %w", toolName, err)
		}
		// Non-fatal tool degrade: log + continue with empty records so one flaky
		// resolver does not abort the fail_fast subs stage (bash CONTINUE_ON_TOOL_ERROR).
		if app.Log != nil {
			app.Log.Warn("resolve: dnsx recon failed (non-fatal degrade)",
				"tool", toolName, "error", err.Error())
		}
	} else {
		dnsregs = res.Stdout
	}

	// Persist the records artefact verbatim (PAR-01 contract).
	if _, err := writeArtefactFile(app, "subdomains_dnsregs.json", dnsregs); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Parse records → in-scope hostnames + host→IP pairs + distinct public IPs.
	hostSet := newOrderedStringSet()
	pubIPs := newOrderedStringSet()
	var ipPairs []string
	for _, rec := range parseDNSRegs(dnsregs) {
		// (a) In-scope hostnames from every string value (jq '.. | strings').
		for _, s := range rec.allStrings {
			if h := normalizeHost(s); hostnameRE.MatchString(h) && inScope(app, h) {
				hostSet.add(h)
			}
		}
		// (b) host→IP pairs (A + AAAA) → subdomains_ips.txt; public IPs → reverse feed.
		host := normalizeHost(rec.host)
		for _, ip := range append(append([]string{}, rec.a...), rec.aaaa...) {
			ip = strings.TrimSpace(ip)
			if !isValidIP(ip) {
				continue
			}
			if host != "" {
				ipPairs = append(ipPairs, host+" - "+ip)
			}
			if isPublicIP(ip) {
				pubIPs.add(ip)
			}
		}
	}

	// IP-pairs file (portscan + geo IP-seed; bash subdomains/subdomains_ips.txt).
	if _, err := writeSubdomainsFile(app, "subdomains_ips.txt", ipPairs); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// hakip2host reverse-IP fold (gated). Adds in-scope hostnames to the same set.
	// DEFER (→ Phase 14): the ip.thc.org curl reverse source (bash sub_dns:937-946)
	// is a secondary/niche provider and is intentionally NOT ported here.
	if cfg.Subdomains.ReverseIP.Enabled {
		for _, h := range reverseIPHosts(ctx, app, pubIPs.list()) {
			hostSet.add(h)
		}
	}

	// Write the collected in-scope hostnames to the resolved.dns staging file.
	stagingPath, werr := writeResolvedStagingFile(app, "dns", hostSet.list())
	if werr != nil {
		return task.Result{Status: task.StatusErrored}, werr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats: map[string]int{
			"resolved_found": hostSet.len(),
			"ip_pairs":       len(ipPairs),
		},
	}, nil
}

// -------------------------------------------------------------------------
// SubSRVTask — dnsx SRV (Exec, bounded output)
// -------------------------------------------------------------------------

// SubSRVTask runs dnsx SRV record enumeration.
// Writes staging file: inputs/resolved.srv.txt
type SubSRVTask struct{}

func (SubSRVTask) Name() string        { return "subdomains.srv" }
func (SubSRVTask) Module() string      { return "subdomains" }
func (SubSRVTask) DependsOn() []string { return nil }

func (SubSRVTask) Description() string {
	return "SRV record enumeration of passive subdomain set via dnsx"
}

func (SubSRVTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// Run runs dnsx -srv against the passive merged list, writing SRV-discovered
// hostnames to inputs/resolved.srv.txt.
func (SubSRVTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dnsx"
	cfg := app.Cfg
	inputFile := passiveMergedPath(app)
	args := []string{
		"-l", inputFile,
		"-srv",
		"-silent",
	}
	if cfg.Subdomains.DNSResolve.DNSXThreads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXThreads))
	}
	return runExecTask(ctx, app, toolName, args)
}

// SubPTRTask REMOVED (13-01 Task 2): it was dead code — it read inputs/asn.ips.txt
// which no task ever writes, and it ran in the resolve stage BEFORE the asn task
// that would produce IPs. The default-path reverse-IP capability is now covered by
// the hakip2host fold in SubDNSTask (reverseip.go). The full ASN-CIDR PTR sweep
// (bash sub_ptr_cidrs, gated PTR_SWEEP=false by default — not on the recon/all
// default path) is DEFERRED to Phase 14; the SubPTRSweep config struct + PTRSweep
// default are retained as dead scaffold for that deferred feature.

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(SubActiveTask{}) }
func init() { task.Register(SubTLSTask{}) }
func init() { task.Register(SubNoerrorTask{}) }
func init() { task.Register(SubDNSTask{}) }
func init() { task.Register(SubSRVTask{}) }
