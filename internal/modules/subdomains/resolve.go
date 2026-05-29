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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
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
func runStreamTask(ctx context.Context, app *appctx.AppContext, toolName string, args []string) (task.Result, error) {
	ch, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: Stream failed: %w", toolName, err)
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
func runExecTask(ctx context.Context, app *appctx.AppContext, toolName string, args []string) (task.Result, error) {
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: Run failed: %w", toolName, err)
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
// resolved staging file. Creates inputs/ directory if needed.
func writeResolvedStagingFile(app *appctx.AppContext, toolName string, lines []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("resolve %s: mkdir inputs/: %w", toolName, err)
	}
	stagingPath := resolvedStagingPath(app, toolName)
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(stagingPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("resolve %s: write staging file: %w", toolName, err)
	}
	return stagingPath, nil
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
			_ = renameErr // non-fatal if already at the right path
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

// SubDNSTask runs dnsx with A/AAAA/CNAME/NS/MX record resolution.
// Writes staging file: inputs/resolved.dns.txt
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

// Run runs dnsx with multi-record flags against the passive merged list,
// writing resolved hostnames to inputs/resolved.dns.txt.
func (SubDNSTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "dnsx"
	cfg := app.Cfg
	inputFile := passiveMergedPath(app)
	args := []string{
		"-l", inputFile,
		"-a", "-aaaa", "-cname", "-ns", "-mx",
		"-silent",
	}
	if cfg.Subdomains.DNSResolve.DNSXThreads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXThreads))
	}
	if cfg.Subdomains.DNSResolve.DNSXRateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.Subdomains.DNSResolve.DNSXRateLimit))
	}
	return runExecTask(ctx, app, toolName, args)
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

// -------------------------------------------------------------------------
// SubPTRTask — puredns reverse PTR sweep (Stream)
// -------------------------------------------------------------------------

// SubPTRTask performs reverse PTR lookups on discovered IP ranges via puredns.
// Input: inputs/asn.ips.txt (written by ASN enrichment stage, plan-05).
// Writes staging file: inputs/resolved.ptr.txt
type SubPTRTask struct{}

func (SubPTRTask) Name() string        { return "subdomains.ptr" }
func (SubPTRTask) Module() string      { return "subdomains" }
func (SubPTRTask) DependsOn() []string { return nil }

func (SubPTRTask) Description() string {
	return "Reverse PTR sweep of ASN IP ranges via puredns"
}

func (SubPTRTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.PTRSweep.Enabled
}

// Run runs puredns reverse on the IP list from inputs/asn.ips.txt, writing
// reverse-PTR hostnames to inputs/resolved.ptr.txt. Uses Stream for XCUT-09.
func (SubPTRTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "puredns"
	cfg := app.Cfg
	ipsFile := filepath.Join(app.Target.WorkDir, "inputs", "asn.ips.txt")
	args := []string{
		"reverse",
		ipsFile,
		"-r", cfg.Paths.Resolvers,
		"--quiet",
	}
	return runStreamTask(ctx, app, toolName, args)
}

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(SubActiveTask{}) }
func init() { task.Register(SubTLSTask{}) }
func init() { task.Register(SubNoerrorTask{}) }
func init() { task.Register(SubDNSTask{}) }
func init() { task.Register(SubSRVTask{}) }
func init() { task.Register(SubPTRTask{}) }
