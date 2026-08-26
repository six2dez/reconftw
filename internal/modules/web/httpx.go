// httpx.go — HTTPXTask: HTTP probe (httpx), DAG root for the web pipeline.
//
// HTTPXTask is the dependency root — DependsOn returns nil. All other web
// Tasks DependsOn "web.httpx" (directly or transitively). The entire web
// pipeline is best_effort (D-W12); httpx is NOT fail_fast.
//
// INPUT BOUNDARY (D-W10):
//  1. ctx value keyed by hostsFileKey — set by runWebCmd via CtxWithHostsFile
//  2. artefacts/hosts.jsonl (prior web run output)
//  3. artefacts/subdomains.jsonl (prior subs run; host field extracted)
//  4. fail-fast with "no host list: run `subs` first or pass --hosts <file>"
//
// OUTPUT SCHEMA (D-W11 hosts.jsonl):
//
//	{host, url, scheme, port, status, title, tech[], content_length, ip, cdn}
//
// The cdn field is populated empty here; cdncheck Task (Phase 5 plan-03) fills it.
//
// ARG VECTOR (RESEARCH §httpx — verbatim v1 form; [ASSUMED] flags noted):
//
//	httpx -follow-host-redirects -random-agent -status-code
//	      -p <ports> -threads <n> -rl <n> -timeout <n>
//	      -silent -retries 2 -title -web-server -tech-detect
//	      -location -no-color -json -o <output-file>
//	      -l <input-file>
//
// [ASSUMED: -follow-host-redirects is the correct v1 flag form; verify at install.]
//
// Source: .planning/phases/05-web-pipeline-e2e/05-01-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // used for input-file hash only, not crypto
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// hostsFileKey is the context key type for the --hosts flag value.
// Using a private unexported type prevents key collisions from other packages.
type hostsFileKey struct{}

// CtxWithHostsFile returns a new context carrying the --hosts flag value.
// Called by runWebCmd before executing the web pipeline.
func CtxWithHostsFile(ctx context.Context, hostsFile string) context.Context {
	return context.WithValue(ctx, hostsFileKey{}, hostsFile)
}

// hostsFileFromCtx extracts the --hosts flag value from a context.
// Returns "" if not set.
func hostsFileFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(hostsFileKey{}).(string); ok {
		return v
	}
	return ""
}

// HostRecord is the D-W11 JSONL schema for artefacts/hosts.jsonl.
// Written by HTTPXTask.Run after parsing httpx's JSONL output.
type HostRecord struct {
	Host          string   `json:"host"`
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	Port          string   `json:"port"`
	Status        int      `json:"status"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	ContentLength int      `json:"content_length"`
	IP            string   `json:"ip"`
	CDN           string   `json:"cdn"` // populated by cdncheck Task later
}

// httpxRaw is the subset of httpx JSONL fields we parse.
// httpx outputs more fields; we only map the ones in D-W11.
//
// FIELD NAMES AND TYPES ARE LOAD-BEARING — verified against real httpx v1.6
// `-json` output, not inferred. Three of them were wrong, and the combination
// meant this parser had NEVER successfully decoded a single real httpx record:
//
//	port           httpx emits a STRING ("80"), not a number. Decoding it into
//	               an int made json.Unmarshal fail, which discarded the WHOLE
//	               line — "all 20 lines failed to parse". This is what emptied
//	               artefacts/hosts.jsonl and, through it, the entire web layer:
//	               0 live hosts and 2 finding classes against v1's 12 and 50.
//	status_code    underscore, not "status-code". Silent zero.
//	content_length underscore, not "content-length". Silent zero.
//
// The two underscore fields would have been silent data loss on their own; the
// port type mismatch was fatal. See TestParseHTTPXOutputRealFixture, which pins
// all three against captured real output.
type httpxRaw struct {
	Input         string   `json:"input"`
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	Port          string   `json:"port"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	Technologies  []string `json:"tech"`
	ContentLength int      `json:"content_length"`
	Host          string   `json:"host"`
	A             []string `json:"a"` // resolved IPs from httpx
}

// HTTPXTask runs httpx HTTP probe and writes hosts.jsonl.
type HTTPXTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *HTTPXTask) Name() string { return "web.httpx" }

// Module returns the owning module group.
func (t *HTTPXTask) Module() string { return "web" }

// Description returns a human-readable one-line description.
func (t *HTTPXTask) Description() string { return "HTTP probe (httpx)" }

// Enabled reports whether this task should run.
// Maps to cfg.Web.Probe.Enabled (WEBPROBEFULL legacy alias).
func (t *HTTPXTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Probe.Enabled
}

// DependsOn returns nil — HTTPXTask IS the DAG root (D-W12).
func (t *HTTPXTask) DependsOn() []string { return nil }

// Run executes httpx and writes parsed records to artefacts/hosts.jsonl.
//
// Input resolution follows D-W10 precedence:
//  1. ctx-carried --hosts FILE (set via CtxWithHostsFile by runWebCmd)
//  2. artefacts/hosts.jsonl — prior web run
//  3. artefacts/subdomains.jsonl — prior subs run (extracts host fields)
//  4. fail-fast error
func (t *HTTPXTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "httpx"
	cfg := app.Cfg

	// Step 1: Resolve input file (D-W10 precedence).
	inputFile, err := resolveHostInput(ctx, app)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Validate --hosts path (T-05-01 / WR-08: operator-trust model).
	if err := checkHostsFileReadable(inputFile); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Compute input hash for checkpoint idempotency (informational).
	inputHash, _ := fileHash(inputFile)
	// The input COUNT is what makes "produced nothing" answerable: nothing from
	// zero hosts is correct, nothing from 30 hosts is a defect. Cheap — the file
	// is already being read for fileHash.
	inputCount := countNonEmptyLines(inputFile)

	// Step 2: Build output file path.
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: mkdir artefacts/: %w", err)
	}
	artefactFile := filepath.Join(artefactsDir, "hosts.jsonl")

	// httpx's RAW output goes to a staging path, never onto the artefact.
	//
	// CR-02 (phase 16 review, proven in 17-06): this used to be artefactFile
	// itself, and that is destructive in two separate ways, both observed:
	//
	//  1. httpx CREATES AND TRUNCATES its -o file. Verified on httpx v1.9.0:
	//       $ httpx -l k2in.txt -o k2out.jsonl -silent -duc -json   (no live host)
	//       $ ls -l k2out.jsonl  ->  0 bytes, exit 0
	//     A run that finds nothing still leaves a 0-byte -o. Pointing -o at the
	//     artefact therefore erases it even on a clean, successful run.
	//  2. Step 5 below reads outputFile back and parses it as httpx output. When
	//     -o WAS the artefact and httpx wrote nothing, this parsed subdomains.geo's
	//     enrichment records as if they were httpx's own output and republished
	//     them stripped — ip/asn/country silently blanked. Observed in the CR-02
	//     RED run: {"host":"api.example.com",…,"ip":""} where the input carried
	//     "ip":"93.184.216.34","asn":"AS15133".
	//
	// The artefact is still written, exactly as before, through app.Tree.Append
	// (scope-enforcing) in step 6 — that is the ONLY writer of it here now.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: mkdir inputs/: %w", err)
	}
	outputFile := filepath.Join(inputsDir, "hosts.httpx.raw.jsonl")

	// Step 3: Build arg vector (RESEARCH §httpx verbatim v1 form).
	// Ports: cfg.Web.Probe.Ports; "" → omit -p flag (httpx uses its default).
	// Threads: cfg.Web.Probe.Threads; 0 → omit.
	// RateLimit: cfg.Web.Probe.RateLimit; 0 → omit.
	// Timeout: cfg.Web.Probe.TimeoutSeconds; 0 → omit.
	args := []string{
		"-follow-host-redirects", // [ASSUMED: verify exact flag at install — DoD-1]
		"-random-agent",
		"-status-code",
	}
	// Ports: 80,443 plus the uncommon list when web.probe.uncommon_enabled, which
	// is v1's single-pass shape (modules/web.sh:139 probe_ports="${WEBPROBE_PORTS:-
	// 80,443,${UNCOMMON_PORTS_WEB:-}}"). uncommon_enabled/threads/timeout were
	// declared in config, defaulted ON, aliased for migrating v1 operators — and
	// read by nothing, so v2 probed 80,443 only. See uncommon_ports.go.
	if ports := probePorts(cfg); ports != "" {
		args = append(args, "-p", ports)
	}
	// Thread and timeout budgets follow the port set: probing ~94 ports per host
	// with the two-port budget is what makes a wide sweep look like a hang. v1
	// switches to HTTPX_UNCOMMONPORTS_THREADS/_TIMEOUT for exactly this reason.
	threads := cfg.Web.Probe.Threads
	timeoutSec := cfg.Web.Probe.TimeoutSeconds
	if uncommonPortsEnabled(cfg) {
		if cfg.Web.Probe.UncommonThreads > 0 {
			threads = cfg.Web.Probe.UncommonThreads
		}
		if cfg.Web.Probe.UncommonTimeout > 0 {
			timeoutSec = cfg.Web.Probe.UncommonTimeout
		}
	}
	if threads > 0 {
		args = append(args, "-threads", strconv.Itoa(threads))
	}
	if rl := cfg.Web.Probe.RateLimit; rl > 0 {
		args = append(args, "-rl", strconv.Itoa(rl))
	}
	if timeoutSec > 0 {
		args = append(args, "-timeout", strconv.Itoa(timeoutSec))
	}
	args = append(args,
		"-silent",
		"-retries", "2",
		"-title",
		"-web-server",
		"-tech-detect",
		"-location",
		"-no-color",
		"-json",
		"-o", outputFile,
		"-l", inputFile,
	)

	// Step 4: Execute httpx.
	//
	// An input path equal to an output path is never correct, for any tool. This
	// assertion is the last thing between the argv and the process, and it fails
	// LOUDLY rather than skipping: a silent skip here is indistinguishable from a
	// dead target, which is exactly what a 0-byte hosts.jsonl looked like for four
	// days. Reachable today via `--hosts artefacts/hosts.jsonl`, which priority 1
	// returns verbatim; the derivation in resolveHostInput closes the other routes
	// but cannot close an operator-supplied path.
	if sameFilePath(inputFile, outputFile) {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: refusing to dispatch: the input list and the output file are the same path (%s); httpx truncates its -o file, so this would destroy the list while reading it", inputFile)
	}

	// T-05-02: stdout routed to run.log only (GAP-3 pattern via app.Tools).
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: tool execution failed: %w", err)
	}

	// Step 5: Parse JSONL output.
	// httpx writes results to -o file; fall back to res.Stdout.
	var jsonlSrc []byte
	if data, rerr := os.ReadFile(outputFile); rerr == nil && len(data) > 0 { //nolint:gosec
		jsonlSrc = data
	} else if len(res.Stdout) > 0 {
		jsonlSrc = res.Stdout
	}

	records, parseErr := parseHTTPXOutput(jsonlSrc)
	// A TOTAL parse failure is not a "parse warning". It means the tool's output
	// format and this parser's expectations have diverged, which is exactly the
	// 2026-08-21 root cause: httpxRaw.Port was an int against httpx's string
	// "port", json.Unmarshal failed on all 20 lines, records was empty, the
	// artefact was truncated and the WHOLE web layer skipped — while this line
	// logged it at Debug and the task returned OK.
	//
	// parseHTTPXOutput only returns non-nil for the total case; the partial case
	// (some lines parsed) is deliberately NOT fatal, because a few malformed lines
	// in a long run is a different fact and treating it as fatal would make the
	// rule useless.
	if parseErr != nil {
		if app.Log != nil {
			app.Log.Warn("web.httpx: output did not parse",
				"event", "httpx_total_parse_failure",
				"err", parseErr.Error(),
				"input_hosts", inputCount,
			)
		}
		// Publish the empty artefact first: the F3 contract (an empty run must
		// publish an EMPTY artefact, not leave a stale one) holds regardless of
		// why the run was empty.
		if pubErr := output.PublishArtefact(app.Target.WorkDir, "hosts", nil); pubErr != nil && app.Log != nil {
			app.Log.Debug("web.httpx: empty hosts publish failed", "err", pubErr)
		}
		return task.Result{
			Status:  task.StatusSkipped,
			Outputs: []string{artefactFile},
			Reason:  parseErr.Error(),
		}, nil
	}

	// Step 6: Scope-filter and append to artefacts/hosts.jsonl via app.Tree.
	var inScope [][]byte
	for _, rec := range records {
		hostVal := rec.Host
		if hostVal == "" {
			hostVal = rec.URL
		}
		if app.Tree != nil && !app.Tree.InScope(hostVal) {
			continue
		}
		line, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		inScope = append(inScope, line)
	}

	// F3 (phase 15): publish artefacts/hosts.jsonl UNCONDITIONALLY.
	//
	// "hosts" has TWO direct writers — this one and subdomains/geo.go — and the
	// empty publish is assigned to httpx ALONE. The ordering evidence, verified
	// on the tree:
	//
	//  1. subdomains.geo sits in the "subs-enrichment" stage group, the LAST
	//     subdomains group, and web.httpx sits in "web-probe", the FIRST web
	//     group; webStageGroups() is appended after the subs groups
	//     (internal/mcp/handlers/composite.go). geo therefore runs strictly
	//     BEFORE httpx whenever both run.
	//  2. Tree.Append REPLACES rather than appends, so geo's records do not
	//     survive an httpx run that probes. (Until CR-02 was fixed httpx also
	//     pointed its -o at the artefact, which destroyed geo's records even when
	//     httpx produced nothing at all; -o now goes to inputs/ — see step 2.)
	//     Adding the empty publish here removes no data that currently survives.
	//  3. Both MergeStage(…, "hosts") calls run AFTER httpx (web-portscan and
	//     web-producers) and are union-preserving via merge.go's hosts seed
	//     branch, so portscan / nerva / wellknown staging still lands on top of
	//     a now-possibly-empty base.
	//
	// Reaching here means httpx RAN: the three StatusErrored returns above
	// (input resolution, unreadable hosts file, mkdir) all precede this and
	// leave the previous artefact untouched.
	//
	// KNOWN LIMITATION, deliberately not "fixed" here: in a subs-only or passive
	// run httpx never runs, so a previous run's hosts.jsonl survives even when
	// geo ran and found nothing. Giving geo the empty publish instead would
	// erase web hosts that NO producer in that run examined, which is worse.
	if len(inScope) > 0 {
		// Tree.Append stays the scope-enforcement boundary for non-empty batches.
		if appendErr := app.Tree.Append("hosts", inScope); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.httpx: Tree.Append failed",
					"records", len(inScope), "err", appendErr)
			}
			// Non-fatal per best_effort (D-W12).
		}
	} else if pubErr := output.PublishArtefact(app.Target.WorkDir, "hosts", nil); pubErr != nil {
		// Append short-circuits on an empty batch and cannot express "this probe
		// found nothing", so the empty case goes through PublishArtefact. This
		// also truncates httpx's own raw -o output, which is desirable: that
		// write is unfiltered and must not survive as the artefact.
		if app.Log != nil {
			app.Log.Debug("web.httpx: empty hosts publish failed", "err", pubErr)
		}
	}

	if app.Log != nil && inputHash != "" {
		app.Log.Debug("web.httpx: completed",
			"input", inputFile,
			"input_hash", inputHash,
			"records", len(inScope))
	}

	if len(inScope) == 0 {
		// Rule B2. Nothing from a NON-EMPTY input is a question that needs an
		// answer; nothing from an empty input is simply nothing to do, and
		// collapsing the two would make a first-run `web`-only invocation look
		// broken.
		if inputCount > 0 {
			reason := fmt.Sprintf("probed %d host(s), no live host survived probing or scope filtering", inputCount)
			if app.Log != nil {
				app.Log.Warn("web.httpx: produced no hosts from a non-empty input",
					"event", "httpx_no_hosts_from_input",
					"input_hosts", inputCount,
				)
			}
			return task.Result{
				Status:  task.StatusSkipped,
				Outputs: []string{artefactFile},
				Reason:  reason,
			}, nil
		}
		return task.Result{
			Status:  task.StatusSkipped,
			Outputs: []string{artefactFile},
			Reason:  "no hosts to probe",
		}, nil
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{artefactFile},
		Stats:   map[string]int{"hosts_found": len(inScope)},
	}, nil
}

// countNonEmptyLines counts non-blank lines in path. Returns 0 when unreadable —
// the caller uses it only to distinguish "nothing from something" from "nothing
// from nothing", and an unreadable input is already reported upstream.
func countNonEmptyLines(path string) int {
	data, err := os.ReadFile(path) //nolint:gosec // path resolved from the run's own workspace
	if err != nil {
		return 0
	}
	n := 0
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

// uncommonPortsEnabled reports whether the uncommon-port sweep is on.
func uncommonPortsEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.Web.Probe.UncommonEnabled && uncommonWebPorts != ""
}

// probePorts builds the httpx -p value: the configured ports, plus the uncommon
// list when enabled. Duplicates are dropped so an operator who already listed
// 8443 in web.probe.ports does not get it twice.
//
// An empty result means "omit -p" and let httpx use its own default, which is
// the pre-existing contract for an unset web.probe.ports.
func probePorts(cfg *config.Config) string {
	base := strings.TrimSpace(cfg.Web.Probe.Ports)
	if !uncommonPortsEnabled(cfg) {
		return base
	}

	seen := make(map[string]struct{}, 128)
	out := make([]string, 0, 128)
	for _, group := range []string{base, uncommonWebPorts} {
		for _, p := range strings.Split(group, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return strings.Join(out, ",")
}

// resolveHostInput implements the D-W10 input precedence.
func resolveHostInput(ctx context.Context, app *appctx.AppContext) (string, error) {
	// Priority 1: ctx-carried --hosts flag (set by runWebCmd).
	//
	// An operator who points --hosts at a JSONL artefact (their own
	// artefacts/hosts.jsonl is the obvious candidate — it is the file the run
	// just produced) gets the SAME silent nothing CR-02 describes, because httpx
	// cannot use a JSON object as a target. Detect that shape and extract, rather
	// than probing nothing and calling the target dead.
	if hostsFile := hostsFileFromCtx(ctx); hostsFile != "" {
		if _, err := os.Stat(hostsFile); err == nil {
			if looksLikeJSONLines(hostsFile) {
				if derived, derr := extractHostsFromHostsJSONL(hostsFile, app); derr == nil && derived != "" {
					return derived, nil
				}
			}
			return hostsFile, nil
		}
	}

	// Priority 2: prior artefacts/hosts.jsonl — EXTRACTED, never passed through.
	//
	// CR-02. This branch used to return the artefact path itself. artefacts/hosts.jsonl
	// holds JSON objects, and httpx cannot use one as a target. Same binary, same
	// live host, httpx v1.9.0 on 127.0.0.1 (no third-party host contacted):
	//
	//	$ printf '127.0.0.1:18099\n' | httpx -silent -duc -no-color
	//	http://127.0.0.1:18099
	//	$ printf '{"host":"127.0.0.1:18099","url":"http://127.0.0.1:18099"}\n' | httpx -silent -duc -no-color
	//	(no output)
	//
	// So every run that took this branch probed nothing and then reported
	// "probed N host(s), no live host survived probing" — which reads exactly like
	// a dead target. Priority 3 already derives a text list; this now does the same.
	hostsJSONL := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	if info, err := os.Stat(hostsJSONL); err == nil && info.Size() > 0 {
		hostsFromArtefact, err := extractHostsFromHostsJSONL(hostsJSONL, app)
		if err == nil && hostsFromArtefact != "" {
			return hostsFromArtefact, nil
		}
	}

	// Priority 3: derive hosts from artefacts/subdomains.jsonl.
	subdomainsJSONL := filepath.Join(app.Target.WorkDir, "artefacts", "subdomains.jsonl")
	if _, err := os.Stat(subdomainsJSONL); err == nil {
		hostsFromSubs, err := extractHostsFromSubdomainsJSONL(subdomainsJSONL, app)
		if err == nil && hostsFromSubs != "" {
			return hostsFromSubs, nil
		}
	}

	return "", fmt.Errorf("web.httpx: no host list: run `subs` first or pass --hosts <file>")
}

// extractHostsFromSubdomainsJSONL reads artefacts/subdomains.jsonl and
// writes a plain-text hostname file to inputs/httpx.hosts.txt, returning
// its path. Returns error if subdomains.jsonl is empty or unreadable.
func extractHostsFromSubdomainsJSONL(subdomainsPath string, app *appctx.AppContext) (string, error) {
	f, err := os.Open(subdomainsPath) //nolint:gosec // path from trusted WorkDir
	if err != nil {
		return "", fmt.Errorf("open subdomains.jsonl: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var hostnames []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Subdomain string `json:"subdomain"`
			Host      string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := rec.Subdomain
		if h == "" {
			h = rec.Host
		}
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}
	if len(hostnames) == 0 {
		return "", fmt.Errorf("subdomains.jsonl: no hostnames found")
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir inputs/: %w", err)
	}
	hostsPath := filepath.Join(inputsDir, "httpx.hosts.txt")
	content := strings.Join(hostnames, "\n") + "\n"
	if err := os.WriteFile(hostsPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("write httpx.hosts.txt: %w", err)
	}
	return hostsPath, nil
}

// extractHostsFromHostsJSONL reads a prior artefacts/hosts.jsonl and writes the
// bare hostnames to inputs/httpx.hosts.txt, returning its path.
//
// The `host` field is preferred; `url` is the fallback and is reduced to its
// host[:port] because httpx accepts either but the artefact's url carries a
// scheme and path that a bare-host list must not.
func extractHostsFromHostsJSONL(hostsPath string, app *appctx.AppContext) (string, error) {
	f, err := os.Open(hostsPath) //nolint:gosec // path from trusted WorkDir
	if err != nil {
		return "", fmt.Errorf("open hosts.jsonl: %w", err)
	}
	defer f.Close() //nolint:errcheck

	seen := make(map[string]struct{})
	var hostnames []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Host string `json:"host"`
			URL  string `json:"url"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := strings.TrimSpace(rec.Host)
		if h == "" {
			h = hostFromURL(rec.URL)
		}
		if h == "" {
			continue
		}
		if _, dup := seen[h]; dup {
			continue
		}
		seen[h] = struct{}{}
		hostnames = append(hostnames, h)
	}
	if len(hostnames) == 0 {
		return "", fmt.Errorf("hosts.jsonl: no hostnames found")
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir inputs/: %w", err)
	}
	outPath := filepath.Join(inputsDir, "httpx.hosts.txt")
	content := strings.Join(hostnames, "\n") + "\n"
	if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("write httpx.hosts.txt: %w", err)
	}
	return outPath, nil
}

// looksLikeJSONLines reports whether the first non-blank line of path is a JSON
// object. It reads at most the first 1 MiB: the question is about the file's
// SHAPE, and a host list whose first line is a JSON object is a JSONL artefact
// however long the rest of it is.
func looksLikeJSONLines(path string) bool {
	f, err := os.Open(path) //nolint:gosec // operator-supplied path, operator-trust model (WR-08)
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		return len(line) > 0 && line[0] == '{' && json.Valid(line)
	}
	return false
}

// hostFromURL reduces a URL to host[:port]. It is deliberately string-based:
// url.Parse on a bare "api.example.com" returns an empty Host, and this is only
// ever fed the artefact's own url field.
func hostFromURL(raw string) string {
	u := strings.TrimSpace(raw)
	if u == "" {
		return ""
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	return strings.TrimSpace(u)
}

// sameFilePath reports whether a and b name the same file.
//
// It compares the cleaned absolute paths AND, when both exist, the underlying
// inode via os.SameFile — a symlink or a "./artefacts/hosts.jsonl" spelling of
// the same file must not slip past a string comparison.
func sameFilePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, cb := filepath.Clean(a), filepath.Clean(b)
	if abs, err := filepath.Abs(ca); err == nil {
		ca = abs
	}
	if abs, err := filepath.Abs(cb); err == nil {
		cb = abs
	}
	if ca == cb {
		return true
	}
	ia, erra := os.Stat(a)
	ib, errb := os.Stat(b)
	if erra != nil || errb != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// checkHostsFileReadable checks that path is accessible and is a regular file.
// The --hosts flag is operator-supplied on the operator's local machine;
// arbitrary absolute paths are allowed by design — the operator controls the
// machine running reconftw. The ".." substring check was removed (WR-08): it
// was over-inclusive (blocked legitimate filenames containing "..") and under-
// inclusive (did not prevent absolute path reads, which are the actual exposure).
func checkHostsFileReadable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("web.httpx: --hosts file not accessible %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("web.httpx: --hosts path is not a regular file: %q", path)
	}
	return nil
}

// fileHash computes a hex-encoded MD5 hash of the file at path.
// Used only for checkpoint input-hash tracking (not cryptographic security).
func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller already validated
	if err != nil {
		return "", err
	}
	h := md5.Sum(data) //nolint:gosec // MD5 for tracking only, not security
	return hex.EncodeToString(h[:]), nil
}

// parseHTTPXOutput parses httpx JSONL output into HostRecord slice.
// Lines that fail to parse are silently skipped (passive parsing).
// Returns records and a non-nil error only when ALL lines failed to parse.
func parseHTTPXOutput(jsonlData []byte) ([]HostRecord, error) {
	if len(jsonlData) == 0 {
		return nil, nil
	}

	var records []HostRecord
	var parseErrors int
	scanner := bufio.NewScanner(bytes.NewReader(jsonlData))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var raw httpxRaw
		if err := json.Unmarshal(line, &raw); err != nil {
			parseErrors++
			continue
		}

		// Map httpx raw fields to D-W11 HostRecord schema.
		host := raw.Host
		if host == "" {
			host = raw.Input
		}

		// First resolved IP from httpx "a" field (DNS A records).
		ip := ""
		if len(raw.A) > 0 {
			ip = raw.A[0]
		}

		// Port is already a string in httpx output and HostRecord.Port is a
		// string too (D-W11), so it passes through verbatim.
		portStr := strings.TrimSpace(raw.Port)

		rec := HostRecord{
			Host:          host,
			URL:           raw.URL,
			Scheme:        raw.Scheme,
			Port:          portStr,
			Status:        raw.StatusCode,
			Title:         raw.Title,
			Tech:          raw.Technologies,
			ContentLength: raw.ContentLength,
			IP:            ip,
			CDN:           "", // populated by cdncheck Task (Phase 5 plan-03)
		}
		if rec.Tech == nil {
			rec.Tech = []string{}
		}
		records = append(records, rec)
	}

	if parseErrors > 0 && len(records) == 0 {
		return nil, fmt.Errorf("web.httpx: all %d lines failed to parse", parseErrors)
	}
	return records, nil
}

// init self-registers HTTPXTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&HTTPXTask{}) }
