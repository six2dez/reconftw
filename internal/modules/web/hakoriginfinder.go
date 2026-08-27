// hakoriginfinder.go — HakoriginfinderTask: origin IP discovery → artefacts/origins.jsonl.
//
// Name: "web.hakoriginfinder"  DependsOn: ["web.httpx"]
//
// HakoriginfinderTask runs hakoriginfinder per host, feeding each host's IP
// via stdin and parsing the tool's output for origin IP attribution.
//
// Per-host run strategy (CR-06 fix): feeding all IPs in a single batch
// and attributing by line index produces wrong host↔IP mappings.
// Instead, we run hakoriginfinder once per host using that host's specific IP,
// so every OriginRecord has unambiguous host attribution.
//
// D-W11 origins.jsonl schema: {host, origin_ip, method, confidence}
//
// ARG VECTOR (RESEARCH §hakoriginfinder):
//
//	hakoriginfinder -h https://<hostname>  (stdin: one IP)
//
// T-05-10: tool stdout routed to run.log only (never INFO terminal, GAP-3).
//
// hakoriginfinder is a LocalBackend tool only (D-W13).
//
// 18-04: THIS FILE NO LONGER BYPASSES THE SEAM. Its only manifest reason was
// `stdin`, and backend.Runner.RunOpts has carried stdin since 18-01. Its sibling
// hakip2host came home in 18-01 through exactly this seam.
//
// TIMEOUT: the per-invocation 120s context.WithTimeout is GONE. tools.lock OWNS
// the bound — the hakoriginfinder row carries timeout_seconds = 120, precisely
// the value this file used to apply, and applyToolContract derives it inside the
// Runner ONCE PER INVOCATION, which is what the per-host loop needs.
//
// DEFAULT ARGS: the hakoriginfinder row carries default_args = [], so the argv
// is byte-for-byte the pre-move `-h https://<host>`.
//
// ONE RECORDER ENTRY PER HOST, and that is intended. The per-host run strategy
// (CR-06) means N invocations for N hosts, so logs/tools.jsonl now carries N
// start/end pairs instead of nothing at all. This is the FIRST time per-host
// origin attribution is visible in the invocation record; the recorder already
// rotates on size, which is the accepted cost (T-18-04-06).
//
// BEHAVIOUR CHANGE, STATED RATHER THAN HIDDEN: on a NON-ZERO EXIT with output,
// the old code fell through and parsed that partial output; LocalBackend returns
// a *ToolError with no Result, so it no longer does. Decided for THIS tool on
// evidence: hakoriginfinder exits 0 when it finds no origin (verified 2026-08-26
// against the real binary), so the non-zero arm is a genuine failure, and an
// origin IP scraped from a failed run is exactly the kind of low-confidence
// attribution that should not be published.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-03-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// OriginRecord is the D-W11 origins.jsonl schema row.
type OriginRecord struct {
	Host       string `json:"host"`
	OriginIP   string `json:"origin_ip"`
	Method     string `json:"method"`
	Confidence string `json:"confidence"`
}

// ipv4RE matches IPv4 addresses in hakoriginfinder output.
// RESEARCH §hakoriginfinder: grep -aoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'
var ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// hostIPPair holds the per-record host and IP fields from hosts.jsonl.
type hostIPPair struct {
	host string
	ip   string
}

// hakoriginfinderToolName is the tools.lock registry key. A named constant so
// the argv test names the same string the dispatch does.
const hakoriginfinderToolName = "hakoriginfinder"

// HakoriginfinderTask runs hakoriginfinder to discover origin IPs.
type HakoriginfinderTask struct{}

func (t *HakoriginfinderTask) Name() string        { return "web.hakoriginfinder" }
func (t *HakoriginfinderTask) Module() string      { return "web" }
func (t *HakoriginfinderTask) Description() string { return "Origin IP discovery (hakoriginfinder)" }
func (t *HakoriginfinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Probe.Enabled
}
func (t *HakoriginfinderTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes hakoriginfinder per host and writes origin records to origins.jsonl.
func (t *HakoriginfinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// CR-06: read host+IP pairs together so per-host attribution is unambiguous.
	pairs, err := readHostIPPairsFromJSONL(app)
	if err != nil || len(pairs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.hakoriginfinder: no host/IP pairs in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.hakoriginfinder: mkdir inputs/: %w", err)
	}

	// NO exec.LookPath GATE. An unresolvable hakoriginfinder now returns a typed
	// dispatch failure from the Runner and is RECORDED as dispatch_failed rather
	// than vanishing silently. THE TASK'S STATUS IS UNCHANGED: the first host
	// whose dispatch never started returns StatusSkipped exactly as the old gate
	// did — including NOT publishing origins, so a run in which the tool never
	// ran cannot empty a previous run's artefact (F3 did-not-run).
	var origins []OriginRecord
	unresolvable := false
	for _, pair := range pairs {
		if pair.ip == "" || pair.host == "" {
			continue
		}
		originIP, runErr := runHakoriginfinderForHost(ctx, app, pair.host, pair.ip)
		if runErr != nil {
			// WR-06: LATCH, do not return from inside the loop.
			//
			// Returning here threw away every result the earlier iterations had already
			// collected. With CR-04 fixed, a rate-limiter or context error mid-loop IS a
			// dispatch failure, so a Ctrl-C or a task deadline part-way through now
			// reaches this arm and silently discarded a partial but perfectly valid set.
			// The decision belongs after the loop, where "the tool never ran" and "the
			// tool ran for a while then the scan was cancelled" are distinguishable —
			// the pattern web/jsa.go already uses.
			if coreerrors.IsDispatchFailure(runErr) {
				unresolvable = true
				break
			}
			if app.Log != nil {
				app.Log.Debug("web.hakoriginfinder: per-host run error",
					"host", pair.host, "err", runErr)
			}
		}
		if originIP != "" {
			origins = append(origins, OriginRecord{
				Host:       pair.host,
				OriginIP:   originIP,
				Method:     "hakoriginfinder",
				Confidence: "low", // CR-06: unambiguous attribution but tool output is uncertain
			})
		}
	}

	// WR-06: only a run that collected NOTHING is a skip. If earlier hosts produced
	// origins before the dispatch failure, they are a real observation and are
	// published; publishing them is also what keeps the F3 contract below honest,
	// since reaching it means the tool genuinely ran.
	if unresolvable && len(origins) == 0 {
		if app.Log != nil {
			app.Log.Info("web.hakoriginfinder: tool unavailable — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if unresolvable && app.Log != nil {
		app.Log.Warn("web.hakoriginfinder: dispatch stopped part-way — publishing the origins "+
			"collected before it (WR-06)", "origins", len(origins))
	}

	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.hakoriginfinder: mkdir artefacts/: %w", err)
	}

	// F3 (phase 15): publish artefacts/origins.jsonl UNCONDITIONALLY.
	//
	// hakoriginfinder is the sole direct writer of "origins" and there is no
	// staging producer for that stage, so web.MergeStage is barred from touching
	// it (15-03's directArtefactWriterStages). This is therefore the ONLY place
	// the artefact can be emptied — and it must be. The old
	// `if len(origins) == 0 { return StatusDone }` short-circuit here meant a run
	// that probed every host and found no origin republished the PREVIOUS run's
	// origins, so an origin IP that has since been fixed kept being reported as
	// exposed.
	//
	// Reaching here means the tool RAN: the StatusSkipped returns above (no
	// host/IP pairs, binary not on PATH) and the StatusErrored mkdir failures
	// leave the previous artefact untouched — the "did not run → preserve" half.
	var lines [][]byte
	for _, r := range origins {
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) > 0 {
		// Tree.Append stays the scope-enforcement boundary for non-empty batches.
		if appendErr := app.Tree.Append("origins", lines); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.hakoriginfinder: Tree.Append failed", "err", appendErr)
			}
		}
	} else if pubErr := output.PublishArtefact(app.Target.WorkDir, "origins", nil); pubErr != nil {
		// Append short-circuits on an empty batch and cannot express "this run
		// found nothing", so the empty case goes through PublishArtefact.
		if app.Log != nil {
			app.Log.Debug("web.hakoriginfinder: empty origins publish failed", "err", pubErr)
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.hakoriginfinder: completed", "origins_found", len(origins))
	}
	return task.Result{
		Status:     task.StatusDone,
		Stats:      map[string]int{"origins_found": len(origins)},
		Incomplete: unresolvable,
	}, nil
}

// hakoriginfinderArgs returns the arg vector for one host, VERBATIM as it stood
// before 18-04 moved this dispatch onto the Runner:
//
//	hakoriginfinder -h https://<hostname>   (stdin: the host's IP)
//
// A function rather than an inline literal so
// TestHakoriginfinderArgvUnchangedAcrossTheMove can assert the process received
// exactly this slice and nothing prepended it.
func hakoriginfinderArgs(targetHost string) []string {
	return []string{"-h", "https://" + targetHost}
}

// runHakoriginfinderForHost runs hakoriginfinder for a single host/IP pair
// through backend.Runner, with that host's IP on standard input.
// Returns the first origin IP found in the output, or "" if none.
// Each call has an unambiguous host↔IP relationship (CR-06 fix).
//
// The returned error is the Runner's, unwrapped: the caller distinguishes a
// dispatch failure (tool absent — a task-level skip) from a per-host run error
// (best-effort, logged and stepped over).
func runHakoriginfinderForHost(ctx context.Context, app *appctx.AppContext,
	targetHost, inputIP string,
) (string, error) {
	if app == nil || app.Tools == nil {
		return "", nil
	}
	res, err := app.Tools.RunOpts(ctx, hakoriginfinderToolName,
		hakoriginfinderArgs(targetHost),
		backend.ExecOptions{Stdin: []byte(inputIP + "\n")})
	if err != nil {
		return "", err
	}
	return parseHakoriginOutput(string(res.Stdout), targetHost), nil
}

// parseHakoriginOutput extracts the first VALID IPv4 address from
// hakoriginfinder output for the given host. The host parameter is used only
// for context in the attribution — it is NOT used for index-based selection.
// Returns "" if no valid IPv4 is found in the output.
//
// IN-02: the ipv4RE regex matches octets up to 999 (e.g. "999.999.999.999").
// Validate each regex match with net.ParseIP and require a 4-octet (non-IPv6)
// result so an out-of-range string can never land in OriginRecord.OriginIP.
func parseHakoriginOutput(output, _ string) string {
	if output == "" {
		return ""
	}
	for _, candidate := range ipv4RE.FindAllString(output, -1) {
		ip := net.ParseIP(candidate)
		if ip != nil && ip.To4() != nil {
			return candidate
		}
	}
	return ""
}

// readHostIPPairsFromJSONL reads artefacts/hosts.jsonl and returns host+IP pairs.
// WR-06: uses bufio.Scanner with 4MiB buffer (not os.ReadFile+strings.Split).
// Pairs with empty host or empty IP are not filtered here; callers skip them.
func readHostIPPairsFromJSONL(app *appctx.AppContext) ([]hostIPPair, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	f, err := os.Open(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl for host/IP pairs: %w", err)
	}
	defer f.Close() //nolint:errcheck

	seen := make(map[string]bool)
	var pairs []hostIPPair

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Host string `json:"host"`
			IP   string `json:"ip"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		host := strings.TrimSpace(rec.Host)
		ip := strings.TrimSpace(rec.IP)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		pairs = append(pairs, hostIPPair{host: host, ip: ip})
	}
	return pairs, scanner.Err()
}

// IN-01: readIPsFromJSONL was removed — after the CR-06 per-host rewrite, Run
// uses only readHostIPPairsFromJSONL. It had no production or test callers, so
// it was dead code. readHostnamesFromJSONL below is KEPT: it is still called by
// vhostfinder.go (VhostFinderTask reads bare hostnames from hosts.jsonl).

// readHostnamesFromJSONL reads artefacts/hosts.jsonl and returns the list of
// host field values (bare hostnames, not URLs). Used by vhostfinder.go.
// WR-06: uses bufio.Scanner with 4MiB buffer (not os.ReadFile+strings.Split).
func readHostnamesFromJSONL(app *appctx.AppContext) ([]string, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	f, err := os.Open(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl: %w", err)
	}
	defer f.Close() //nolint:errcheck

	seen := make(map[string]bool)
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
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := strings.TrimSpace(rec.Host)
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		hostnames = append(hostnames, h)
	}
	return hostnames, scanner.Err()
}

func init() { task.Register(&HakoriginfinderTask{}) }
