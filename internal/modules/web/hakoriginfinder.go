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
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
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
	const toolName = "hakoriginfinder"

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

	hakoBin, lookErr := exec.LookPath(toolName)
	if lookErr != nil {
		if app.Log != nil {
			app.Log.Info("web.hakoriginfinder: binary not on PATH — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// CR-07: per-invocation timeout from tools.lock hakoriginfinder.timeout_seconds=120.
	const toolTimeout = 120 * time.Second

	var origins []OriginRecord
	for _, pair := range pairs {
		if pair.ip == "" || pair.host == "" {
			continue
		}
		originIP, runErr := runHakoriginfinderForHost(ctx, hakoBin, pair.host, pair.ip, toolTimeout)
		if runErr != nil && app.Log != nil {
			app.Log.Debug("web.hakoriginfinder: per-host run error",
				"host", pair.host, "err", runErr)
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
		Status: task.StatusDone,
		Stats:  map[string]int{"origins_found": len(origins)},
	}, nil
}

// runHakoriginfinderForHost runs hakoriginfinder for a single host/IP pair.
// Returns the first origin IP found in the output, or "" if none.
// Each call has an unambiguous host↔IP relationship (CR-06 fix).
func runHakoriginfinderForHost(ctx context.Context, hakoBin, targetHost, inputIP string,
	timeout time.Duration,
) (string, error) {
	// Derive per-invocation bounded context (CR-07).
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// ARG VECTOR: hakoriginfinder -h https://<hostname>  (stdin: the host's IP)
	targetURL := "https://" + targetHost
	//nolint:gosec // hakoBin from LookPath; targetURL from validated hostname
	cmd := exec.CommandContext(cmdCtx, hakoBin, "-h", targetURL)
	cmd.Stdin = strings.NewReader(inputIP + "\n")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf

	if err := cmd.Run(); err != nil {
		// Non-zero exit is normal when no origin is found.
		if outBuf.Len() == 0 {
			return "", nil
		}
	}

	return parseHakoriginOutput(outBuf.String(), targetHost), nil
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
