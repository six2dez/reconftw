// ffuf.go — FfufTask: web directory/file fuzzer → artefacts/fuzz.jsonl.
//
// FfufTask runs ffuf per-host against probed hosts, writing structured
// results to artefacts/fuzz.jsonl (D-W11 schema: {url, status, length,
// words, lines, redirect}).
//
// DEPENDENCY: DependsOn ["web.httpx"] — reads artefacts/hosts.jsonl as input.
//
// ARG VECTOR (RESEARCH §ffuf — verbatim v1 form, web.sh:1497-1499):
//
//	ffuf -mc all -fc 404 -sf -noninteractive -of json
//	     -t <threads> -rate <rate> -H "<header>"
//	     -w <wordlist> -maxtime <maxtime>
//	     -u <hostURL>/FUZZ -o <stagingFile>
//
// DEEP mode (web.sh:1503) adds: -recursion -recursion-depth <depth>
//
// THREAD CAP (T-05-06 / WEB-03): threads = min(cfg.Web.Fuzz.Threads,
// cfg.Advanced.Tools.FFUF.Threads) when both are set and positive; otherwise
// uses the non-zero value; final default = AVAILABLE_CORES * 10 (v1 default).
//
// XCUT-09 (Pitfall 5): ffuf runs up to FFUF_MAXTIME (default 900s) per host;
// Backend.Stream is mandatory to deliver heartbeat events for long runs.
//
// T-05-05 mitigation: each host URL from hosts.jsonl is validated for
// http/https scheme before being interpolated into the -u flag.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-02-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ffufJSON is the top-level structure of ffuf's -of json output.
// Source: RESEARCH §Code Examples: ffufJSON struct (web.sh:1520-1521).
type ffufJSON struct {
	Results []ffufResult `json:"results"`
}

// ffufResult maps one entry from ffuf's results array.
type ffufResult struct {
	Status           int    `json:"status"`
	Length           int    `json:"length"`
	Words            int    `json:"words"`
	Lines            int    `json:"lines"`
	URL              string `json:"url"`
	Redirectlocation string `json:"redirectlocation"`
}

// FuzzRecord is the D-W11 artefacts/fuzz.jsonl schema.
// Fields: {url, status, length, words, lines, redirect}.
type FuzzRecord struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int    `json:"length"`
	Words    int    `json:"words"`
	Lines    int    `json:"lines"`
	Redirect string `json:"redirect,omitempty"`
}

// FfufTask runs ffuf against probed hosts and writes fuzz.jsonl.
type FfufTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *FfufTask) Name() string { return "web.ffuf" }

// Module returns the owning module group.
func (t *FfufTask) Module() string { return "web" }

// Description returns a human-readable one-line description.
func (t *FfufTask) Description() string { return "Web directory/file fuzzer (ffuf → fuzz.jsonl)" }

// Enabled reports whether this task should run.
func (t *FfufTask) Enabled(cfg *config.Config) bool { return cfg.Web.Fuzz.Enabled }

// DependsOn returns the DAG edges: depends on web.httpx for hosts.jsonl input.
func (t *FfufTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes ffuf per host and writes D-W11 records to artefacts/fuzz.jsonl.
func (t *FfufTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "ffuf"
	cfg := app.Cfg

	// Resolve wordlist path (Paths.FuzzWordlist is the canonical source).
	wordlist := cfg.Paths.FuzzWordlist
	if wordlist == "" {
		if app.Log != nil {
			app.Log.Info("web.ffuf: no fuzz wordlist configured — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if _, err := os.Stat(wordlist); err != nil {
		if app.Log != nil {
			app.Log.Info("web.ffuf: fuzz wordlist not accessible — skipping",
				"path", wordlist, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read probed hosts from artefacts/hosts.jsonl.
	allHosts, err := readHostURLsFromJSONL(app)
	if err != nil || len(allHosts) == 0 {
		if app.Log != nil {
			app.Log.Info("web.ffuf: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Prepare directories.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.ffuf: mkdir inputs/: %w", err)
	}
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.ffuf: mkdir artefacts/: %w", err)
	}

	// Resolve thread count: cap at FFUF_THREADS_MAX (T-05-06 / WEB-03).
	threads := resolveFFUFThreads(cfg)

	// Rate limit (0 = unlimited, matching v1 default).
	rateLimit := cfg.Web.Fuzz.RateLimit
	if rateLimit <= 0 {
		rateLimit = cfg.Advanced.Tools.FFUF.RateLimit // may also be 0
	}

	// Max time per host (default 900s = v1 FFUF_MAXTIME).
	maxTime := cfg.Web.Fuzz.MaxTimeSeconds
	if maxTime <= 0 {
		maxTime = cfg.Advanced.Tools.FFUF.MaxTimeSeconds
	}
	if maxTime <= 0 {
		maxTime = 900 // v1 FFUF_MAXTIME default
	}

	// Deep mode and recursion depth.
	deepMode := cfg.Advanced.Deep
	recursionDepth := cfg.Web.Fuzz.RecursionDepth
	if recursionDepth <= 0 {
		recursionDepth = 2 // v1 FUZZ_RECURSION_DEPTH default
	}

	// Custom header (cfg.Advanced.Header; empty = omit flag).
	header := cfg.Advanced.Header

	// Extra flags from advanced.tools.ffuf.flags.
	var extraArgs []string
	if cfg.Advanced.Tools.FFUF.Flags != "" {
		extraArgs = strings.Fields(cfg.Advanced.Tools.FFUF.Flags)
	}

	var totalResults int

	for i, hostURL := range allHosts {
		// T-05-05: validate URL scheme before interpolating into -u flag.
		if err := validateFFUFURL(hostURL); err != nil {
			if app.Log != nil {
				app.Log.Debug("web.ffuf: skipping host with invalid URL", "url", hostURL, "err", err)
			}
			continue
		}

		stagingFile := filepath.Join(artefactsDir, fmt.Sprintf("ffuf.host%d.json.tmp", i))

		results, err := runFFUFHost(ctx, app, toolName, hostURL, wordlist,
			threads, rateLimit, maxTime, header, extraArgs,
			deepMode, recursionDepth, stagingFile)
		if err != nil {
			// F6: a TERMINAL error means ffuf RAN on this host and ended badly.
			// Fail the task rather than silently publishing the hosts fuzzed so
			// far as a complete fuzz of every host.
			if isTerminalStreamError(err) {
				os.Remove(stagingFile) //nolint:errcheck // best effort cleanup
				return task.Result{Status: task.StatusErrored}, err
			}
			if app.Log != nil {
				app.Log.Debug("web.ffuf: host run error",
					"host", hostURL, "err", err)
			}
		}
		totalResults += len(results)

		// Append to artefacts/fuzz.jsonl via app.Tree.Append.
		if len(results) > 0 {
			var lines [][]byte
			for _, rec := range results {
				b, merr := json.Marshal(rec)
				if merr != nil {
					continue
				}
				lines = append(lines, b)
			}
			if len(lines) > 0 {
				if appendErr := app.Tree.Append("fuzz", lines); appendErr != nil {
					if app.Log != nil {
						app.Log.Debug("web.ffuf: Tree.Append failed",
							"records", len(lines), "err", appendErr)
					}
					// Non-fatal per best_effort (D-W12).
				}
			}
		}

		// Clean up staging file.
		os.Remove(stagingFile) //nolint:errcheck // best effort cleanup
	}

	if app.Log != nil {
		app.Log.Debug("web.ffuf: completed",
			"hosts", len(allHosts),
			"total_results", totalResults)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"fuzz_results": totalResults},
	}, nil
}

// runFFUFHost runs ffuf for a single host URL, returns parsed FuzzRecord slice.
// Uses Backend.Stream (XCUT-09 — ffuf runs up to maxTime per host; Pitfall 5).
func runFFUFHost(ctx context.Context, app *appctx.AppContext, toolName, hostURL string,
	wordlist string, threads, rateLimit, maxTime int, header string,
	extraArgs []string, deepMode bool, recursionDepth int,
	stagingFile string,
) ([]FuzzRecord, error) {
	// Build arg vector (RESEARCH §ffuf verbatim v1 form web.sh:1497-1499).
	// -mc all -fc 404 -sf -noninteractive -of json
	args := []string{
		"-mc", "all",
		"-fc", "404",
		"-sf",
		"-noninteractive",
		"-of", "json",
	}
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}
	if rateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(rateLimit))
	}
	if header != "" {
		args = append(args, "-H", header)
	}
	args = append(args, "-w", wordlist)
	args = append(args, "-maxtime", strconv.Itoa(maxTime))

	// DEEP mode recursion (web.sh:1503).
	if deepMode {
		args = append(args, "-recursion", "-recursion-depth", strconv.Itoa(recursionDepth))
	}

	args = append(args, extraArgs...)

	// -u: hostURL/FUZZ (trimming trailing slash to avoid double //).
	fuzzURL := strings.TrimRight(hostURL, "/") + "/FUZZ"
	args = append(args, "-u", fuzzURL, "-o", stagingFile)

	// Use Backend.Stream for XCUT-09 heartbeat (ffuf runs up to maxTime seconds;
	// Pitfall 5 mitigation).
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		// DISPATCH failure — ffuf is not on PATH; nothing ran for this host.
		return nil, fmt.Errorf("ffuf stream for %s: %w", hostURL, err)
	}

	// F6 (phase 15): consume the TERMINAL error before reading stagingFile. A
	// ffuf that hits -maxtime and is killed, or dies on a malformed wordlist,
	// leaves a truncated -o JSON document; parsing it would report a partial
	// fuzz as this host's complete result set.
	if drainErr := backend.Drain(eventCh); drainErr != nil {
		return nil, terminalStreamError(toolName, drainErr)
	}

	// Parse staging JSON file.
	data, err := os.ReadFile(stagingFile) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no results produced
		}
		return nil, fmt.Errorf("read ffuf staging for %s: %w", hostURL, err)
	}

	return parseFFUFOutput(data), nil
}

// parseFFUFOutput parses ffuf -of json output into FuzzRecord slice.
// Lines that fail to parse are silently skipped (passive parsing).
func parseFFUFOutput(data []byte) []FuzzRecord {
	if len(data) == 0 {
		return nil
	}
	// ffuf -of json writes a single JSON object with a "results" array.
	var fj ffufJSON
	if err := json.Unmarshal(data, &fj); err != nil {
		// Fallback: try JSONL (one result per line).
		return parseFFUFJSONL(data)
	}
	var records []FuzzRecord
	for _, r := range fj.Results {
		if r.URL == "" {
			continue
		}
		records = append(records, FuzzRecord{
			URL:      r.URL,
			Status:   r.Status,
			Length:   r.Length,
			Words:    r.Words,
			Lines:    r.Lines,
			Redirect: r.Redirectlocation,
		})
	}
	return records
}

// parseFFUFJSONL parses ffuf output as JSONL (one ffufResult per line).
// Used as a fallback when the output is not a single JSON object.
func parseFFUFJSONL(data []byte) []FuzzRecord {
	var records []FuzzRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var r ffufResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		if r.URL == "" {
			continue
		}
		records = append(records, FuzzRecord{
			URL:      r.URL,
			Status:   r.Status,
			Length:   r.Length,
			Words:    r.Words,
			Lines:    r.Lines,
			Redirect: r.Redirectlocation,
		})
	}
	return records
}

// resolveFFUFThreads computes the effective thread count, capping at
// cfg.Advanced.Tools.FFUF.Threads (FFUF_THREADS_MAX) per T-05-06 / WEB-03.
// Falls back to AVAILABLE_CORES * 10 (v1 default) when no config is set.
func resolveFFUFThreads(cfg *config.Config) int {
	computed := cfg.Web.Fuzz.Threads
	if computed <= 0 {
		computed = runtime.NumCPU() * 10
	}
	cap := cfg.Advanced.Tools.FFUF.Threads
	if cap > 0 && computed > cap {
		computed = cap
	}
	return computed
}

// validateFFUFURL checks that u is an http or https URL (T-05-05 mitigation).
// Rejects empty, non-parseable, or non-http/https URLs to prevent ffuf arg injection.
func validateFFUFURL(u string) error {
	if u == "" {
		return fmt.Errorf("empty URL")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return fmt.Errorf("parse URL %q: %w", u, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("URL %q has non-http/https scheme %q", u, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL %q has empty host", u)
	}
	return nil
}

// init self-registers FfufTask with the Default task registry.
func init() { task.Register(&FfufTask{}) }
