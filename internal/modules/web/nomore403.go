// nomore403.go — Nomore403Task: 4xx bypass scanner → artefacts/findings.jsonl.
//
// Nomore403Task reads 4xx URLs (status 400-499, excluding 404) from
// artefacts/fuzz.jsonl and runs the nomore403 repo-clone binary to discover
// bypass techniques for hardened 4xx responses.
//
// DEPENDENCY: DependsOn ["web.ffuf"] — reads artefacts/fuzz.jsonl as input.
//
// REPO-CLONE BINARY (RESEARCH §nomore403, Pitfall 2):
// nomore403 is NOT a `go install` tool. It is cloned from GitHub and built
// locally, at <tools_dir>/nomore403/nomore403.
//
// 18-05: IT COMES HOME. Until this plan the binary was probed with os.Stat and
// dispatched with exec.CommandContext, because the registry resolved every tool
// with exec.LookPath (which cannot see a clone) and backend.Runner exposed
// neither stdin nor a working directory. All three gaps are closed:
//
//   - 18-02 declared clone_dir/clone_entry for nomore403 in tools.lock, so
//     ToolRegistry.Discover resolves Tool.Path from the clone.
//   - 18-02 declared clone_workdir = true for it — the ONLY row that does —
//     so Discover also populates Tool.WorkDir with the clone directory.
//   - 18-01 added Runner.RunOpts + ExecOptions.Stdin.
//
// CRITICAL (T-05-16 / Pitfall 2 mitigation), unchanged as a REQUIREMENT and
// changed only in WHO SATISFIES IT: nomore403 must run with its own directory
// as cwd because it resolves its payload wordlists relative to it (the tool
// prints "Payloads folder: payloads" — a relative path — in its own banner).
// That cwd now comes from Tool.WorkDir via the manifest. This file deliberately
// does NOT pass ExecOptions.Dir: doing so would re-introduce a module-side
// notion of where the clone lives, which is the thing 18-02 removed.
//
// DEADLINE: the local 300s context.WithTimeout is GONE. tools.lock declares
// nomore403 timeout_seconds = 300 and applyToolContract derives the bound
// inside the Runner, so the manifest is now the SINGLE owner. The two agreed;
// keeping both would have meant two bounds for one tool that drift the moment
// the manifest is edited.
//
// PARTIAL OUTPUT ON A NON-ZERO EXIT IS NO LONGER PARSED, and that loss was
// measured rather than assumed. Driven against a live loopback target on
// 2026-08-26 the real binary exits 0 — with findings and without. It exits 2
// only when it cannot reach the target at all (calibration + default request
// both fail), and on that path its stdout carries error prose, not bypasses.
// So the discarded buffer holds nothing this task ever wanted.
//
// INPUT FILTER (RESEARCH §nomore403): only 4xx responses excluding 404 are
// meaningful bypass candidates (v1 vulns.sh:762: grep 4xx not 404, awk $3).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-05-PLAN.md Task 1;
// .planning/phases/18-the-runner-seam-close-the-bypass/18-05-PLAN.md Task 1.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// nomore403ToolName is the tools.lock entry this task dispatches. The same row
// is dispatched by vulns/bypass4xx.go, and after 18-05 BOTH resolve it through
// the registry — pinned by TestBypass4xxAndNomore403ResolveTheSameBinary.
const nomore403ToolName = "nomore403"

// nomore403Args is the arg vector. IT IS EMPTY, and that is the captured
// pre-move value, not an omission: nomore403 reads its target URLs from
// standard input and the pre-18-05 call was exec.CommandContext(ctx, binaryPath)
// with no arguments at all. tools.lock declares default_args = [] for this row,
// so applyToolContract prepends nothing and the command line is byte-for-byte
// what it has always been.
func nomore403Args() []string { return nil }

// Nomore403Task runs nomore403 against 4xx URLs and writes bypass findings
// to artefacts/findings.jsonl.
type Nomore403Task struct{}

func (t *Nomore403Task) Name() string   { return "web.nomore403" }
func (t *Nomore403Task) Module() string { return "web" }
func (t *Nomore403Task) Description() string {
	return "4xx bypass scanner (nomore403 → findings.jsonl)"
}

// Enabled reports whether 4xx bypass scanning is configured.
// Maps to cfg.Vulns.Bypass4xx.Enabled (v1: bypass_4xx flag, default true).
func (t *Nomore403Task) Enabled(cfg *config.Config) bool {
	return cfg.Vulns.Bypass4xx.Enabled
}

// DependsOn returns the DAG edges: nomore403 reads fuzz.jsonl from web.ffuf.
func (t *Nomore403Task) DependsOn() []string { return []string{"web.ffuf"} }

// Run reads 4xx URLs from fuzz.jsonl, invokes nomore403, writes findings.
func (t *Nomore403Task) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// NO os.Stat BINARY PROBE, and no module-side join into the tools root. The
	// registry resolves nomore403 from its declared clone coordinates; an
	// unresolvable one leaves Tool.Path empty, cmd.Start fails, and the Runner
	// reports a typed dispatch failure that lands in logs/tools.jsonl as
	// dispatch_failed instead of vanishing. The task's STATUS on an absent binary
	// is unchanged — StatusSkipped, see the dispatch below.

	// Read fuzz.jsonl; collect 4xx URLs excluding 404.
	fuzzURLs, err := read4xxURLsFromFuzzJSONL(app)
	if err != nil && app.Log != nil {
		app.Log.Debug("web.nomore403: read fuzz.jsonl error", "err", err)
	}
	if len(fuzzURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.nomore403: no 4xx bypass candidates in fuzz.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Build input payload: newline-separated URLs.
	inputData := []byte(strings.Join(fuzzURLs, "\n") + "\n")

	// Invoke nomore403 through the seam:
	//   v1 form: cd <toolsDir>/nomore403 && ./nomore403 < <input>
	//   v2 form: app.Tools.RunOpts(ctx, "nomore403", nil, ExecOptions{Stdin: ...})
	//
	// The cwd is NOT passed here. It comes from Tool.WorkDir, which Discover
	// populates from clone_workdir in tools.lock — see this file's header.
	res, runErr := app.Tools.RunOpts(ctx, nomore403ToolName, nomore403Args(),
		backend.ExecOptions{Stdin: inputData})
	if runErr != nil {
		// A tool that is not registered, or registered but unresolvable (Discover
		// leaves Path empty, so cmd.Start fails and LocalBackend reports
		// NeverStarted), is the SAME graceful skip the os.Stat gate used to give
		// — including not staging, so a run in which nomore403 never ran cannot
		// clear a previous run's bypasses (F3 did-not-run).
		if coreerrors.IsDispatchFailure(runErr) {
			if app.Log != nil {
				app.Log.Info("web.nomore403: nomore403 unavailable — run reconftw install")
			}
			return task.Result{Status: task.StatusSkipped}, nil
		}
		// A non-zero exit means the target could not be reached at all (see the
		// header's measurement). No partial output is parsed on this path.
		if app.Log != nil {
			app.Log.Debug("web.nomore403: nomore403 exited non-zero (no partial output on this path)",
				"err", runErr)
		}
	}

	var outBytes []byte
	if res != nil {
		outBytes = res.Stdout
	}
	findings := parseNomore403Output(outBytes)

	// Stage findings for the findings merge (best_effort D-W12).
	//
	// F3 (phase 15): staged UNCONDITIONALLY — StageJSONL removes the staging
	// file when this run found no bypasses, so a previous run's bypasses cannot
	// be republished.
	var lines [][]byte
	for _, rec := range findings {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	// F3 DID-NOT-RUN, deadline arm (18-06 code review, CR-03). Reaching here with
	// res == nil means the tool did NOT complete — a tools.lock deadline, a crash,
	// or a cancelled context. Before the move each of these files applied its own
	// context.WithTimeout and PARSED the partially-filled buffer, so a timeout
	// still staged what it had seen. The move removed both, so res is nil and
	// findings is empty — and StageJSONL implements an empty input as os.Remove.
	// A run that never observed the corpus has no standing to delete what a
	// previous run did observe, which is exactly what the F3 comment below claims
	// and, on this path, did not deliver.
	if res == nil {
		if app.Log != nil {
			app.Log.Warn("web.nomore403: incomplete run — previous staging preserved",
				"err", runErr)
		}
	} else {
		stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.nomore403.jsonl")
		if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
			app.Log.Debug("web.nomore403: staging write failed",
				"path", stagingPath, "err", wErr)
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.nomore403: completed",
			"input_urls", len(fuzzURLs),
			"bypasses", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"bypasses": len(findings)},
		// V-04: the tool did not finish (deadline, crash, cancellation), so this run
		// must NOT be checkpointed as done — otherwise the next run with the same
		// input hash skips it and the deadline becomes a permanent, silent hole.
		// Status stays non-error on purpose: this is best-effort and must not fail
		// the scan. See task.Result.Incomplete.
		Incomplete: res == nil,
	}, nil
}

// parseNomore403Output parses nomore403 stdout.
// Each non-empty line is a bypass URL/result.
func parseNomore403Output(data []byte) []FindingRecord {
	if len(data) == 0 {
		return nil
	}
	var records []FindingRecord
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		records = append(records, FindingRecord{
			Type:       "http",
			Host:       extractHostFromURL(line),
			TemplateID: "nomore403-bypass",
			Severity:   "medium",
			MatchedAt:  line,
			Confidence: "medium",
			Refs:       []string{},
		})
	}
	return records
}

// read4xxURLsFromFuzzJSONL reads artefacts/fuzz.jsonl and returns URLs with
// status codes 400-499 excluding 404 (bypass candidates per v1 vulns.sh:762).
func read4xxURLsFromFuzzJSONL(app *appctx.AppContext) ([]string, error) {
	fuzzPath := filepath.Join(app.Target.WorkDir, "artefacts", "fuzz.jsonl")
	data, err := os.ReadFile(fuzzPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read fuzz.jsonl: %w", err)
	}
	var urls []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec FuzzRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Filter: 4xx excluding 404 (status >= 400 AND <= 499 AND != 404).
		if rec.Status >= 400 && rec.Status <= 499 && rec.Status != 404 && rec.URL != "" {
			urls = append(urls, rec.URL)
		}
	}
	return urls, nil
}

func init() { task.Register(&Nomore403Task{}) }
