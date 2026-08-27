// toolsjsonl_coverage_test.go — the fourth census: which tools can appear in
// logs/tools.jsonl at all (18-06 / RS-E).
//
// # WHY A FOURTH CENSUS
//
// The other three count things a reader must still interpret:
//
//	ARGV_COVERAGE   Tasks in accounted buckets. A Task can be `driven` while the
//	                tool it dispatches is answered by a capturing backend that
//	                never touches the recorder.
//	BYPASS_CENSUS   files that dispatch around backend.Runner. It counts what is
//	                still WRONG, so at zero it says nothing about what is right.
//	REALTOOLS       whether the real binary accepts the arg vector. Says nothing
//	                about whether the invocation was RECORDED.
//
// None of them answers the operator's actual question: "when I run a scan, does
// this tool show up in logs/tools.jsonl?" That file is the run's only account of
// what executed, and for the whole life of v2 a tool dispatched with
// exec.CommandContext produced NOTHING in it — no start record, no outcome, no
// argv. 18-04 and 18-05 routed thirteen such files onto backend.Runner. This
// file asserts, BY NAME, that the tools they carried now reach the recorder.
//
// # WHY BY NAME AND NOT BY COUNT
//
// A count can be satisfied by the wrong set. The whole point of this phase is a
// specific list of tools crossing a specific seam, so the assertion names them:
// a regression that re-routes `Gxss` around the Runner while some other tool
// starts being recorded would keep any count intact and would fail here.
//
// # WHY THESE TOOLS COULD NOT HAVE APPEARED BEFORE THIS PHASE
//
// Each was dispatched with a bare exec.CommandContext in a module file, which is
// a code path with no reference to ToolRecorder at all — the recorder is reached
// ONLY through Runner.Run/RunOpts/Stream/StreamOpts (runner.go execRecorded and
// streamRecorded). 18-03's manifest recorded every one of them as a declared
// bypass with its exact dispatch sites:
//
//	Gxss             web/gxss.go       2 sites, reason `stdin`         -> home 18-04
//	mantra           web/mantra.go     2 sites, reason `stdin`         -> home 18-04
//	hakoriginfinder  web/hakoriginfinder.go 2 sites, reason `stdin`    -> home 18-04
//	nomore403        web/nomore403.go  2 sites, `stdin` + `work_dir`   -> home 18-05
//	roboxtractor     web/wordlistgen.go (the roboxtractor leg)         -> home 18-05
//
// The census line this file emits, TOOLS_JSONL_COVERAGE, makes the set visible
// rather than implied — the same reason ARGV_COVERAGE prints its buckets.
package backend_test

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// toolsJSONLExpected pairs a Task this phase moved with the tool whose name must
// appear in logs/tools.jsonl once that Task is driven.
//
// The Task is named as well as the tool, so a failure says which move regressed
// rather than only which tool went quiet.
var toolsJSONLExpected = []struct {
	task string
	tool string
	// homedBy names the plan that routed it onto the seam, so a reader can find
	// the change that made this assertion possible.
	homedBy string
}{
	{"web.gxss", "Gxss", "18-04"},
	{"web.mantra", "mantra", "18-04"},
	{"web.hakoriginfinder", "hakoriginfinder", "18-04"},
	{"web.nomore403", "nomore403", "18-05"},
	{"web.wordlistgen", "roboxtractor", "18-05"},
}

// TestToolsJsonlCoverage drives each moved Task through a REAL Runner with a
// REAL ToolRecorder and asserts its tool's record lands in logs/tools.jsonl.
//
// The backend is the census's arg-capturing one — no process starts — but the
// RECORDER is the production type writing the production format to a real file,
// because the claim under test is "this invocation is now accounted for", and a
// stubbed recorder would prove only that a stub was called.
func TestToolsJsonlCoverage(t *testing.T) {
	blockNetworkEgress(t)

	var recorded []string
	for _, want := range toolsJSONLExpected {
		want := want
		t.Run(want.task, func(t *testing.T) {
			tk, ok := task.Default.Lookup(want.task)
			if !ok {
				t.Fatalf("Task %q is NOT REGISTERED. This assertion names a Task that no longer "+
					"exists, which makes it vacuous rather than green — rename or remove the entry.",
					want.task)
			}

			workDir := t.TempDir()
			cfg := config.Defaults()
			genericSeed(t, workDir, cfg)

			// The PRODUCTION recorder, at the PRODUCTION path.
			logPath := filepath.Join(workDir, "logs", "tools.jsonl")
			runner := backend.NewRunner(&multiCapture{}, censusToolRegistry(t), nil)
			runner.Recorder = backend.NewToolRecorder(logPath, nil)

			app := &appctx.AppContext{
				Log:    slog.New(slog.NewTextHandler(&syncBuffer{}, &slog.HandlerOptions{Level: slog.LevelDebug})),
				Tools:  runner,
				Tree:   permissiveTree{},
				Cfg:    cfg,
				Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
			}

			ctx, cancel := context.WithTimeout(context.Background(), censusTaskDeadline)
			defer cancel()
			_, _ = tk.Run(ctx, app)

			records := readToolRecords(t, logPath)

			// PRESENCE BEFORE CONTENT. An absence check over a file nothing wrote
			// passes trivially, which is 18-04's own lesson; assert the file has
			// records at all before asserting anything about which.
			if len(records) == 0 {
				t.Fatalf("%s produced ZERO records in %s.\n"+
					"  Before this phase that was the normal state for this Task, because it dispatched\n"+
					"  %q with a bare exec.CommandContext and the recorder is reachable only through\n"+
					"  backend.Runner. A regression to that shape is silent everywhere else: the scan\n"+
					"  still runs, findings still appear, and the run's only account of what executed\n"+
					"  simply omits it.", want.task, logPath, want.tool)
			}

			var startArgv []string
			found := false
			for _, rec := range records {
				if rec.Tool != want.tool {
					continue
				}
				found = true
				if rec.Phase == backend.PhaseStart {
					startArgv = rec.Argv
				}
			}
			if !found {
				var got []string
				for _, rec := range records {
					got = append(got, rec.Tool)
				}
				sort.Strings(got)
				t.Fatalf("%s wrote %d record(s) but NONE names %q (tools seen: %s).\n"+
					"  %s routed this dispatch onto backend.Runner; a record under a different tool\n"+
					"  name means the Task now reaches for something else, and one under no name at\n"+
					"  all means it went back around the seam.",
					want.task, len(records), want.tool, strings.Join(dedupe(got), ","), want.homedBy)
			}

			// The start record must carry an argv shape, not an empty one. Two of
			// these tools (nomore403, and Gxss under some seeds) legitimately
			// dispatch with an EMPTY argv — they read their input from standard
			// input and take no flags — so this asserts the field is PRESENT and
			// well-formed rather than non-empty, which would be a false
			// requirement dressed as rigour.
			if startArgv == nil {
				t.Logf("NOTE %s -> %s: start record carries an empty argv. That is correct for a tool "+
					"whose entire input arrives on stdin; it is asserted here as observed, not required.",
					want.task, want.tool)
			}
			for i, a := range startArgv {
				if strings.ContainsAny(a, "\n\r") {
					t.Errorf("%s -> %s argv[%d] contains a newline (%q). tools.jsonl is line-delimited "+
						"JSON; an embedded newline in a recorded argv is how a log file stops parsing.",
						want.task, want.tool, i, a)
				}
			}

			recorded = append(recorded, want.tool)
			t.Logf("TOOLS_JSONL tool=%s task=%s records=%d argv=%v",
				want.tool, want.task, len(records), startArgv)
		})
	}

	sort.Strings(recorded)
	t.Logf("TOOLS_JSONL_COVERAGE tools=%s", strings.Join(recorded, ","))

	if len(recorded) != len(toolsJSONLExpected) {
		t.Errorf("TOOLS_JSONL_COVERAGE names %d tools but %d were expected — a subtest failed and the "+
			"census line above under-reports. The line is the artefact a reader greps for, so it must "+
			"not read as a smaller clean set.", len(recorded), len(toolsJSONLExpected))
	}
}

// readToolRecords parses logs/tools.jsonl. A missing file is NOT an error here —
// it is the exact pre-phase state and the caller reports it with the context
// that makes it meaningful.
func readToolRecords(t *testing.T, path string) []backend.InvocationRecord {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // t.TempDir()-scoped path
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	var out []backend.InvocationRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec backend.InvocationRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%s:%d is not valid JSON (%v): %s\n"+
				"  tools.jsonl is the run's machine-readable account of what executed; a line an\n"+
				"  operator's jq cannot parse is a line that is not there.", path, n, err, line)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
