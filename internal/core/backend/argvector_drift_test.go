// argvector_drift_test.go — drive real Tasks against an arg-capturing backend
// and check the argv they dispatch, hermetically.
//
// NO BUILD TAG AND NO BINARIES. This is the layer that runs on a CI runner with
// an empty PATH, which is what the two shipped flag bugs both got past: the only
// test that claimed to validate arg vectors sat behind //go:build realtools and
// nothing ran it.
//
// The assertion itself lives in toolflags_test.go (assertFlagsDefined); this
// file supplies the argv by running the Task the way the scheduler would.
//
// # THE PATTERN THIS GENERALISES
//
// internal/modules/subdomains/resolver_gate_test.go's TestSubActivePurednsFlagNames
// does exactly this for one Task and one tool, and it is the guard that closed
// the `puredns -rt` blocker. It was correct and mutation-proven, but it lived in
// one module package and covered one tool. This file lifts the harness so any
// registered Task can be driven from one place.
//
// # COVERAGE IS AN ASSERTED NUMBER, NOT AN IMPRESSION
//
// Some Tasks cannot be driven hermetically — they need network state, an
// external service, or a filesystem shape too costly to fake. Those are named on
// undrivableTasks WITH A REASON, and its size is asserted, because an unasserted
// exclusion list is how coverage drains away without a diff ever showing it.
//
// # DEFAULT ARGS
//
// The argv a Task really dispatches is tools.lock's DefaultArgs prepended to the
// Task's own args, applied in applyToolContract at the Runner seam. The harness
// therefore drives a real backend.Runner rather than calling the Task's arg
// builder, so a default_args entry is included exactly as production would see
// it. TestDriftHarnessIncludesDefaultArgs pins that.
package backend_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	// Blank imports register the Tasks. Without these the registry is empty and
	// every case below would skip — which would look exactly like passing.
	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
	_ "github.com/six2dez/reconftw/internal/modules/web"
)

// driveCase is one Task driven for its argv.
type driveCase struct {
	taskName string
	tool     string
	// seed prepares the workdir and config so the Task reaches its tool call.
	seed func(t *testing.T, workDir string, cfg *config.Config)
}

// undrivableTasks names Tasks this harness deliberately does not drive, with the
// reason. Its size is asserted by TestUndrivableListIsPinned.
//
// This is the detector's COVERAGE LIMIT stated as a number. Growing it is a
// visible diff and needs a reason in the same commit.
var undrivableTasks = map[string]string{
	"subdomains.takeover.dnstake": "dnstake's argv depends on a resolved-host file the subzy case already covers for this tool class; adding it would duplicate coverage, not extend it",
	"web.nuclei":                  "runNucleiGroup fans out per host-group and per template path; a hermetic drive would pin one arbitrary group's argv and read as if it covered all of them",
	"web.portscan":                "dispatches naabu, nmap and smap from one Task through three branches selected by config and by prior-stage output; one drive covers one branch and would misreport as three",
}

const undrivableTasksSize = 3

// TestUndrivableListIsPinned keeps the exclusion list from growing unnoticed.
func TestUndrivableListIsPinned(t *testing.T) {
	if len(undrivableTasks) != undrivableTasksSize {
		t.Errorf("undrivableTasks has %d entries, constant says %d.\n"+
			"  This list IS the detector's coverage limit. If you added an entry, say why in the map\n"+
			"  and raise the constant in the same commit so the reduction in coverage is visible.",
			len(undrivableTasks), undrivableTasksSize)
	}
	for name, why := range undrivableTasks {
		if why == "" {
			t.Errorf("undrivableTasks[%q] has no reason — an unexplained exclusion is indistinguishable "+
				"from an oversight", name)
		}
	}
}

// driveCases are the Tasks driven for their argv. Scoped to the tools in
// knownToolFlags (see that file's scope criterion) — driving a Task whose tool
// has no flag table would capture argv nothing checks.
var driveCases = []driveCase{
	{
		taskName: "subdomains.takeover.subzy",
		tool:     "subzy",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"), "api.example.com\n")
			cfg.Subdomains.Takeover.Enabled = true
		},
	},
	{
		taskName: "web.httpx",
		tool:     "httpx",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "artefacts", "subdomains.jsonl"),
				"{\"subdomain\":\"api.example.com\"}\n")
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"), "api.example.com\n")
			cfg.Web.Probe.Enabled = true
		},
	},
}

// TestTaskArgVectorFlagsAreDefined is the guard.
//
// It drives each Task exactly as the scheduler would — through a real
// backend.Runner, so tools.lock DefaultArgs are applied — captures the argv, and
// asserts every dash-prefixed token is a flag the tool defines.
func TestTaskArgVectorFlagsAreDefined(t *testing.T) {
	for _, tc := range driveCases {
		tc := tc
		t.Run(tc.taskName, func(t *testing.T) {
			if why, excluded := undrivableTasks[tc.taskName]; excluded {
				t.Fatalf("%s is both driven and on the undrivable list (%q) — one of the two is wrong",
					tc.taskName, why)
			}
			argv, ok := driveTaskForArgs(t, tc)
			if !ok {
				t.Fatalf("%s dispatched no tool invocation.\n"+
					"  The seed did not get the Task as far as its tool call, so this case asserts NOTHING\n"+
					"  while appearing to pass. Fix the seed, or move the Task to undrivableTasks with a\n"+
					"  reason.", tc.taskName)
			}
			t.Logf("%s -> %s %v", tc.taskName, tc.tool, argv)
			if !assertFlagsDefined(t, tc.tool, argv) {
				t.Fatalf("no flag table for %q — add one to knownToolFlags with its provenance, or drop "+
					"this case; a driven Task whose argv nothing checks is theatre", tc.tool)
			}
		})
	}
}

// TestDriftHarnessIncludesDefaultArgs proves the harness sees what production
// sees.
//
// If the harness called a Task's arg builder directly it would miss tools.lock's
// default_args, and a bad flag added there would be invisible to every case
// above. Driving a real Runner is what makes the coverage real, so it is pinned.
func TestDriftHarnessIncludesDefaultArgs(t *testing.T) {
	capture := &argCapture{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "fixture-tool", DefaultArgs: []string{"--from-default-args"}})
	runner := backend.NewRunner(capture, reg, nil)

	if _, err := runner.Run(context.Background(), "fixture-tool", []string{"--from-caller"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{"--from-default-args", "--from-caller"}
	if len(capture.args) != len(want) {
		t.Fatalf("argv = %v, want %v — default_args did not reach the captured vector", capture.args, want)
	}
	for i := range want {
		if capture.args[i] != want[i] {
			t.Fatalf("argv = %v, want %v", capture.args, want)
		}
	}
}

// --- harness ----------------------------------------------------------------

// driveTaskForArgs runs one Task against an arg-capturing backend and returns
// the argv it dispatched.
func driveTaskForArgs(t *testing.T, tc driveCase) ([]string, bool) {
	t.Helper()

	workDir := t.TempDir()
	for _, d := range []string{"inputs", "artefacts", "raw", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cfg := &config.Config{}
	tc.seed(t, workDir, cfg)

	capture := &argCapture{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: tc.tool})

	app := &appctx.AppContext{
		Tools:  backend.NewRunner(capture, reg, nil),
		Tree:   permissiveTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	tk, ok := task.Default.Lookup(tc.taskName)
	if !ok {
		var names []string
		for _, r := range task.Default.All() {
			names = append(names, r.Name())
		}
		sort.Strings(names)
		t.Fatalf("task %q is not registered — the entry is STALE.\n"+
			"  A renamed Task would otherwise leave this case silently checking nothing.\n"+
			"  registered: %v", tc.taskName, names)
	}

	// The Task's own error is not the subject: a mocked tool returning no output
	// makes many Tasks report skipped, and that is fine. The argv is the subject.
	_, _ = tk.Run(context.Background(), app)
	return capture.args, len(capture.args) > 0
}

func seedFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// argCapture records the argv of the first dispatch it sees.
type argCapture struct{ args []string }

func (c *argCapture) record(args []string) {
	if c.args == nil {
		c.args = append([]string(nil), args...)
	}
}

func (c *argCapture) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	c.record(args)
	return &backend.Result{ExitCode: 0}, nil
}

func (c *argCapture) ExecEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return c.Exec(ctx, tl, args)
}

func (c *argCapture) Stream(_ context.Context, _ *backend.Tool, args []string) (<-chan backend.Event, error) {
	c.record(args)
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (c *argCapture) StreamEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return c.Stream(ctx, tl, args)
}

func (c *argCapture) HealthCheck(_ context.Context) error { return nil }
func (c *argCapture) Capacity() int                       { return 1 }

// permissiveTree admits everything — scope is not what this file tests.
type permissiveTree struct{}

func (permissiveTree) Append(_ string, _ [][]byte) error { return nil }
func (permissiveTree) InScope(_ string) bool             { return true }

// --- probe-vs-Task drift ------------------------------------------------------

// TestProbeTableDeclaresMirrors makes an unfilled `mirrors` field impossible.
//
// The field exists so a probe can say which Task it copies. A blank one would be
// indistinguishable from an entry nobody got round to filling in, and the drift
// check would skip it silently — reproducing the exact hole this file closes.
func TestProbeTableDeclaresMirrors(t *testing.T) {
	if len(subdomainWebProbes) == 0 {
		t.Fatal("subdomainWebProbes is empty — the probe table checks nothing")
	}
	for i, p := range subdomainWebProbes {
		if p.mirrors == "" {
			t.Errorf("probe %d (%s %v) has a blank mirrors field.\n"+
				"  Name the Task it copies, or say probeMirrorsNoTask explicitly. A blank is not a\n"+
				"  declaration, it is an omission that this drift check would skip.", i, p.name, p.args)
		}
	}
}

// TestProbeTableMatchesTaskArgVectors is the drift detector.
//
// The probe table's own comment claims each entry "uses the EXACT arg vector
// from internal/modules/…". Nothing enforced that, so a module could change a
// flag and the probe would keep validating the old vector forever — the same
// failure class the probe exists to prevent, relocated from the tool to the test.
//
// FLAG-NAME SETS, NOT FULL ARGV. Full equality is unachievable: the probe
// substitutes throwaway paths and a synthetic domain, and a test that cannot
// pass gets deleted. Flag names are what broke twice, so flag names are what is
// compared.
func TestProbeTableMatchesTaskArgVectors(t *testing.T) {
	byTask := map[string]driveCase{}
	for _, dc := range driveCases {
		byTask[dc.taskName] = dc
	}

	checked := 0
	for _, p := range subdomainWebProbes {
		if p.mirrors == probeMirrorsNoTask {
			continue
		}
		p := p
		t.Run(p.name+"->"+p.mirrors, func(t *testing.T) {
			if _, ok := task.Default.Lookup(p.mirrors); !ok {
				t.Fatalf("probe %q names Task %q, which is NOT REGISTERED — the entry is STALE.\n"+
					"  A renamed Task would otherwise leave this probe checking a vector nothing dispatches.",
					p.name, p.mirrors)
			}
			dc, ok := byTask[p.mirrors]
			if !ok {
				t.Skipf("Task %q is named by a probe but is not in driveCases, so its argv cannot be "+
					"captured here; add a driveCase or move it to undrivableTasks", p.mirrors)
			}
			argv, got := driveTaskForArgs(t, dc)
			if !got {
				t.Fatalf("%s dispatched nothing — the seed did not reach the tool call", dc.taskName)
			}
			probeFlags := flagNamesOf(p.args)
			taskFlags := flagNamesOf(argv)
			if onlyProbe, onlyTask := symmetricDiff(probeFlags, taskFlags); len(onlyProbe)+len(onlyTask) > 0 {
				t.Errorf("DRIFT: probe %q and Task %q dispatch different flag names.\n"+
					"  probe flags: %v\n"+
					"  task  flags: %v\n"+
					"  only in probe: %v\n"+
					"  only in task:  %v\n"+
					"  The probe table is a hand-copied duplicate of the module's arg vector. One of the\n"+
					"  two changed and the other did not — fix the probe, or fix the module, but do not\n"+
					"  leave them disagreeing: the probe would keep validating a vector nothing dispatches.",
					p.name, p.mirrors, probeFlags, taskFlags, onlyProbe, onlyTask)
			}
			checked++
		})
	}

	// A drift detector that checked nothing would pass. Say what it covered.
	t.Logf("PROBE_DRIFT_COVERAGE checked=%d of %d probe entries; the rest declare probeMirrorsNoTask",
		checked, len(subdomainWebProbes))
}

// flagNamesOf returns the sorted, de-duplicated dash-prefixed tokens in argv.
// Negative numbers are values, not flags (see dashToken).
func flagNamesOf(argv []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range argv {
		if !dashToken.MatchString(a) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func symmetricDiff(a, b []string) (onlyA, onlyB []string) {
	inB := map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	inA := map[string]bool{}
	for _, x := range a {
		inA[x] = true
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}
