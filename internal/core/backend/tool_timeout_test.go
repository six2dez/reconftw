// tool_timeout_test.go — a tool that blocks must fail visibly, within a bound.
//
// ORIGIN: phase 16 plan 03 established that httpx, naabu, nuclei and notify had
// `timeout_seconds = 0` in tools.lock, and that applyToolContract is the ONLY
// place a tool acquires a deadline — there is no per-task timeout in the
// scheduler and no run-level deadline in cmd/reconftw. A tool that blocked
// therefore blocked until the operator killed the process, and the run reported
// nothing at all about it. Plan 16-05 gives those four a bound (option P4,
// chosen by the operator on 2026-08-24).
//
// P0 WAS ALSO CHOSEN, AND THAT MATTERS FOR READING THIS FILE. The update-check
// hypothesis was FALSIFIED — arm C of the 16-03 matrix showed the startup check
// is bounded at ~5s, and the one hang that WAS reproduced happened with the
// update-check flag present and zero connections to the instrumented endpoint.
// So these deadlines are not a fix for a known mechanism. They are the guard
// that works WITHOUT knowing the mechanism: whatever causes a stall, the run now
// reports it instead of hanging.
//
// # THE THREE LANDING POINTS
//
// A timeout has to surface in three places that were built by three different
// plans, and this is the first change that exercises all of them at once. Their
// composition is asserted here rather than assumed:
//
//	(a) the recorder   logs/tools.jsonl carries OutcomeTimeout   (plan 16-01)
//	(b) the task       a non-Done status whose Reason names it   (plan 16-02)
//	(c) the error      errors.Is(err, coreerrors.ErrTimeout)     (phase 3)
package backend_test

import (
	"context"
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/task"
)

// intendedDeadlines is what plan 16-05 set, in the units a reader expects.
//
// A SECONDS-VERSUS-NANOSECONDS MIX-UP IN A MANIFEST FIELD IS SILENT AND TOTAL:
// every tool would appear to time out instantly, or never. registry_seed.go
// multiplies timeout_seconds by time.Second; this pins the result.
var intendedDeadlines = map[string]time.Duration{
	"httpx":  time.Hour,
	"naabu":  time.Hour,
	"nuclei": 4 * time.Hour,
	"notify": 5 * time.Minute,
}

// TestToolsLockDeadlinesParseToIntendedDurations is the unit-correctness guard.
func TestToolsLockDeadlinesParseToIntendedDurations(t *testing.T) {
	for name, want := range intendedDeadlines {
		tool, ok := backend.Default.Lookup(name)
		if !ok {
			t.Errorf("%s is not in the seeded registry — the manifest entry did not load", name)
			continue
		}
		if tool.Timeout != want {
			t.Errorf("%s Timeout = %v, want %v.\n"+
				"  registry_seed.go reads timeout_seconds and multiplies by time.Second. A mismatch here\n"+
				"  is either a manifest edit that did not land or a unit error, and a unit error would\n"+
				"  make every invocation of this tool time out instantly or never.", name, tool.Timeout, want)
		}
		if tool.Timeout == 0 {
			t.Errorf("%s has NO deadline. applyToolContract is the only layer that supplies one, so a "+
				"blocked %s blocks until the operator kills the process.", name, name)
		}
	}
}

// TestToolTimeout_ExecPath_SurfacesToolTimeout is landing point (c) on the
// buffered path, and Test 1 of the plan's behaviour list.
func TestToolTimeout_ExecPath_SurfacesToolTimeout(t *testing.T) {
	runner, _ := timeoutRunner(t, 200*time.Millisecond)

	start := time.Now()
	_, err := runner.Run(context.Background(), "slowtool", []string{"30"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a tool that outlived its deadline returned no error — the deadline is not applied")
	}
	if !stderrors.Is(err, coreerrors.ErrTimeout) {
		t.Fatalf("err = %v (%T), want errors.Is(err, ErrTimeout).\n"+
			"  A generic error here means a caller cannot tell a stall from any other failure, which is\n"+
			"  the distinction the whole deadline exists to create.", err, err)
	}
	var tt *coreerrors.ToolTimeout
	if !stderrors.As(err, &tt) {
		t.Fatalf("err = %v, want a *ToolTimeout carrying the tool name", err)
	}
	if tt.Tool != "slowtool" {
		t.Errorf("ToolTimeout.Tool = %q, want %q — an unnamed timeout is not actionable", tt.Tool, "slowtool")
	}
	// The bound must actually bound. Generous ceiling: the point is that it
	// returned in the region of the deadline, not at the tool's own 30s.
	if elapsed > 10*time.Second {
		t.Errorf("the call took %v against a 200ms deadline — the deadline did not fire", elapsed)
	}
}

// TestToolTimeout_StreamPath_ReachesConsumerAsTerminalEvent is Test 2.
//
// A channel that simply CLOSES is indistinguishable from a tool that finished,
// which is the F6 failure class phase 15 closed for exit codes. The deadline has
// to arrive as a terminal Event.Err.
func TestToolTimeout_StreamPath_ReachesConsumerAsTerminalEvent(t *testing.T) {
	runner, _ := timeoutRunner(t, 200*time.Millisecond)

	ch, err := runner.Stream(context.Background(), "slowtool", []string{"30"})
	if err != nil {
		t.Fatalf("Stream dispatch failed: %v", err)
	}
	var termErr error
	for ev := range ch {
		if ev.Err != nil {
			termErr = ev.Err
		}
	}
	if termErr == nil {
		t.Fatal("the stream closed with NO terminal error after its deadline fired — a consumer cannot " +
			"tell that from a tool that finished cleanly")
	}
	if !stderrors.Is(termErr, coreerrors.ErrTimeout) {
		t.Errorf("terminal Event.Err = %v, want errors.Is(err, ErrTimeout)", termErr)
	}
}

// TestToolTimeout_FastToolIsUnaffected is Test 3, and it is the no-truncation
// assertion: a deadline must not change the behaviour or the duration of work
// that finishes well inside it.
func TestToolTimeout_FastToolIsUnaffected(t *testing.T) {
	runner, _ := timeoutRunner(t, 30*time.Second)

	start := time.Now()
	res, err := runner.Run(context.Background(), "fasttool", []string{"hello"})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("a tool finishing inside its deadline returned err=%v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "hello") {
		t.Errorf("stdout = %q, want it to contain %q", res.Stdout, "hello")
	}
	// The deadline machinery must not inflate the duration toward the deadline.
	if elapsed > 5*time.Second {
		t.Errorf("a trivial command took %v under a 30s deadline — the deadline machinery is waiting "+
			"for something it should not", elapsed)
	}
}

// TestToolTimeout_RecordedWithTimeoutOutcome is landing point (a).
//
// Plan 16-01's recorder has a CLOSED outcome vocabulary, and OutcomeTimeout is
// deliberately distinct from OutcomeExitNonZero. A stall recorded as an ordinary
// non-zero exit would be invisible to any grep looking for stalls.
func TestToolTimeout_RecordedWithTimeoutOutcome(t *testing.T) {
	runner, logPath := timeoutRunner(t, 200*time.Millisecond)

	_, _ = runner.Run(context.Background(), "slowtool", []string{"30"})

	data, err := os.ReadFile(logPath) //nolint:gosec
	if err != nil {
		t.Fatalf("read %s: %v — the recorder wrote nothing for a timed-out tool", logPath, err)
	}
	// START and END are SEPARATE records paired by id: only the start carries
	// `tool`, only the end carries `outcome`. An earlier version of this test
	// looked for both fields on one line and reported a product defect that did
	// not exist — the pairing is the recorder's documented shape.
	toolByID := map[string]string{}
	outcomeByID := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec struct {
			ID      string `json:"id"`
			Tool    string `json:"tool"`
			Outcome string `json:"outcome"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		if rec.Tool != "" {
			toolByID[rec.ID] = rec.Tool
		}
		if rec.Outcome != "" {
			outcomeByID[rec.ID] = rec.Outcome
		}
	}
	var sawTimeout bool
	for id, tool := range toolByID {
		if tool == "slowtool" && outcomeByID[id] == backend.OutcomeTimeout {
			sawTimeout = true
		}
	}
	if !sawTimeout {
		t.Errorf("logs/tools.jsonl has no %q record for slowtool.\n"+
			"  full log:\n%s\n"+
			"  A stall that is not recorded with its own outcome cannot be found by anyone reading a\n"+
			"  run's record afterwards, which is the only way a 4-hour timeout is ever diagnosed.",
			backend.OutcomeTimeout, data)
	}
}

// TestToolTimeout_TaskReportsNonOKWithAReasonNamingIt is landing point (b).
//
// Plan 16-02's rule: a task whose tool failed reports SKIP with a reason an
// operator can read, never OK. A timeout has to land in that same place rather
// than inventing a new one — so this asserts the composition of 16-02's
// constructor with this plan's error, which is what a module will actually do.
func TestToolTimeout_TaskReportsNonOKWithAReasonNamingIt(t *testing.T) {
	timeoutErr := &coreerrors.ToolTimeout{Tool: "httpx", Timeout: time.Hour}
	res := task.ToolDegraded("httpx", timeoutErr)

	if res.Status == task.StatusDone {
		t.Fatal("a timed-out tool produced StatusDone — on the operator's screen that is [OK], which is " +
			"exactly the silent-success shape plan 16-02 closed")
	}
	if res.Reason == "" {
		t.Fatal("a non-Done status with an empty Reason tells the operator nothing")
	}
	for _, want := range []string{"httpx", "timed out"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("Reason = %q, want it to contain %q so the operator can tell a stall from any "+
				"other tool failure without opening the log", res.Reason, want)
		}
	}
}

// --- harness ------------------------------------------------------------------

// timeoutRunner builds a Runner over the REAL LocalBackend with a recorder, and
// registers two tools: `slowtool` (/bin/sleep) with the given deadline and
// `fasttool` (/bin/echo) with the same one.
//
// The real backend is used deliberately: a mock cannot demonstrate that a
// deadline stops an actual process, which is the entire claim.
func timeoutRunner(t *testing.T, deadline time.Duration) (*backend.Runner, string) {
	t.Helper()
	for _, p := range []string{"/bin/sleep", "/bin/echo"} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("%s is not present on this system, so a real-process deadline cannot be demonstrated", p)
		}
	}

	workDir := t.TempDir()
	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "slowtool", Path: "/bin/sleep", Timeout: deadline})
	reg.Register(&backend.Tool{Name: "fasttool", Path: "/bin/echo", Timeout: deadline})

	runner := backend.NewRunner(backend.NewLocalBackend(2*time.Second), reg, nil)
	runner.Recorder = backend.NewToolRecorder(logPath, nil)
	return runner, logPath
}
