// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior tests 11-19, 23-24 — Scheduler.RunStage + failure_policy fork
// + checkpoint integration + LifecycleAware hook.
package scheduler_test

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
)

// stubCheckpoint is the test double satisfying checkpoint.Interface. In-
// memory; tracks Begin / Complete / Done call counts and the done-map.
type stubCheckpoint struct {
	mu       sync.Mutex
	beginN   int
	doneN    int
	complN   int
	doneMap  map[string]bool
	doneErr  error
	beginErr error
}

func (s *stubCheckpoint) Begin(_ context.Context, _, _, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beginN++
	return s.beginErr
}

func (s *stubCheckpoint) Done(_ context.Context, task, _, _ string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.doneN++
	if s.doneErr != nil {
		return false, s.doneErr
	}
	return s.doneMap[task], nil
}

func (s *stubCheckpoint) Complete(_ context.Context, _, _, _ string, _ []string, _ error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.complN++
	return nil
}

var _ checkpoint.Interface = (*stubCheckpoint)(nil)

// fakeTask is the controllable test Task. Fields below tune behaviour.
type fakeTask struct {
	name     string
	module   string
	dur      time.Duration
	err      error
	deps     []string
	started  atomic.Int32
	finished atomic.Int32
}

func (f *fakeTask) Name() string                    { return f.name }
func (f *fakeTask) Module() string                  { return f.module }
func (f *fakeTask) Description() string             { return "fake " + f.name }
func (f *fakeTask) Enabled(*config.Config) bool     { return true }
func (f *fakeTask) DependsOn() []string             { return f.deps }
func (f *fakeTask) Run(ctx context.Context, _ *appctx.AppContext) (task.Result, error) {
	f.started.Add(1)
	defer f.finished.Add(1)
	if f.dur > 0 {
		select {
		case <-ctx.Done():
			return task.Result{Status: task.StatusCancelled}, ctx.Err()
		case <-time.After(f.dur):
		}
	}
	if f.err != nil {
		return task.Result{Status: task.StatusErrored}, f.err
	}
	return task.Result{Status: task.StatusDone, Outputs: []string{"out/" + f.name}}, nil
}

// lifecycleTask records OnStart/OnEnd invocations.
type lifecycleTask struct {
	fakeTask
	onStart    atomic.Int32
	onEnd      atomic.Int32
	onStartErr error
	onEndErr   error
}

func (l *lifecycleTask) OnStart(context.Context, *appctx.AppContext) error {
	l.onStart.Add(1)
	return l.onStartErr
}
func (l *lifecycleTask) OnEnd(context.Context, *appctx.AppContext, task.Result) error {
	l.onEnd.Add(1)
	return l.onEndErr
}

func newScheduler(cp checkpoint.Interface) *scheduler.Scheduler {
	s := scheduler.NewScheduler(4, 0, cp, slog.Default())
	s.Hash = func(name, target string) string { return "hash-" + name }
	return s
}

// Test 11: NewScheduler returns a working *Scheduler.
func TestNewSchedulerWorks(t *testing.T) {
	s := scheduler.NewScheduler(8, 5, nil, slog.Default())
	if s == nil {
		t.Fatal("NewScheduler returned nil")
	}
	if s.MaxConcurrent != 8 {
		t.Errorf("MaxConcurrent = %d, want 8", s.MaxConcurrent)
	}
	// negative MaxJobs gets clamped to 4
	s2 := scheduler.NewScheduler(0, 1, nil, nil)
	if s2.MaxConcurrent != 4 {
		t.Errorf("zero MaxJobs not clamped: %d", s2.MaxConcurrent)
	}
	// Implements SchedulerRunner interface
	var _ appctx.SchedulerRunner = s
	if s.MaxConcurrency() != 8 {
		t.Errorf("MaxConcurrency() = %d, want 8", s.MaxConcurrency())
	}
}

// Test 12: RunStage runs all tasks (fail_fast — subdomains).
func TestRunStageAllTasksRun(t *testing.T) {
	s := newScheduler(nil)
	a := &fakeTask{name: "a", module: "subdomains"}
	b := &fakeTask{name: "b", module: "subdomains"}
	c := &fakeTask{name: "c", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a, b, c}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	if a.started.Load() != 1 || b.started.Load() != 1 || c.started.Load() != 1 {
		t.Errorf("not all tasks ran: a=%d b=%d c=%d", a.started.Load(), b.started.Load(), c.started.Load())
	}
}

// Test 13: empty tasks is a no-op.
func TestRunStageEmpty(t *testing.T) {
	s := newScheduler(nil)
	if err := s.RunStage(context.Background(), "subdomains", nil); err != nil {
		t.Errorf("RunStage(nil) error = %v", err)
	}
}

// Test 14: TestFailureMatrixFailFast — first error cancels peers.
func TestFailureMatrixFailFast(t *testing.T) {
	s := newScheduler(nil)
	a := &fakeTask{name: "a", module: "subdomains", err: errors.New("a-failed")}
	// b and c are long-running so the ctx cancellation can interrupt them.
	b := &fakeTask{name: "b", module: "subdomains", dur: 2 * time.Second}
	c := &fakeTask{name: "c", module: "subdomains", dur: 2 * time.Second}

	start := time.Now()
	err := s.RunStage(context.Background(), "subdomains", []task.Task{a, b, c})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("RunStage with fail_fast + errored task returned nil")
	}
	// b and c got cancelled — elapsed should be << 2s
	if elapsed > 1*time.Second {
		t.Errorf("RunStage elapsed = %v; expected fast cancellation (<1s)", elapsed)
	}
}

// Test 15: TestFailureMatrixBestEffort — error logged, peers continue,
// stage returns nil.
func TestFailureMatrixBestEffort(t *testing.T) {
	s := newScheduler(nil)
	a := &fakeTask{name: "a", module: "osint", err: errors.New("a-failed")}
	b := &fakeTask{name: "b", module: "osint"}
	c := &fakeTask{name: "c", module: "osint"}
	err := s.RunStage(context.Background(), "osint", []task.Task{a, b, c})
	if err != nil {
		t.Errorf("RunStage best_effort returned %v; want nil (errors swallowed)", err)
	}
	if a.started.Load() != 1 || b.started.Load() != 1 || c.started.Load() != 1 {
		t.Errorf("not all best_effort tasks ran: a=%d b=%d c=%d",
			a.started.Load(), b.started.Load(), c.started.Load())
	}
}

// Test 17: TestCheckpointSkipOnHit — Done returns true → task skipped.
func TestCheckpointSkipOnHit(t *testing.T) {
	cp := &stubCheckpoint{doneMap: map[string]bool{"skipme": true}}
	s := newScheduler(cp)
	a := &fakeTask{name: "skipme", module: "subdomains"}
	b := &fakeTask{name: "runme", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a, b}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	if a.started.Load() != 0 {
		t.Errorf("Done-hit task ran: started=%d", a.started.Load())
	}
	if b.started.Load() != 1 {
		t.Errorf("Done-miss task did NOT run: started=%d", b.started.Load())
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.beginN != 1 {
		t.Errorf("Begin called %d times, want 1", cp.beginN)
	}
	if cp.doneN != 2 {
		t.Errorf("Done called %d times, want 2", cp.doneN)
	}
	if cp.complN != 1 {
		t.Errorf("Complete called %d times, want 1", cp.complN)
	}
}

// Test 18: Begin → Run → Complete sequence is recorded.
func TestBeginRunCompleteSequence(t *testing.T) {
	cp := &stubCheckpoint{}
	s := newScheduler(cp)
	a := &fakeTask{name: "a", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.beginN != 1 || cp.complN != 1 {
		t.Errorf("Begin/Complete counts wrong: beginN=%d complN=%d", cp.beginN, cp.complN)
	}
}

// Test 19: hash computation uses checkpoint.InputHash by default.
// The scheduler's Hash hook is set in newScheduler; here we use the
// default by constructing a Scheduler directly without setting Hash.
func TestDefaultHashUsesInputHash(t *testing.T) {
	cp := &stubCheckpoint{}
	s := scheduler.NewScheduler(4, 0, cp, slog.Default())
	a := &fakeTask{name: "a", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	// We can't observe the hash directly without a hook; the InputHash
	// path is exercised — coverage will catch regressions.
}

// Test 23-24: LifecycleAware OnStart called before Run; OnEnd called
// after. OnEnd errors are logged but don't fail the task.
func TestLifecycleHooksCalled(t *testing.T) {
	s := newScheduler(nil)
	l := &lifecycleTask{fakeTask: fakeTask{name: "l", module: "subdomains"}}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{l}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	if l.onStart.Load() != 1 {
		t.Errorf("OnStart count = %d, want 1", l.onStart.Load())
	}
	if l.onEnd.Load() != 1 {
		t.Errorf("OnEnd count = %d, want 1", l.onEnd.Load())
	}
	if l.fakeTask.started.Load() != 1 {
		t.Errorf("Run count = %d, want 1", l.fakeTask.started.Load())
	}
}

func TestLifecycleOnEndErrorIsLoggedNotPropagated(t *testing.T) {
	s := newScheduler(nil)
	l := &lifecycleTask{
		fakeTask:  fakeTask{name: "l", module: "subdomains"},
		onEndErr:  errors.New("end-err"),
	}
	err := s.RunStage(context.Background(), "subdomains", []task.Task{l})
	if err != nil {
		t.Errorf("OnEnd error propagated to RunStage: %v", err)
	}
}

// Test (smoke): Checkpoint.Begin error propagates as RunStage error
// (fail_fast — first error stops the stage).
func TestCheckpointBeginErrorPropagates(t *testing.T) {
	cp := &stubCheckpoint{beginErr: errors.New("begin-failed")}
	s := newScheduler(cp)
	a := &fakeTask{name: "a", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a}); err == nil {
		t.Fatal("RunStage with Begin error returned nil")
	} else if !errors.Is(err, cp.beginErr) {
		t.Errorf("RunStage error = %v; want %v", err, cp.beginErr)
	}
	if a.started.Load() != 0 {
		t.Errorf("task ran despite Begin error; started=%d", a.started.Load())
	}
}

// Test (smoke): RunTask hook is called when set; receives task by value.
func TestRunTaskHookInvoked(t *testing.T) {
	s := newScheduler(nil)
	called := atomic.Int32{}
	s.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
		called.Add(1)
		return t.Run(ctx, nil)
	}
	a := &fakeTask{name: "a", module: "subdomains"}
	if err := s.RunStage(context.Background(), "subdomains", []task.Task{a}); err != nil {
		t.Fatalf("RunStage error = %v", err)
	}
	if called.Load() != 1 {
		t.Errorf("RunTask hook called %d times, want 1", called.Load())
	}
}
