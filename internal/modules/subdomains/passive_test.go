// passive_test.go — GAP-2 soft-fail tests for the passive RunStage.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-09-PLAN.md
// Task 2: TestPassiveSoftFail + TestPassiveSoftFailScopeErrorPropagates.
//
// These tests verify that:
//  1. A single flaky passive source error does NOT abort the stage (PolicyBestEffort).
//  2. A ScopeError/OutOfScope returned by a passive task IS propagated, not swallowed.
//
// The tests wire a Scheduler directly with module="subdomains.passive" so the
// policy lookup in policyFor returns PolicyBestEffort without any PolicyOverride.
// No internal/modules/subdomains import required — tasks are constructed inline
// (prevents any cycle; the scheduler → subdomains direction is fine since subdomains
// imports scheduler only in test files, not in production code).
package subdomains_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"

	"github.com/six2dez/reconftw/internal/core/config"
)

// fakeTask is a minimal task.Task implementation for unit tests.
type fakeTask struct {
	name  string
	runFn func(ctx context.Context) (task.Result, error)
}

func (f fakeTask) Name() string                  { return f.name }
func (f fakeTask) Module() string                { return "subdomains" }
func (f fakeTask) Description() string           { return "fake task for testing" }
func (f fakeTask) Enabled(_ *config.Config) bool { return true }
func (f fakeTask) DependsOn() []string           { return nil }
func (f fakeTask) Run(ctx context.Context, _ *appctx.AppContext) (task.Result, error) {
	return f.runFn(ctx)
}

// TestPassiveSoftFail: one erroring passive task (ToolError/network flakiness)
// must NOT abort the stage — RunStage("subdomains.passive", ...) returns nil.
//
// Source: GAP-2 plan 04-09 Task 2.
func TestPassiveSoftFail(t *testing.T) {
	ctx := context.Background()

	goodRan := false
	goodTask := fakeTask{
		name: "subdomains.passive.good",
		runFn: func(ctx context.Context) (task.Result, error) {
			goodRan = true
			return task.Result{Status: task.StatusDone}, nil
		},
	}
	badTask := fakeTask{
		name: "subdomains.passive.bad",
		runFn: func(ctx context.Context) (task.Result, error) {
			return task.Result{Status: task.StatusErrored},
				&coreerrors.ToolError{Tool: "crt", ExitCode: 1, Stderr: "network timeout"}
		},
	}

	sched := scheduler.NewScheduler(4, 0, nil, nil)
	// Use RunTask hook so tasks execute without a real AppContext.
	sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
		return t.Run(ctx, nil)
	}

	err := sched.RunStage(ctx, "subdomains.passive", []task.Task{goodTask, badTask})
	if err != nil {
		t.Errorf("TestPassiveSoftFail: RunStage returned non-nil error %v; want nil (best_effort should swallow ToolError)", err)
	}
	if !goodRan {
		t.Error("TestPassiveSoftFail: good task did not run — bad task should not cancel peers")
	}
}

// TestPassiveSoftFailScopeErrorPropagates: a ScopeError returned by a passive task
// MUST be re-propagated even in best_effort mode — scope violations are never swallowed.
//
// Source: GAP-2 plan 04-09 Task 2 + T-04-09-01 threat mitigation.
func TestPassiveSoftFailScopeErrorPropagates(t *testing.T) {
	ctx := context.Background()

	scopeErr := &coreerrors.ScopeError{
		Input:  "evil.notexample.com",
		Reason: "domain not in scope *.example.com",
	}
	// Verify our test error satisfies the sentinel bridge before asserting on scheduler.
	if !errors.Is(scopeErr, coreerrors.ErrScope) {
		t.Fatal("test setup: ScopeError.Is(ErrScope) returned false — sentinel bridge broken")
	}

	badTask := fakeTask{
		name: "subdomains.passive.scope-violation",
		runFn: func(ctx context.Context) (task.Result, error) {
			return task.Result{Status: task.StatusErrored}, scopeErr
		},
	}
	goodTask := fakeTask{
		name: "subdomains.passive.good",
		runFn: func(ctx context.Context) (task.Result, error) {
			return task.Result{Status: task.StatusDone}, nil
		},
	}

	sched := scheduler.NewScheduler(4, 0, nil, nil)
	sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
		return t.Run(ctx, nil)
	}

	err := sched.RunStage(ctx, "subdomains.passive", []task.Task{badTask, goodTask})
	if err == nil {
		t.Fatal("TestPassiveSoftFailScopeErrorPropagates: RunStage returned nil; want non-nil (scope error must surface)")
	}
	if !errors.Is(err, coreerrors.ErrScope) {
		t.Errorf("TestPassiveSoftFailScopeErrorPropagates: returned error %v does not match ErrScope sentinel; want errors.Is(err, coreerrors.ErrScope)==true", err)
	}
}

// TestPassiveSoftFailOutOfScopePropagates: an OutOfScope returned by a passive task
// must also be re-propagated (OutOfScope shares the ErrScope sentinel with ScopeError).
//
// Source: GAP-2 plan 04-09 Task 2 + errors.go comments (both structs use ErrScope).
func TestPassiveSoftFailOutOfScopePropagates(t *testing.T) {
	ctx := context.Background()

	oosErr := &coreerrors.OutOfScope{
		Value:  "notexample.com",
		Reason: "not in wildcard *.example.com",
	}
	if !errors.Is(oosErr, coreerrors.ErrScope) {
		t.Fatal("test setup: OutOfScope.Is(ErrScope) returned false — sentinel bridge broken")
	}

	badTask := fakeTask{
		name: "subdomains.passive.oos-violation",
		runFn: func(ctx context.Context) (task.Result, error) {
			return task.Result{Status: task.StatusErrored}, oosErr
		},
	}

	sched := scheduler.NewScheduler(4, 0, nil, nil)
	sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
		return t.Run(ctx, nil)
	}

	err := sched.RunStage(ctx, "subdomains.passive", []task.Task{badTask})
	if err == nil {
		t.Fatal("TestPassiveSoftFailOutOfScopePropagates: RunStage returned nil; want non-nil (OutOfScope must surface)")
	}
	if !errors.Is(err, coreerrors.ErrScope) {
		t.Errorf("TestPassiveSoftFailOutOfScopePropagates: returned error %v does not match ErrScope sentinel", err)
	}
}

// TestPassiveSpineStaysFailFast: resolve/brute stages with module="subdomains"
// must still use fail_fast — the spine is not softened by GAP-2.
func TestPassiveSpineStaysFailFast(t *testing.T) {
	ctx := context.Background()

	// A simple fmt.Errorf (not a scope error) returned from module="subdomains"
	// must propagate (fail_fast semantics).
	badTask := fakeTask{
		name: "subdomains.resolve.dns",
		runFn: func(ctx context.Context) (task.Result, error) {
			return task.Result{Status: task.StatusErrored}, fmt.Errorf("dns resolution failed")
		},
	}

	sched := scheduler.NewScheduler(4, 0, nil, nil)
	sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
		return t.Run(ctx, nil)
	}

	err := sched.RunStage(ctx, "subdomains", []task.Task{badTask})
	if err == nil {
		t.Error("TestPassiveSpineStaysFailFast: RunStage returned nil for module='subdomains'; want non-nil (fail_fast must propagate error)")
	}
}
