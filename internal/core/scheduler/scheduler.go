// Package scheduler implements reconFTW v2's bounded concurrent task
// dispatcher with per-module-group failure_policy enforcement.
//
// Source: ADR 0002 §7.2 lines 1950-2054 (BINDING — fail_fast vs best_effort fork).
//
// Concurrency primitive: golang.org/x/sync/errgroup. Two distinct usage
// patterns map directly to the two policies:
//
//	PolicyFailFast  → errgroup.WithContext(ctx) — first error cancels peer ctx
//	PolicyBestEffort → zero-value errgroup.Group — no cancellation; errors logged
//
// Checkpoint integration (W15): Scheduler.Checkpoint is typed as
// checkpoint.Interface (NOT *checkpoint.Store). Plan 07's MockCheckpoint
// satisfies the interface — Plan 05 tests use an inline stub.
//
// Heartbeat (XCUT-09): each Task.Run wrapper starts a heartbeat goroutine
// at HeartbeatSeconds cadence. The goroutine is torn down by a defer; the
// per-package test init() calls goleak.VerifyNone to assert no leaks.
//
// BLOCKER 4 RESOLUTION: Scheduler ships in the same plan as the Task
// interface, so the canonical interface is born final — no `any`
// placeholders anywhere in scheduler/.
//
// IMPORT-CYCLE NOTE: scheduler does NOT import appctx. The Scheduler runs
// Tasks via the s.RunTask hook (a closure injected by appctx.Boot) rather
// than holding a reference to *appctx.AppContext directly. This breaks
// the appctx → scheduler → task → appctx cycle (Plan 05 Task 1 design).
// See internal/core/appctx/appctx.go header for the broader cycle-break
// rationale.

package scheduler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/task"
)

// RunTaskFunc wraps Task.Run so the Scheduler can invoke it without
// importing appctx. Injected by appctx.Boot (Plan 05 Task 2) as:
//
//	sched.RunTask = func(ctx context.Context, t task.Task) (task.Result, error) {
//	    return t.Run(ctx, app)
//	}
//
// If RunTask is nil at RunStage time, the Scheduler calls t.Run(ctx, nil).
// Plan 05 tests use a non-nil RunTask that just calls t.Run with a stub
// AppContext or directly invokes a closure capturing the test's fake.
type RunTaskFunc func(ctx context.Context, t task.Task) (task.Result, error)

// InputHasher computes a checkpoint input hash for (taskName, target).
// Defaults to checkpoint.InputHash when unset. Plan 05 tests inject a
// hash function over the test's stub config so the hash is deterministic.
type InputHasher func(taskName, target string) string

// Scheduler dispatches Tasks under a configured concurrency cap with
// per-module failure_policy semantics.
type Scheduler struct {
	// MaxConcurrent is the cap on simultaneously-running tasks per stage.
	// Maps to cfg.Concurrency.MaxJobs. Default: 4.
	MaxConcurrent int

	// HeartbeatSeconds is the cadence at which long-running tasks emit
	// "task_heartbeat" events (XCUT-09). 0 disables heartbeats.
	HeartbeatSeconds int

	// PolicyOverride maps module name → FailurePolicy. Lookups not present
	// here fall through to policyFor's default (subdomains→fail_fast,
	// everything else→best_effort).
	PolicyOverride map[string]FailurePolicy

	// Checkpoint is typed as the W15 interface so Plan 07's MockCheckpoint
	// satisfies it. *checkpoint.Store satisfies via the gate in
	// internal/core/checkpoint/interface.go.
	Checkpoint checkpoint.Interface

	// Log is the slog handle for "task_skipped_checkpoint_hit",
	// "task_error_best_effort", "task_heartbeat", etc. May be nil — falls
	// through to slog.Default().
	Log *slog.Logger

	// RunTask is the appctx-injected closure that invokes t.Run(ctx, app).
	// Set by appctx.Boot in Plan 05 Task 2; nil is tolerated for tests
	// that supply their own RunTask via direct field assignment.
	RunTask RunTaskFunc

	// Hash computes the checkpoint input_hash for (taskName, target). Test
	// hook — production uses checkpoint.InputHash via the runOne default.
	Hash InputHasher

	// ForceRerun, when true, skips the checkpoint Done() early-return so
	// already-completed tasks re-execute — but Begin/Complete still run, so the
	// forced run records FRESH checkpoints for the next run (never drops the
	// resumable state). Wired from cfg.Advanced.Diff / --force by BootReconApp
	// (INTEG-03). Default false = normal resume-from-checkpoint behavior. Has no
	// effect when Checkpoint is nil (all checkpoint steps skipped regardless).
	ForceRerun bool

	// Limiter, when non-nil, is a process-wide weighted semaphore that bounds
	// the TOTAL number of concurrently-executing tasks across ALL Scheduler
	// instances that share it. MCP server mode gives each scan session its OWN
	// Scheduler — so the per-scan RunTask / Checkpoint / Hash fields never race
	// across concurrent sessions — but injects one shared Limiter so the
	// sessions collectively cannot exceed PARALLEL_MAX_JOBS (MCP-05). nil = no
	// global cap (single-scan CLI mode, where per-stage MaxConcurrent suffices).
	Limiter *semaphore.Weighted
}

// MaxConcurrency implements the appctx.SchedulerRunner interface — the
// minimal contract appctx requires from the Scheduler. Plan 06 main.go
// type-asserts to *Scheduler to access the full API.
func (s *Scheduler) MaxConcurrency() int { return s.MaxConcurrent }

// NewScheduler constructs a Scheduler with the given limits and
// dependencies. maxJobs ≤ 0 is normalized to 4.
//
// cp may be nil — Scheduler skips checkpoint integration in that case
// (testing convenience). log may be nil — falls through to slog.Default.
func NewScheduler(maxJobs, heartbeatSec int, cp checkpoint.Interface, log *slog.Logger) *Scheduler {
	if maxJobs <= 0 {
		maxJobs = 4
	}
	return &Scheduler{
		MaxConcurrent:    maxJobs,
		HeartbeatSeconds: heartbeatSec,
		Checkpoint:       cp,
		Log:              log,
	}
}

// RunStage executes tasks under the failure_policy for module. Empty tasks
// is a no-op (returns nil).
//
// fail_fast: errgroup.WithContext — first error cancels peer context;
// stage returns the first non-nil error.
//
// best_effort: zero-value errgroup.Group — all tasks complete regardless
// of peer errors; per-task errors logged as warnings; stage returns nil.
//
// Per ADR §7.2 lines 1998-2032.
func (s *Scheduler) RunStage(ctx context.Context, module string, tasks []task.Task) error {
	if len(tasks) == 0 {
		return nil
	}
	policy := policyFor(module, s.PolicyOverride)

	if policy == PolicyFailFast {
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(s.MaxConcurrent)
		for _, t := range tasks {
			t := t // capture for goroutine
			g.Go(func() error { return s.runOne(gctx, t) })
		}
		return g.Wait()
	}

	// best_effort: zero-value errgroup — no peer cancellation.
	g := new(errgroup.Group)
	g.SetLimit(s.MaxConcurrent)
	for _, t := range tasks {
		t := t
		g.Go(func() error {
			if err := s.runOne(ctx, t); err != nil {
				// GAP-2 / T-04-09-01: ScopeError and OutOfScope are NOT swallowed.
				// Only ToolError/ToolTimeout (network flakiness) may be silently
				// logged. Scope violations indicate a security/scope misconfiguration
				// and must surface to the caller. The sentinel bridge is the ONLY
				// detection mechanism — no string matching permitted (ADR §6).
				if errors.Is(err, coreerrors.ErrScope) {
					return err // scope/security violation — surface it, never swallow
				}
				s.log().Warn("task_error_best_effort",
					slog.String("task", t.Name()),
					slog.String("module", t.Module()),
					slog.Any("err", err))
			}
			return nil // swallow per best_effort contract
		})
	}
	return g.Wait()
}

// runOne is the per-Task wrapper around checkpoint + heartbeat +
// LifecycleAware + Task.Run. Returns the Task's error (or nil).
//
// Checkpoint flow (Test 17/18):
//  1. Done(ctx, name, target, hash) — if true, skip without running.
//  2. Begin(ctx, name, target, hash) — record in-progress row.
//  3. Run the Task (with heartbeat + lifecycle wrappers).
//  4. Complete(ctx, name, target, hash, outputs, runErr).
//
// If Checkpoint is nil, all four steps are skipped — used by tests that
// disable checkpoint integration.
func (s *Scheduler) runOne(ctx context.Context, t task.Task) error {
	target := s.targetFor()
	hash := s.hashFor(t.Name(), target)

	if s.Checkpoint != nil {
		// ForceRerun (INTEG-03): bypass ONLY the Done() early-return so a forced
		// run re-executes completed tasks. Begin() below and Complete() at the end
		// still run, so the forced run records fresh checkpoints for the next run.
		if !s.ForceRerun {
			done, err := s.Checkpoint.Done(ctx, t.Name(), target, hash)
			if err != nil {
				return err
			}
			if done {
				s.log().Info("task_skipped_checkpoint_hit", slog.String("task", t.Name()))
				return nil
			}
		}
		if err := s.Checkpoint.Begin(ctx, t.Name(), target, hash); err != nil {
			return err
		}
	}

	// Global concurrency gate (MCP-05): when a shared Limiter is set, block
	// until a process-wide slot is free so concurrent scan sessions cannot
	// collectively exceed PARALLEL_MAX_JOBS. The per-stage errgroup SetLimit
	// only bounds a single scan's stage; the Limiter is the cross-session cap.
	// nil Limiter (CLI single-scan mode) skips this entirely. Acquire honors
	// ctx cancellation so a cancelled scan does not block forever.
	if s.Limiter != nil {
		if err := s.Limiter.Acquire(ctx, 1); err != nil {
			return err
		}
		defer s.Limiter.Release(1)
	}

	// LifecycleAware OnStart — errors logged as warnings; do not abort.
	if la, ok := t.(task.LifecycleAware); ok {
		if err := la.OnStart(ctx, nil); err != nil { // app passed via RunTask closure
			s.log().Warn("task_onstart_failed",
				slog.String("task", t.Name()),
				slog.Any("err", err))
		}
	}

	// Heartbeat goroutine (XCUT-09).
	cadence := time.Duration(s.HeartbeatSeconds) * time.Second
	stopHB := startHeartbeat(ctx, s.log(), t.Name(), t.Module(), cadence)
	defer stopHB()

	start := time.Now()
	result, runErr := s.invokeTask(ctx, t)
	result.Duration = time.Since(start)

	// LifecycleAware OnEnd — errors logged as warnings; main result wins.
	if la, ok := t.(task.LifecycleAware); ok {
		if endErr := la.OnEnd(ctx, nil, result); endErr != nil {
			s.log().Warn("task_onend_failed",
				slog.String("task", t.Name()),
				slog.Any("err", endErr))
		}
	}

	if s.Checkpoint != nil {
		_ = s.Checkpoint.Complete(ctx, t.Name(), target, hash, result.Outputs, runErr)
	}
	return runErr
}

// invokeTask invokes Task.Run via the RunTask hook. Falls back to t.Run(ctx, nil)
// if RunTask is unset — useful for unit tests that pass nil for the AppContext.
func (s *Scheduler) invokeTask(ctx context.Context, t task.Task) (task.Result, error) {
	if s.RunTask != nil {
		return s.RunTask(ctx, t)
	}
	return t.Run(ctx, nil)
}

// targetFor returns the checkpoint target string. Plan 05 Scheduler does
// not hold an AppContext reference (import-cycle break), so target comes
// from the optional Hash hook. Defaults to "" — tests use deterministic
// hashes anyway; Plan 06 main.go wires the real target via a closure that
// captures app.Target.Domain.
func (s *Scheduler) targetFor() string { return "" }

// hashFor computes the checkpoint input_hash. Defaults to a stable hash
// derived via checkpoint.InputHash with an empty config/wordlist slice
// (Phase 3 placeholder — Plan 06 main.go wires real config bytes via the
// Hash hook). Tests supply their own Hash for determinism.
func (s *Scheduler) hashFor(taskName, target string) string {
	if s.Hash != nil {
		return s.Hash(taskName, target)
	}
	return checkpoint.InputHash(taskName, target, jsonNil, []byte{})
}

// log returns the configured logger or slog.Default() if nil.
func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// jsonNil is the marshaled form of `nil` — used as the placeholder config
// slice when Hash is nil (Phase 3 default).
var jsonNil = func() []byte {
	b, _ := json.Marshal(nil)
	return b
}()
