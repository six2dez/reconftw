package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// gatedTask increments a shared in-flight counter on entry and records the
// peak concurrency observed across ALL schedulers that ran it. Used to prove
// the shared Limiter enforces a global concurrency ceiling (MCP-05).
type gatedTask struct {
	module   string
	inFlight *atomic.Int32
	peak     *atomic.Int32
	hold     time.Duration
}

func (g *gatedTask) Name() string                { return "gated" }
func (g *gatedTask) Module() string              { return g.module }
func (g *gatedTask) Description() string         { return "gated task" }
func (g *gatedTask) Enabled(*config.Config) bool { return true }
func (g *gatedTask) DependsOn() []string         { return nil }

func (g *gatedTask) Run(ctx context.Context, _ *appctx.AppContext) (task.Result, error) {
	cur := g.inFlight.Add(1)
	defer g.inFlight.Add(-1)
	for { // record the peak observed concurrency
		p := g.peak.Load()
		if cur <= p || g.peak.CompareAndSwap(p, cur) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return task.Result{Status: task.StatusCancelled}, ctx.Err()
	case <-time.After(g.hold):
	}
	return task.Result{Status: task.StatusDone}, nil
}

// TestSharedLimiterGlobalConcurrency proves that when N independent Scheduler
// instances share ONE Limiter (the MCP server model — one scheduler per scan
// session, one global semaphore), the total number of concurrently-executing
// tasks across ALL schedulers never exceeds the limiter weight, even though
// each scheduler's own per-stage MaxConcurrent is higher.
//
// This is the regression guard for the Phase 8 verifier finding: the previous
// design shared a single Scheduler struct across sessions (racing on the
// per-scan RunTask/Checkpoint fields and NOT actually bounding global
// concurrency). The fix gives each session its own Scheduler plus a shared
// Limiter; this test asserts the global bound holds.
func TestSharedLimiterGlobalConcurrency(t *testing.T) {
	const weight = 2
	const sessions = 3
	const tasksPerSession = 4

	limiter := semaphore.NewWeighted(weight)
	var inFlight, peak atomic.Int32

	var wg sync.WaitGroup
	for s := 0; s < sessions; s++ {
		wg.Add(1)
		go func(s int) {
			defer wg.Done()
			// Each session has its OWN scheduler with a generous per-stage cap
			// (higher than the global weight) so the global Limiter — not the
			// per-stage errgroup — is what bounds concurrency.
			sched := NewScheduler(tasksPerSession, 0, nil, nil)
			sched.Limiter = limiter
			tasks := make([]task.Task, tasksPerSession)
			for i := range tasks {
				tasks[i] = &gatedTask{
					module:   "osint", // best_effort: no peer cancellation
					inFlight: &inFlight,
					peak:     &peak,
					hold:     20 * time.Millisecond,
				}
			}
			if err := sched.RunStage(context.Background(), "osint", tasks); err != nil {
				t.Errorf("session %d RunStage: %v", s, err)
			}
		}(s)
	}
	wg.Wait()

	if got := peak.Load(); got > weight {
		t.Fatalf("global concurrency exceeded shared limiter weight: peak=%d, weight=%d", got, weight)
	}
	if peak.Load() == 0 {
		t.Fatal("no tasks observed running — test did not exercise the scheduler")
	}
}

// TestNilLimiterUnbounded confirms the CLI path (nil Limiter) is unaffected:
// a single scheduler with no Limiter runs up to its per-stage MaxConcurrent.
func TestNilLimiterUnbounded(t *testing.T) {
	var inFlight, peak atomic.Int32
	sched := NewScheduler(4, 0, nil, nil) // nil Limiter
	tasks := make([]task.Task, 4)
	for i := range tasks {
		tasks[i] = &gatedTask{module: "osint", inFlight: &inFlight, peak: &peak, hold: 20 * time.Millisecond}
	}
	if err := sched.RunStage(context.Background(), "osint", tasks); err != nil {
		t.Fatalf("RunStage: %v", err)
	}
	if peak.Load() < 2 {
		t.Fatalf("expected per-stage parallelism with nil limiter, peak=%d", peak.Load())
	}
}
