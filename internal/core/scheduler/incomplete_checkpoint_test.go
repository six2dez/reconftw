// incomplete_checkpoint_test.go — V-04: a run whose tool did not finish must not
// be checkpointed as done.
//
// checkpoint.Store.Complete derives its terminal status from runErr ALONE, and
// Done() returns true only for "done". A best-effort task that returned
// StatusDone with a nil error after its tool was killed by its own deadline wrote
// a DONE row, and the next run with the same input hash skipped the task
// entirely — a deadline turned into a permanent, silent hole in coverage.
package scheduler

import (
	"context"
	"errors"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// recordingCheckpoint captures what Complete was told, which is the whole point:
// the bug was invisible precisely because the RECORD disagreed with reality.
type recordingCheckpoint struct {
	completedErr error
	called       bool
}

func (c *recordingCheckpoint) Begin(context.Context, string, string, string) error { return nil }
func (c *recordingCheckpoint) Done(context.Context, string, string, string) (bool, error) {
	return false, nil
}

func (c *recordingCheckpoint) Complete(_ context.Context, _, _, _ string, _ []string, runErr error) error {
	c.called = true
	c.completedErr = runErr
	return nil
}

type fixedResultTask struct {
	name string
	res  task.Result
}

func (t *fixedResultTask) Name() string                { return t.name }
func (t *fixedResultTask) Module() string              { return "test" }
func (t *fixedResultTask) Description() string         { return "fixed-result task" }
func (t *fixedResultTask) Enabled(*config.Config) bool { return true }
func (t *fixedResultTask) DependsOn() []string         { return nil }
func (t *fixedResultTask) Run(context.Context, *appctx.AppContext) (task.Result, error) {
	return t.res, nil
}

func TestIncompleteRunIsNotCheckpointedAsDone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		result     task.Result
		wantCPErr  bool
		wantReason string
	}{
		{
			name:       "incomplete run records an error so it is retried",
			result:     task.Result{Status: task.StatusDone, Incomplete: true},
			wantCPErr:  true,
			wantReason: "a deadline-killed tool must be retried, not skipped forever",
		},
		{
			name:       "incomplete skipped run also records an error",
			result:     task.Result{Status: task.StatusSkipped, Incomplete: true},
			wantCPErr:  true,
			wantReason: "a partially published skipped run must be retried, not skipped forever",
		},
		{
			name:       "a genuinely complete run still records as done",
			result:     task.Result{Status: task.StatusDone},
			wantCPErr:  false,
			wantReason: "a clean run must not be forced to re-run",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cp := &recordingCheckpoint{}
			s := &Scheduler{Checkpoint: cp}
			s.RunTask = func(ctx context.Context, tk task.Task) (task.Result, error) {
				return tk.Run(ctx, nil)
			}

			runErr := s.runOne(context.Background(), &fixedResultTask{name: "t", res: tc.result})

			// The scan MUST NOT fail either way — these are best-effort tasks, and
			// returning the error would turn a tool timeout into a failed scan.
			if runErr != nil {
				t.Fatalf("runOne returned %v — an incomplete best-effort run must not fail the scan", runErr)
			}
			if !cp.called {
				t.Fatal("Checkpoint.Complete was never called, so this test asserts nothing")
			}
			gotErr := cp.completedErr != nil
			if gotErr != tc.wantCPErr {
				t.Fatalf("checkpointed error = %v, want non-nil = %v — %s",
					cp.completedErr, tc.wantCPErr, tc.wantReason)
			}
			if tc.wantCPErr && !errors.Is(cp.completedErr, task.ErrIncompleteRun) {
				t.Errorf("checkpointed error is %v, want task.ErrIncompleteRun", cp.completedErr)
			}
		})
	}
}
