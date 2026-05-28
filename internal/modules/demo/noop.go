// Package demo registers the Phase 3 noop.demo Task.
//
// Source: .planning/phases/03-foundation-kernel/03-CONTEXT.md
// "End-of-Phase-3 demo shape" default option (b) — hardcoded-stub
// `noop.demo` Task proves Scheduler + Backend + Tree + Checkpoint
// cooperate end-to-end with a single line in artefacts/demo.jsonl.
//
// Phase 3 acceptance integration test (Plan 07 TestKernelDemoEndToEnd)
// invokes Plan 06's `kernel-demo` hidden subcommand which runs this
// Task through the full Scheduler pipeline.
//
// DELETE THIS FILE in Phase 4 plan-01; replace with
// internal/modules/subdomains/passive.go. The Phase 4 plan-01
// acceptance includes the deletion of both this file AND
// cmd/reconftw/kernel_demo.go (Plan 06 ships the hidden subcommand —
// see CONTEXT D-05 W16).

package demo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// NoopTask is the Phase 3 demo Task. Single fixture line into
// artefacts/demo.jsonl proves the kernel pipeline cooperates.
type NoopTask struct{}

// Name returns the canonical task identifier.
func (NoopTask) Name() string { return "noop.demo" }

// Module returns the owning module group.
func (NoopTask) Module() string { return "demo" }

// Description returns the human-readable description.
func (NoopTask) Description() string {
	return "Phase 3 demo task — replaced in Phase 4 plan-01"
}

// Enabled is unconditionally true — the demo task is always available
// when the demo package is imported.
func (NoopTask) Enabled(*config.Config) bool { return true }

// DependsOn returns nil — the demo task has no dependencies; it runs
// first and standalone in the test pipeline.
func (NoopTask) DependsOn() []string { return nil }

// Run writes one fixture line to artefacts/demo.jsonl via the
// AppContext OutputTree. Returns Result with Status=Done and the
// artefact path in Outputs.
//
// Fixture content: `{"demo":"phase-3-kernel","timestamp":"<RFC3339>"}`.
// Plan 07 integration test reads the line back, decodes it, and
// asserts the fields.
func (NoopTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	if app == nil || app.Tree == nil {
		// Defensive — tests that pass a nil AppContext can't satisfy the
		// contract; return a skipped result rather than panicking.
		return task.Result{Status: task.StatusSkipped}, nil
	}
	line, err := json.Marshal(map[string]any{
		"demo":      "phase-3-kernel",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}
	if err := app.Tree.Append("demo", [][]byte{line}); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}
	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{"artefacts/demo.jsonl"},
	}, nil
}

// init registers NoopTask with the Default Task registry. Plan 06
// main.go blank-imports this package so the registration fires at
// binary startup:
//
//	import _ "github.com/six2dez/reconftw/internal/modules/demo"
func init() {
	task.Register(NoopTask{})
}
