// kernel_demo.go — hidden Phase 3 acceptance subcommand.
//
// PHASE 3 ACCEPTANCE ONLY. Authorized per:
//   - 03-CONTEXT.md D-05 (Revision iter 1 amendment, 2026-05-28) — W16.
//   - ADR §0 D-07 — non-breaking additions to the CLI surface are permitted.
//
// What it does: invokes the noop.demo Task through the full Scheduler
// pipeline so Plan 07's TestKernelDemoEndToEnd integration test can prove
// Scheduler + Backend + Tree + Checkpoint cooperate end-to-end.
//
// Why hidden: the 12 stubbed v2 subcommands (D-02) carry the operator-facing
// contract; surfacing kernel-demo in `--help` would muddy that semantic. Per
// ADR §0 D-07 non-breaking authorization, kernel-demo lives behind Hidden:true
// so it's only invokable by name (Plan 07 acceptance test) but not visible
// to v2 users browsing the binary.
//
// Phase 4 plan-01 ACCEPTANCE includes:
//
//	1. Delete cmd/reconftw/kernel_demo.go (this file).
//	2. Delete internal/modules/demo/noop.go.
//	3. Delete the corresponding blank import in cmd/reconftw/modules.go.
//	4. Add internal/modules/subdomains/passive.go (real subdomains.passive Task).
//
// The Phase 4 plan-01 SUMMARY must cite this comment when checking off the
// deletion items.

package main

import (
	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
)

// newKernelDemoCmd creates the hidden kernel-demo subcommand. Plan 07
// TestKernelDemoEndToEnd integration test invokes:
//
//	./bin/reconftw kernel-demo --target example.com
//
// Expected effect:
//   - workspaces/example.com-<timestamp>/artefacts/demo.jsonl contains one line.
//   - checkpoints.db contains a row for "noop.demo" with status=done.
//
// If --target was not supplied (app == nil), returns *exitCodeError{code: 2}
// — operator must rerun with --target.
func newKernelDemoCmd(app *appctx.AppContext) *cobra.Command {
	return &cobra.Command{
		Use:    "kernel-demo",
		Short:  "Phase 3 acceptance only — runs noop.demo through the Scheduler. Phase 4 deletes this command.",
		Hidden: true, // W16 / ADR §0 D-07 — NOT in --help.
		RunE: func(cmd *cobra.Command, args []string) error {
			if app == nil {
				return &exitCodeError{
					code: 2,
					msg:  "kernel-demo requires --target (e.g. `reconftw kernel-demo --target example.com`)",
				}
			}

			ctx := cmd.Context()

			// Pull the noop.demo Task from the Default registry. modules.go's
			// blank import of internal/modules/demo ensures it's registered
			// by init() at process start.
			tasks := []task.Task{}
			for _, t := range task.Default.All() {
				if t.Name() == "noop.demo" {
					tasks = append(tasks, t)
				}
			}
			if len(tasks) == 0 {
				return &exitCodeError{
					code: 1,
					msg:  "kernel-demo: noop.demo task not registered (cmd/reconftw/modules.go missing blank import?)",
				}
			}

			// app.Scheduler is the SchedulerRunner interface — type-assert to
			// the concrete *scheduler.Scheduler for RunStage access.
			sched, ok := app.Scheduler.(*scheduler.Scheduler)
			if !ok {
				return &exitCodeError{
					code: 1,
					msg:  "kernel-demo: app.Scheduler is not *scheduler.Scheduler — main.go wiring broken",
				}
			}

			return sched.RunStage(ctx, "demo", tasks)
		},
	}
}
