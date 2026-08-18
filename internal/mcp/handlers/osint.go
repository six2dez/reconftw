// Package handlers — OSINT collection handler.
package handlers

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/osint"
)

// osintStageSpec is the per-stage descriptor for the OSINT pipeline.
// Mirrors osintStageSpec in cmd/reconftw/stub_subcommands.go.
type osintStageSpec struct {
	name     string
	prefixes []string
}

// osintStages returns the authoritative ordered OSINT pipeline.
//
// D-O1/D-O8/ARCH-09: most osint tasks run in parallel within the "osint"
// stage. Only the github_repos→github_leaks fold (D-O10) needs sequencing:
// github_repos runs in a pre-stage that fully completes before the "osint"
// stage containing github_leaks starts.
func osintHandlerStages() []osintStageSpec {
	return []osintStageSpec{
		{
			name:     "github-repos",
			prefixes: []string{"osint.github_repos"},
		},
		{
			name: "osint",
			prefixes: []string{
				"osint.domain_info",
				"osint.ip_info",
				"osint.emails",
				"osint.spoofy",
				"osint.github_dorks",
				"osint.gitdorks",
				"osint.github_leaks",
				"osint.github_actions",
				"osint.cloud_enum",
				"osint.postman",
				"osint.swagger",
				"osint.misconfig",
				"osint.msftrecon",
				"osint.cmseek",
				"osint.favirecon",
				"osint.gqlspection",
				"osint.cewler",
				"osint.xnldorker",
				"osint.metadata",
			},
		},
	}
}

// RunOSINTAsync executes the full OSINT collection pipeline.
//
// OSINT is root-domain / company-seeded (D-O1) — no --urls corpus needed.
// All stages are best_effort (D-O8/ARCH-09). B3 fix: app.Checkpoint closed
// via defer; opts.Scheduler.Checkpoint NOT written on the shared scheduler.
func RunOSINTAsync(ctx context.Context, opts RunOptions) (err error) {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/osint: RunOptions.Scheduler must not be nil")
	}

	// F1: a dry run resolves the plan and stops, BEFORE the boot creates the
	// workspace tree and opens checkpoints.db. AfterBoot still fires so the CLI
	// keeps its dry-run task capture.
	if opts.DryRun {
		boot, err := ResolveDryRunBoot(opts)
		if err != nil {
			return fmt.Errorf("mcp/osint: %w", err)
		}
		if opts.AfterBoot != nil {
			opts.AfterBoot(boot)
		}
		return nil
	}

	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/osint: %w", err)
	}
	app := boot.App
	workdir := boot.WorkDir
	cfg := boot.Cfg
	sched := opts.Scheduler

	// Checkpoint + F4 workspace-lock lifecycle: one deferred boot.Close() covers
	// every exit path, including the error returns below.
	defer func() { _ = boot.Close() }()

	if opts.AfterBoot != nil {
		opts.AfterBoot(boot)
	}

	// INTEG-02: real scan — fire scan-start + arm on-failure (mode "osint" matches
	// persistScanToStore). Best-effort; suppressed in monitor mode.
	defer func() {
		if err != nil {
			notifyScanFailure(ctx, boot, opts, "osint", err)
		}
	}()
	notifyScanStart(ctx, boot, opts, "osint")

	sched.Checkpoint = app.Checkpoint

	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("mcp/osint: task DAG: %w", err)
	}

	for _, stage := range osintHandlerStages() {
		stageSlice := task.FilterByModuleAndEnabled(allTasks, "osint", cfg, stage.prefixes)

		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: false}
		}

		if runErr := sched.RunStage(ctx, "osint", stageSlice); runErr != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/osint: stage failed (best_effort — continuing)",
					"stage", stage.name, "err", runErr)
			}
		}

		count := countJSONLLines(filepath.Join(workdir, "artefacts", "findings.jsonl"))
		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: true, Count: count}
		}
	}

	// Final merge: consolidate all findings staging files.
	if mergeErr := osint.MergeAllOSINTArtefacts(ctx, app); mergeErr != nil {
		if app.Log != nil {
			app.Log.Warn("mcp/osint: final merge failed (best_effort — continuing)", "err", mergeErr)
		}
	}

	persistScanToStore(ctx, boot, opts, "osint")
	return nil
}
