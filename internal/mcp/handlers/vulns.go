// Package handlers — vulnerability scanning handler.
package handlers

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/vulns"
)

// RunVulnsAsync executes the full vulnerability scanning pipeline.
//
// When opts.ExtraFile is non-empty, it is injected as a --urls seed file via
// vulns.CtxWithURLsFile (T-08-03-01: never passed directly to shell commands).
//
// All stages are best_effort (D-V7). B3 fix: app.Checkpoint closed via defer;
// opts.Scheduler.Checkpoint NOT written on the shared scheduler.
func RunVulnsAsync(ctx context.Context, opts RunOptions) error {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/vulns: RunOptions.Scheduler must not be nil")
	}

	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/vulns: %w", err)
	}
	app := boot.App
	workdir := boot.WorkDir
	cfg := boot.Cfg
	sched := opts.Scheduler

	defer func() {
		if closer, ok := app.Checkpoint.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	if opts.AfterBoot != nil {
		opts.AfterBoot(boot)
	}

	if opts.DryRun {
		return nil
	}

	sched.Checkpoint = app.Checkpoint

	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("mcp/vulns: task DAG: %w", err)
	}

	// Inject --urls flag into context for GFTask.Run (D-V5).
	if opts.ExtraFile != "" {
		ctx = vulns.CtxWithURLsFile(ctx, opts.ExtraFile)
	}

	type stageSpec struct {
		name     string
		prefixes []string
	}
	stages := []stageSpec{
		{name: "gf-classify", prefixes: []string{"vulns.gf"}},
		{
			name: "injection",
			prefixes: []string{
				"vulns.xss", "vulns.sqli", "vulns.lfi",
				"vulns.ssti", "vulns.crlf", "vulns.cmdi",
			},
		},
		{
			name: "oob-advanced",
			prefixes: []string{
				"vulns.ssrf", "vulns.smuggling",
				"vulns.webcache_wcvs", "vulns.webcache_toxicache", "vulns.second_order",
			},
		},
		{
			name: "dast-extended",
			prefixes: []string{
				"vulns.nuclei_dast", "vulns.fuzzparams", "vulns.bypass4xx",
				"vulns.testssl", "vulns.fray", "vulns.graphql",
				"vulns.grpc", "vulns.llm", "vulns.websocket",
			},
		},
	}

	for _, stage := range stages {
		stageSlice := task.FilterByModuleAndEnabled(allTasks, "vulns", cfg, stage.prefixes)

		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: false}
		}

		if runErr := sched.RunStage(ctx, "vulns", stageSlice); runErr != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/vulns: stage failed (best_effort — continuing)",
					"stage", stage.name, "err", runErr)
			}
		}

		count := countJSONLLines(filepath.Join(workdir, "artefacts", "findings.jsonl"))
		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: true, Count: count}
		}
	}

	// Final merge: consolidate all findings staging files.
	if mergeErr := vulns.MergeAllVulnsArtefacts(ctx, app); mergeErr != nil {
		if app.Log != nil {
			app.Log.Warn("mcp/vulns: final merge failed (best_effort — continuing)", "err", mergeErr)
		}
	}

	return nil
}
