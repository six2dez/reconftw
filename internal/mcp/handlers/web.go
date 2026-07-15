// Package handlers — web analysis handler.
package handlers

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// RunWebAsync executes the full web analysis pipeline.
//
// When opts.ExtraFile is non-empty, it is injected as a --hosts seed file via
// web.CtxWithHostsFile (T-08-03-01: never passed directly to shell commands).
//
// All stages are best_effort (D-W12) — pipeline completes even if individual
// tools fail. B3 fix: app.Checkpoint is closed via defer; opts.Scheduler.Checkpoint
// is NOT written on the shared scheduler.
func RunWebAsync(ctx context.Context, opts RunOptions) (err error) {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/web: RunOptions.Scheduler must not be nil")
	}

	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/web: %w", err)
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

	// INTEG-02: real scan — fire scan-start + arm on-failure (mode "web" matches
	// persistScanToStore). Best-effort; suppressed in monitor mode.
	defer func() {
		if err != nil {
			notifyScanFailure(ctx, boot, opts, "web", err)
		}
	}()
	notifyScanStart(ctx, boot, opts, "web")

	sched.Checkpoint = app.Checkpoint

	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("mcp/web: task DAG: %w", err)
	}

	// Inject --hosts flag into context for HTTPXTask.Run (D-W10).
	if opts.ExtraFile != "" {
		ctx = web.CtxWithHostsFile(ctx, opts.ExtraFile)
	}

	type stageSpec struct {
		name     string
		prefixes []string
	}
	stages := []stageSpec{
		{name: "probe", prefixes: []string{"web.httpx"}},
		// portscan runs right after probe so its nmapurls-discovered web services
		// (hosts/webs.txt) and open host:port records feed the downstream analysis /
		// url stages. It reads the subs artefact subdomains/subdomains_ips.txt, so no
		// DAG edge is needed. A "hosts" merge follows (below) to fold the
		// portscan/nerva HostRecord staging into artefacts/hosts.jsonl (13-08).
		{name: "portscan", prefixes: []string{"web.portscan"}},
		{name: "analysis-waf", prefixes: []string{"web.wafw00f", "web.cdncheck"}},
		{
			name: "analysis",
			prefixes: []string{
				"web.nuclei", "web.screenshot", "web.ffuf", "web.favirecon",
				"web.vhostfinder", "web.hakoriginfinder", "web.csprecon",
			},
		},
		{name: "urls-fetch", prefixes: []string{"web.katana", "web.urlfinder", "web.waymore"}},
		{name: "js-extract", prefixes: []string{"web.subjs", "web.sourcemapper"}},
		{name: "js-analyze", prefixes: []string{"web.jsluice", "web.jsa", "web.mantra"}},
		{name: "urls-dedup", prefixes: []string{"web.urldedup"}},
		{name: "bypass", prefixes: []string{"web.nomore403", "web.shortscan", "web.gxss", "web.arjun"}},
		// web-producers runs last: url_ext needs the deduped URL corpus, wellknown +
		// wordlistgen need the web target / JS surface. wellknown stages HostRecords
		// (inputs/hosts.wellknown.jsonl) folded into artefacts/hosts.jsonl by the
		// "hosts" merge that follows (13-08).
		{name: "web-producers", prefixes: []string{"web.url_ext", "web.wellknown", "web.wordlistgen"}},
	}

	for _, stage := range stages {
		stageSlice := task.FilterByModuleAndEnabled(allTasks, "web", cfg, stage.prefixes)

		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: false}
		}

		if runErr := sched.RunStage(ctx, "web", stageSlice); runErr != nil {
			// best_effort: log and continue.
			if app.Log != nil {
				app.Log.Warn("mcp/web: stage failed (best_effort — continuing)",
					"stage", stage.name, "err", runErr)
			}
		}

		// Per-stage MergeStage calls so consumers in the next stage read merged artefacts.
		switch stage.name {
		case "portscan", "web-producers":
			// Fold the portscan/nerva (portscan stage) and wellknown (web-producers
			// stage) HostRecord staging files into artefacts/hosts.jsonl so the
			// host/port records reach the store. The "hosts" merge is union-preserving
			// (merge.go) so httpx's directly-written probed hosts are NOT overwritten.
			if mergeErr := web.MergeStage(ctx, app, "hosts"); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/web: MergeStage failed", "stage", "hosts", "err", mergeErr)
				}
			}
		case "analysis-waf":
			if mergeErr := web.MergeStage(ctx, app, "waf"); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/web: MergeStage failed", "stage", "waf", "err", mergeErr)
				}
			}
		case "analysis":
			if mergeErr := web.MergeStage(ctx, app, "findings"); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/web: MergeStage failed", "stage", "findings", "err", mergeErr)
				}
			}
		case "urls-fetch":
			// intermediate merge: populate artefacts/urls.jsonl for js-extract input.
			if mergeErr := web.MergeStage(ctx, app, "urls"); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/web: MergeStage failed", "stage", "urls", "err", mergeErr)
				}
			}
		case "bypass":
			if mergeErr := web.MergeStage(ctx, app, "findings"); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/web: MergeStage failed", "stage", "findings-bypass", "err", mergeErr)
				}
			}
		}

		count := countJSONLLines(filepath.Join(workdir, "artefacts", "hosts.jsonl"))
		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: true, Count: count}
		}
	}

	// Final safety sweep: merge any remaining findings/waf staging files.
	// "urls" is intentionally excluded — urldedup is the sole semantic-dedup writer (WEB-14).
	for _, prefix := range []string{"waf", "findings"} {
		if mergeErr := web.MergeStage(ctx, app, prefix); mergeErr != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/web: final sweep MergeStage failed", "stage", prefix, "err", mergeErr)
			}
		}
	}

	persistScanToStore(ctx, boot, opts, "web")
	return nil
}
