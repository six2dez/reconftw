// Package handlers — subdomain enumeration handler.
package handlers

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// RunSubsAsync executes the full subdomain enumeration pipeline.
//
// Pipeline: opts.DryRun gate → BootReconApp → sched.Checkpoint wiring → task DAG
// build → 5 sequential RunStage calls (passive → resolve → discovery → permut →
// enrichment) → MergeAllSubdomains.
//
// The opts.DryRun gate comes FIRST and must stay first (F1): the boot creates the
// workspace tree and opens checkpoints.db, so checking dry-run after it made
// `--dry-run` write to disk.
//
// B3 fix: app.Checkpoint is closed via defer in this function (not via the
// shared scheduler's Checkpoint field). opts.Scheduler.Checkpoint is NOT
// written here, preserving the D-03 race-free shared-scheduler invariant.
//
// When opts.ProgressSink is non-nil, a StageEvent is sent before and after
// each RunStage call. This is used by the MCP layer for server.ResourceUpdated
// notifications. The CLI passes nil and relies on sched.RunTask for per-task UI.
func RunSubsAsync(ctx context.Context, opts RunOptions) (err error) {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/subs: RunOptions.Scheduler must not be nil")
	}

	// F1: a dry run resolves the plan and stops. This MUST precede BootReconApp,
	// whose tail MkdirAll's the workspace and opens checkpoints.db. AfterBoot
	// still fires — it is what captures the task list the operator asked to see.
	if opts.DryRun {
		boot, err := ResolveDryRunBoot(opts)
		if err != nil {
			return fmt.Errorf("mcp/subs: %w", err)
		}
		if opts.AfterBoot != nil {
			opts.AfterBoot(boot)
		}
		return nil
	}

	// Step 1-5a: Boot the app context.
	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/subs: %w", err)
	}
	app := boot.App
	workdir := boot.WorkDir
	cfg := boot.Cfg
	sched := opts.Scheduler

	// Checkpoint AND workspace-lock lifecycle owned here (B3 fix — not via the
	// shared scheduler). boot.Close() closes the checkpoint and releases the F4
	// workspace lock; deferring it immediately after the boot covers EVERY exit
	// path, including the error returns below and a panic. Do not split this
	// back into two defers — a lock leaked on an error path is indistinguishable
	// from a live run and would block the target until the operator intervenes.
	defer func() { _ = boot.Close() }()

	// Optional AfterBoot hook: called before stage loop so the CLI can inject
	// per-task UI into sched.RunTask after app is available. The dry-run capture
	// is handled by the gate above, which returns before this point.
	if opts.AfterBoot != nil {
		opts.AfterBoot(boot)
	}

	// INTEG-02: this is a real (non-dry-run) scan — fire scan-start and arm the
	// on-failure notifier. Mode label "subs" matches persistScanToStore so
	// scan-start / scan-complete pair up. Both are best-effort and stay silent in
	// monitor mode (opts.SuppressScanNotify).
	defer func() {
		if err != nil {
			notifyScanFailure(ctx, boot, opts, "subs", err)
		}
	}()
	notifyScanStart(ctx, boot, opts, "subs")

	// Step 5b: Wire sched.Checkpoint to enable per-tool resume (D-07).
	// Safe because each RunSubsAsync call has its own app and its own goroutine;
	// concurrent MCP sessions each get their OWN scheduler via opts.Scheduler
	// (per-scan scheduler created in the MCP tool handler). CLI mode passes a
	// per-invocation scheduler so there is no shared-state race.
	sched.Checkpoint = app.Checkpoint

	// Step 6: Build the task DAG.
	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("mcp/subs: task DAG: %w", err)
	}

	// stageSpec describes one sequential subdomain execution stage.
	type stageSpec struct {
		name     string
		module   string   // scheduler module → determines FailurePolicy via policyFor
		merge    string   // staging-file prefix for MergeStage glob ("" = skip merge)
		prefixes []string // task name prefixes for FilterByModuleAndEnabled
	}

	stages := []stageSpec{
		{
			name:   "passive",
			module: "subdomains.passive", // best_effort — independent sources
			merge:  "passive",
			prefixes: []string{
				"subdomains.passive.",
			},
		},
		{
			name:   "resolve",
			module: "subdomains", // fail_fast — TRUE SPINE
			merge:  "resolved",   // Tasks write inputs/resolved.*.txt
			prefixes: []string{
				"subdomains.active",
				"subdomains.tls",
				"subdomains.noerror",
				"subdomains.dns",
				"subdomains.srv",
				"subdomains.brute",
				"subdomains.resolvers.",
			},
		},
		{
			name:   "discovery",
			module: "subdomains.aux", // best_effort — aux independent discovery
			merge:  "resolved",       // scraping/analytics/ns_delegation/csprecon write resolved.*.txt
			prefixes: []string{
				"subdomains.scraping",
				"subdomains.csprecon",
				"subdomains.analytics",
				"subdomains.ns_delegation",
			},
		},
		{
			name:   "permut",
			module: "subdomains.aux", // best_effort — permutations augment, never gate
			merge:  "permut",
			prefixes: []string{
				"subdomains.permut",
				"subdomains.recursive.",
			},
		},
		{
			name:   "enrichment",
			module: "subdomains.aux", // best_effort — post-processing; own artefacts
			merge:  "",               // takeover/buckets/asn/geo write their own *.jsonl
			prefixes: []string{
				"subdomains.takeover.",
				"subdomains.buckets",
				"subdomains.asn",
				"subdomains.geo",
				"subdomains.zonetransfer",
			},
		},
	}

	// Stage loop: sequential execution with per-stage ProgressSink notification.
	for _, stage := range stages {
		stageSlice := task.FilterByModuleAndEnabled(allTasks, "subdomains", cfg, stage.prefixes)

		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: false}
		}

		if runErr := sched.RunStage(ctx, stage.module, stageSlice); runErr != nil {
			return fmt.Errorf("mcp/subs: stage %s: %w", stage.name, runErr)
		}

		// After the enrichment stage, consolidate the takeover staging files into
		// inputs/findings.takeover.jsonl, then build the artefact from staging.
		// A standalone `subs` run executes no web/osint/vulns findings merge, so
		// without this call the takeover findings would stay in staging and never
		// reach artefacts/findings.jsonl.
		if stage.name == "enrichment" {
			if mergeErr := mergeTakeoverFindings(ctx, app); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/subs: takeover_merge_failed", "err", mergeErr)
				}
			}
			if mergeErr := mergeFindingsArtefact(ctx, app); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/subs: findings_merge_failed", "err", mergeErr)
				}
			}
		}

		// MergeStage: consolidate stage outputs into subdomains.jsonl + <merge>.merged.txt.
		if stage.merge != "" {
			if mergeErr := subdomains.MergeStage(ctx, app, stage.merge); mergeErr != nil {
				if app.Log != nil {
					app.Log.Warn("mcp/subs: merge_stage_failed",
						"stage", stage.name, "merge", stage.merge, "err", mergeErr)
				}
			}
		}

		count := countJSONLLines(filepath.Join(workdir, "artefacts", "subdomains.jsonl"))
		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: stage.name, Done: true, Count: count}
		}
	}

	// Final consolidation: UNION of every stage's staging files.
	if mergeErr := subdomains.MergeAllSubdomains(ctx, app); mergeErr != nil {
		if app.Log != nil {
			app.Log.Warn("mcp/subs: final_union_merge_failed", "err", mergeErr)
		}
	}

	// CUT-08: a standalone subs scan also finalizes a workspace, so produce the
	// v1 bash-shape _compat/ tree from the final subdomains.jsonl (+ any takeover/
	// enrichment artefacts). Missing hosts/urls/findings sources are skipped, not
	// fatal — best-effort, never fails the scan.
	writeCompatTree(app, workdir)

	persistScanToStore(ctx, boot, opts, "subs")
	return nil
}
