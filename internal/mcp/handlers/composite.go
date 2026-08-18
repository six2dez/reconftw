// Package handlers — composite pipeline handler (D-01 boot-once model).
//
// RunCompositeAsync boots ONCE (single AppContext, single scheduler, single
// workspace, single checkpoint timeline) and runs the stage groups for the
// requested CompositeMode sequentially. This satisfies D-01: no per-pipeline
// re-boot, no per-pipeline axiom launch/shutdown, no per-pipeline checkpoint.
//
// Axiom lifecycle (T-09-02-03 mitigation): RunCompositeAsync is the SOLE owner
// of axiomBE.Launch and defer axiomBE.Shutdown for composite modes. The per-
// pipeline single handlers (RunSubsAsync/RunWebAsync/RunVulnsAsync/RunOSINTAsync)
// are UNCHANGED — they still own their own Launch+Shutdown for non-composite use.
//
// Checkpoint lifecycle (T-09-02-04 mitigation): RunCompositeAsync owns the
// single defer app.Checkpoint.Close(). Stage loops do NOT close the checkpoint.
package handlers

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/osint"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
	"github.com/six2dez/reconftw/internal/modules/vulns"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// CompositeMode defines which pipelines RunCompositeAsync executes.
type CompositeMode int

const (
	// ModeRecon: passive subs + resolve + discovery → web → osint (SKIPS vulns).
	// D-01 recon definition: does NOT include active brute/permut (those are ModeAll).
	ModeRecon CompositeMode = iota

	// ModeAll: subs (all stages) → web → osint → vulns.
	ModeAll

	// ModePassive: subs passive stage ONLY; no active probing (D-09).
	ModePassive

	// ModeZen: same pipeline as ModeRecon; caller sets ConfigTransform=ApplyZenProfile
	// before calling RunCompositeAsync (stealth/minimal-noise profile, D-02/D-03).
	ModeZen

	// ModeDeep: same pipeline as ModeAll; caller sets ConfigTransform=ApplyDeepProfile
	// before calling RunCompositeAsync (extended brute + fuzz, D-02/D-03).
	ModeDeep
)

// compositeStageGroup describes one sequential pipeline stage group for the
// composite handler. Each group maps to a module/policy and a set of task
// name prefixes to filter against task.Default.Build().
type compositeStageGroup struct {
	name     string   // human label for logs/progress
	module   string   // scheduler module string → failure policy via policyFor
	prefixes []string // task name prefixes for task.FilterByModuleAndEnabled
}

// subsPassiveStages returns stage groups for the passive-only subs pipeline.
// Used by ModePassive (primary composition guard) and as the first group of
// ModeRecon/ModeZen (passive subs before active resolution).
func subsPassiveStages() []compositeStageGroup {
	return []compositeStageGroup{
		{
			name:     "subs-passive",
			module:   "subdomains.passive",
			prefixes: []string{"subdomains.passive."},
		},
	}
}

// subsReconStages returns stage groups for the subs pipeline as used by
// ModeRecon/ModeZen: passive → resolve → discovery (NO brute/permut/enrichment).
// Active brute and permut are reserved for ModeAll/ModeDeep.
func subsReconStages() []compositeStageGroup {
	return []compositeStageGroup{
		{
			name:     "subs-passive",
			module:   "subdomains.passive",
			prefixes: []string{"subdomains.passive."},
		},
		{
			name:   "subs-resolve",
			module: "subdomains",
			prefixes: []string{
				"subdomains.active",
				"subdomains.tls",
				"subdomains.noerror",
				"subdomains.dns",
				"subdomains.srv",
				"subdomains.resolvers.",
			},
		},
		{
			name:   "subs-discovery",
			module: "subdomains.aux",
			prefixes: []string{
				"subdomains.scraping",
				"subdomains.csprecon",
				"subdomains.analytics",
				"subdomains.ns_delegation",
			},
		},
	}
}

// subsAllStages returns all subs stage groups (ModeAll/ModeDeep): passive →
// resolve → discovery → permut → enrichment.
func subsAllStages() []compositeStageGroup {
	return []compositeStageGroup{
		{
			name:     "subs-passive",
			module:   "subdomains.passive",
			prefixes: []string{"subdomains.passive."},
		},
		{
			name:   "subs-resolve",
			module: "subdomains",
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
			name:   "subs-discovery",
			module: "subdomains.aux",
			prefixes: []string{
				"subdomains.scraping",
				"subdomains.csprecon",
				"subdomains.analytics",
				"subdomains.ns_delegation",
			},
		},
		{
			name:   "subs-permut",
			module: "subdomains.aux",
			prefixes: []string{
				"subdomains.permut",
				"subdomains.recursive.",
			},
		},
		{
			name:   "subs-enrichment",
			module: "subdomains.aux",
			prefixes: []string{
				"subdomains.takeover.",
				"subdomains.buckets",
				"subdomains.asn",
				"subdomains.geo",
				"subdomains.zonetransfer",
			},
		},
	}
}

// webStageGroups returns stage groups for the web pipeline (all stages, best_effort).
func webStageGroups() []compositeStageGroup {
	return []compositeStageGroup{
		{name: "web-probe", module: "web", prefixes: []string{"web.httpx"}},
		// web-portscan mirrors RunWebAsync's "portscan" stage: runs after probe so its
		// discovered services + host:port records feed downstream analysis/url stages.
		// A "hosts" merge follows in compositeStagePostMerge (13-08 checker LOW #3).
		{name: "web-portscan", module: "web", prefixes: []string{"web.portscan"}},
		{name: "web-analysis-waf", module: "web", prefixes: []string{"web.wafw00f", "web.cdncheck"}},
		{
			name:   "web-analysis",
			module: "web",
			prefixes: []string{
				"web.nuclei", "web.screenshot", "web.ffuf", "web.favirecon",
				"web.vhostfinder", "web.hakoriginfinder", "web.csprecon",
			},
		},
		{name: "web-urls-fetch", module: "web", prefixes: []string{"web.katana", "web.urlfinder", "web.waymore"}},
		{name: "web-js-extract", module: "web", prefixes: []string{"web.subjs", "web.sourcemapper"}},
		{name: "web-js-analyze", module: "web", prefixes: []string{"web.jsluice", "web.jsa", "web.mantra"}},
		{name: "web-urls-dedup", module: "web", prefixes: []string{"web.urldedup"}},
		{name: "web-bypass", module: "web", prefixes: []string{"web.nomore403", "web.shortscan", "web.gxss", "web.arjun"}},
		// web-producers runs last (url_ext needs the deduped corpus; wellknown +
		// wordlistgen need the web/JS surface). wellknown's HostRecord staging is
		// folded into artefacts/hosts.jsonl by the "hosts" merge in postMerge.
		{name: "web-producers", module: "web", prefixes: []string{"web.url_ext", "web.wellknown", "web.wordlistgen"}},
	}
}

// osintStageGroups returns stage groups for the OSINT pipeline (best_effort).
// Wraps osintHandlerStages() into compositeStageGroup for uniform handling.
func osintStageGroupsComposite() []compositeStageGroup {
	groups := make([]compositeStageGroup, 0, 2)
	for _, s := range osintHandlerStages() {
		groups = append(groups, compositeStageGroup{
			name:     "osint-" + s.name,
			module:   "osint",
			prefixes: s.prefixes,
		})
	}
	return groups
}

// vulnsStageGroupsComposite returns stage groups for the vulns pipeline (best_effort).
func vulnsStageGroupsComposite() []compositeStageGroup {
	return []compositeStageGroup{
		{name: "vulns-gf-classify", module: "vulns", prefixes: []string{"vulns.gf"}},
		{
			name:   "vulns-injection",
			module: "vulns",
			prefixes: []string{
				"vulns.xss", "vulns.sqli", "vulns.lfi",
				"vulns.ssti", "vulns.crlf", "vulns.cmdi",
			},
		},
		{
			name:   "vulns-oob-advanced",
			module: "vulns",
			prefixes: []string{
				"vulns.ssrf", "vulns.smuggling",
				"vulns.webcache_wcvs", "vulns.webcache_toxicache", "vulns.second_order",
			},
		},
		{
			name:   "vulns-dast-extended",
			module: "vulns",
			prefixes: []string{
				"vulns.nuclei_dast", "vulns.fuzzparams", "vulns.bypass4xx",
				"vulns.testssl", "vulns.fray", "vulns.graphql",
				"vulns.grpc", "vulns.llm", "vulns.websocket",
			},
		},
		// spray runs last (reads hosts/portscan_active.gnmap from the web portscan
		// stage). vulns groups run only in ModeAll/ModeDeep, so spray is all/deep-only
		// automatically; SprayTask's DeepOnly + gnmap + IP-target gates do the rest.
		{name: "vulns-spray", module: "vulns", prefixes: []string{"vulns.spray"}},
	}
}

// compositePipelineStages returns the ordered stage groups for a CompositeMode.
// ModeZen uses the same groups as ModeRecon (zen profile applied via ConfigTransform).
// ModeDeep uses the same groups as ModeAll (deep profile applied via ConfigTransform).
func compositePipelineStages(mode CompositeMode) []compositeStageGroup {
	switch mode {
	case ModeRecon, ModeZen:
		groups := make([]compositeStageGroup, 0)
		groups = append(groups, subsReconStages()...)
		groups = append(groups, webStageGroups()...)
		groups = append(groups, osintStageGroupsComposite()...)
		return groups
	case ModeAll, ModeDeep:
		groups := make([]compositeStageGroup, 0)
		groups = append(groups, subsAllStages()...)
		groups = append(groups, webStageGroups()...)
		groups = append(groups, osintStageGroupsComposite()...)
		groups = append(groups, vulnsStageGroupsComposite()...)
		return groups
	case ModePassive:
		return subsPassiveStages()
	default:
		return subsPassiveStages()
	}
}

// CompositePipelinePrefixes returns the set of task name prefixes for a mode.
// Exported so tests can assert mode-level prefix coverage (TestAllPipelineIncludesVulns).
func CompositePipelinePrefixes(mode CompositeMode) []string {
	stages := compositePipelineStages(mode)
	var all []string
	for _, s := range stages {
		all = append(all, s.prefixes...)
	}
	return all
}

// RunCompositeAsync executes the composite pipeline for the given mode.
//
// The opts.DryRun gate is the FIRST thing the function does (F1) — before the
// boot, before any axiom Launch. A dry run must create no workspace, open no
// checkpoint store and start no fleet.
//
// D-01 invariants:
//   - Single BootReconApp call (one AppContext, one workspace, one checkpoint).
//   - Single axiomBE.Launch and single defer axiomBE.Shutdown for the whole run.
//   - Single defer app.Checkpoint.Close().
//   - Stage groups run sequentially; within each group tasks run concurrently
//     under the scheduler semaphore.
//
// Axiom lifecycle ownership (T-09-02-03): ONLY this function calls
// axiomBE.Launch() and defers axiomBE.Shutdown() for composite modes.
// commonAfterBoot (called via opts.AfterBoot) does NOT call Launch/Shutdown.
func RunCompositeAsync(ctx context.Context, opts RunOptions, mode CompositeMode) (err error) {
	if opts.Scheduler == nil {
		return fmt.Errorf("mcp/composite: RunOptions.Scheduler must not be nil")
	}

	// F1: a dry run resolves the plan and stops. This precedes the boot (which
	// MkdirAll's the workspace and opens checkpoints.db) AND every axiom
	// Launch() below — a preview must not spin up a fleet. AfterBoot still
	// fires: it is what feeds dryRunCapture and printCompositeDryRun.
	if opts.DryRun {
		boot, err := ResolveDryRunBoot(opts)
		if err != nil {
			return fmt.Errorf("mcp/composite: %w", err)
		}
		if opts.AfterBoot != nil {
			opts.AfterBoot(boot)
		}
		return nil
	}

	// Single Boot (D-01).
	boot, err := BootReconApp(ctx, opts)
	if err != nil {
		return fmt.Errorf("mcp/composite: %w", err)
	}
	app := boot.App
	workdir := boot.WorkDir
	cfg := boot.Cfg
	sched := opts.Scheduler

	// Single checkpoint lifecycle (T-09-02-04: Pitfall 2).
	defer func() {
		if closer, ok := app.Checkpoint.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	// AfterBoot: wires scheduler limits, log routing, progress UI.
	// commonAfterBoot (called by the CLI AfterBoot closure) does NOT call
	// axiomBE.Launch/Shutdown — those are handled below (T-09-02-03).
	if opts.AfterBoot != nil {
		opts.AfterBoot(boot)
	}

	// INTEG-02: real scan — fire scan-start + arm on-failure. The mode label is
	// compositeModeLabel(mode) so it matches persistScanToStore below (scan-start /
	// scan-complete pair up as "recon"/"all"/"passive"/"zen"/"deep"). Both are
	// best-effort and stay silent under the monitor loop (opts.SuppressScanNotify).
	label := compositeModeLabel(mode)
	defer func() {
		if err != nil {
			notifyScanFailure(ctx, boot, opts, label, err)
		}
	}()
	notifyScanStart(ctx, boot, opts, label)

	// Wire checkpoint to scheduler (B3 fix).
	sched.Checkpoint = app.Checkpoint

	// Build the full task DAG.
	allTasks, err := task.Default.Build()
	if err != nil {
		return fmt.Errorf("mcp/composite: task DAG: %w", err)
	}

	// Axiom lifecycle: SOLE owner for composite modes (T-09-02-03).
	// Single Launch before all stage groups; single Shutdown after all groups.
	// grep-proof: this is the ONE axiomBE.Launch call in this file.
	var axiomBE *backend.AxiomBackend
	if fb, ok := boot.ChosenBackend.(*backend.FailoverBackend); ok {
		if abe, ok := fb.Primary.(*backend.AxiomBackend); ok {
			axiomBE = abe
		}
	}
	if axiomBE != nil {
		if launchErr := axiomBE.Launch(ctx); launchErr != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: axiom launch failed — continuing locally", "err", launchErr)
			}
		} else {
			// grep-proof: this is the ONE defer axiomBE.Shutdown call in this file.
			defer func() { _ = axiomBE.Shutdown(context.Background()) }() //nolint:staticcheck
		}
	}

	// Stage loop: run each pipeline group sequentially.
	stageGroups := compositePipelineStages(mode)
	for _, group := range stageGroups {
		// Select by the task's REAL Module() via filterModuleFor — NOT group.module.
		// group.module is the failure-policy label (used by RunStage +
		// isBestEffortModule below); filtering by it selected zero passive/aux/
		// permut/enrichment tasks (the composite recon/all "0 subdomains" bug).
		stageSlice := task.FilterByModuleAndEnabled(allTasks, filterModuleFor(group.module), cfg, group.prefixes)

		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: group.name, Done: false}
		}

		if runErr := sched.RunStage(ctx, group.module, stageSlice); runErr != nil {
			// Apply best_effort for web/osint/vulns stages; subs resolve is fail_fast.
			if isBestEffortModule(group.module) {
				if app.Log != nil {
					app.Log.Warn("mcp/composite: stage failed (best_effort — continuing)",
						"stage", group.name, "err", runErr)
				}
			} else {
				return fmt.Errorf("mcp/composite: stage %s: %w", group.name, runErr)
			}
		}

		// Per-stage merges mirror the single-pipeline handlers.
		compositeStagePostMerge(ctx, app, group)

		count := countJSONLLines(filepath.Join(workdir, "artefacts", "findings.jsonl"))
		if opts.ProgressSink != nil {
			opts.ProgressSink <- StageEvent{Stage: group.name, Done: true, Count: count}
		}
	}

	// Final merges: consolidate all pipeline artefacts sequentially (single-writer).
	compositeFinalMerge(ctx, app, mode)

	// CUT-08: end-of-scan finalization — materialize the v1 bash-shape
	// Recon/<domain>/ (_compat/) tree from the now-final artefacts. Best-effort:
	// compat writing must never fail the scan (WriteCompat returns nil by contract).
	writeCompatTree(app, workdir)

	persistScanToStore(ctx, boot, opts, compositeModeLabel(mode))
	return nil
}

// compositeModeLabel maps a CompositeMode to the scan.mode string recorded in
// store.db (mirrors the subcommand names users invoke).
func compositeModeLabel(mode CompositeMode) string {
	switch mode {
	case ModeAll:
		return "all"
	case ModePassive:
		return "passive"
	case ModeZen:
		return "zen"
	case ModeDeep:
		return "deep"
	default:
		return "recon"
	}
}

// isBestEffortModule returns true for modules with best_effort failure policy.
// The subs "resolve" spine stage (module="subdomains") is fail_fast; everything
// else in composites is best_effort.
func isBestEffortModule(module string) bool {
	return module != "subdomains"
}

// filterModuleFor derives the task-SELECTION module (a task's real Module(),
// which is the top-level segment) from a stage group's failure-POLICY label.
// "subdomains.passive" / "subdomains.aux" → "subdomains"; "web"/"osint"/"vulns"
// are returned unchanged. This split is required because every subdomains task
// reports Module()=="subdomains" regardless of its stage, while the composite
// stage groups carry finer policy labels ("subdomains.passive", "subdomains.aux")
// so isBestEffortModule can treat passive/aux as best_effort and the resolve
// spine as fail_fast. Filtering task selection by the policy label matched zero
// passive/aux/permut/enrichment tasks — the composite recon/all "0 subdomains"
// regression. See TestCompositeStageSelectionCoversPassive.
func filterModuleFor(groupModule string) string {
	if dot := strings.IndexByte(groupModule, '.'); dot >= 0 {
		return groupModule[:dot]
	}
	return groupModule
}

// compositeStagePostMerge runs per-stage merge calls after a stage completes.
// Mirrors the per-stage merge logic in the single-pipeline handlers.
func compositeStagePostMerge(ctx context.Context, app *appctx.AppContext, group compositeStageGroup) {
	switch group.name {
	// Subs stages mirror subs.go's per-stage MergeStage sequence: passive→"passive",
	// resolve/discovery→"resolved", permut→"permut", enrichment→takeover only. The
	// passive merge MUST run right after the passive stage so resolve/web receive the
	// passive.merged input; misplacing it under subs-enrichment left recon (which has
	// no enrichment stage) with 0 resolved hosts despite finding subdomains.
	case "subs-passive":
		if err := subdomains.MergeStage(ctx, app, "passive"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: subs merge_stage_failed", "merge", "passive", "err", err)
			}
		}
	case "subs-enrichment":
		if err := mergeTakeoverFindings(ctx, app); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: takeover_merge_failed", "err", err)
			}
		}
		// Build the artefact now so a passive run — which returns before the web
		// findings sweep — still publishes takeover findings. In the other modes
		// this is redundant but harmless: every findings merge rebuilds the same
		// union from inputs/findings.*.jsonl.
		if err := mergeFindingsArtefact(ctx, app); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: findings_merge_failed", "err", err)
			}
		}
	case "subs-resolve":
		if err := subdomains.MergeStage(ctx, app, "resolved"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: subs merge_stage_failed", "merge", "resolved", "err", err)
			}
		}
	case "subs-discovery":
		if err := subdomains.MergeStage(ctx, app, "resolved"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: subs merge_stage_failed", "merge", "resolved", "err", err)
			}
		}
	case "subs-permut":
		if err := subdomains.MergeStage(ctx, app, "permut"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: subs merge_stage_failed", "merge", "permut", "err", err)
			}
		}
	// Web stages: mirrors RunWebAsync per-stage merges.
	case "web-portscan", "web-producers":
		// Fold portscan/nerva (web-portscan) and wellknown (web-producers) HostRecord
		// staging into artefacts/hosts.jsonl so the host/port records reach the store
		// (13-08 checker LOW #3). Union-preserving (merge.go) → httpx hosts survive.
		if err := web.MergeStage(ctx, app, "hosts"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web MergeStage failed", "stage", "hosts", "err", err)
			}
		}
	case "web-analysis-waf":
		if err := web.MergeStage(ctx, app, "waf"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web MergeStage failed", "stage", "waf", "err", err)
			}
		}
	case "web-analysis":
		if err := web.MergeStage(ctx, app, "findings"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web MergeStage failed", "stage", "findings", "err", err)
			}
		}
	case "web-urls-fetch":
		if err := web.MergeStage(ctx, app, "urls"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web MergeStage failed", "stage", "urls", "err", err)
			}
		}
	case "web-bypass":
		if err := web.MergeStage(ctx, app, "findings"); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web MergeStage failed", "stage", "findings-bypass", "err", err)
			}
		}
	}
}

// compositeFinalMerge runs the end-of-pipeline final merges sequentially.
// Each pipeline's MergeAll function is called once in pipeline order.
func compositeFinalMerge(ctx context.Context, app *appctx.AppContext, mode CompositeMode) {
	// Subs final merge (all modes that ran subs).
	if err := subdomains.MergeAllSubdomains(ctx, app); err != nil {
		if app.Log != nil {
			app.Log.Warn("mcp/composite: subs final merge failed", "err", err)
		}
	}

	if mode == ModePassive {
		return // passive runs subs only
	}

	// Web final sweep merge.
	for _, prefix := range []string{"waf", "findings"} {
		if err := web.MergeStage(ctx, app, prefix); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: web final sweep failed", "stage", prefix, "err", err)
			}
		}
	}

	// OSINT final merge.
	if err := osint.MergeAllOSINTArtefacts(ctx, app); err != nil {
		if app.Log != nil {
			app.Log.Warn("mcp/composite: osint final merge failed", "err", err)
		}
	}

	// Vulns final merge only for ModeAll/ModeDeep.
	if mode == ModeAll || mode == ModeDeep {
		if err := vulns.MergeAllVulnsArtefacts(ctx, app); err != nil {
			if app.Log != nil {
				app.Log.Warn("mcp/composite: vulns final merge failed", "err", err)
			}
		}
	}
}
