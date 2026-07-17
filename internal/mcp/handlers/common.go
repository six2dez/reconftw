// Package handlers provides shared run-option types and the BootReconApp
// helper that is used by both the cobra CLI subcommands and the MCP tool
// handlers. Extracting the wiring here satisfies MCP-02: the CLI and MCP
// server invoke identical pipeline logic.
//
// Concurrency model (D-03 concurrent sessions): each scan session gets its
// OWN *scheduler.Scheduler (the MCP tool handler calls a per-scan factory; the
// CLI passes a per-invocation scheduler). Because every scan owns its scheduler,
// appctx.Boot wiring the per-scan RunTask / Checkpoint / Hash onto it is safe —
// concurrent sessions never share those mutable fields. The global
// PARALLEL_MAX_JOBS ceiling (MCP-05) is enforced separately by a shared
// scheduler.Limiter (a process-wide semaphore injected by the factory), NOT by
// sharing a Scheduler struct. Each RunXxxAsync closes app.Checkpoint via defer.
package handlers

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// StageEvent is sent on ProgressSink at stage boundaries. Done=false means
// the stage is about to start; Done=true means it has completed. Count is
// the running artefact count after the stage (meaningful only when Done=true).
type StageEvent struct {
	Stage string
	Done  bool
	Count int
}

// RunOptions carries all parameters for a RunXxxAsync call. Both the cobra
// CLI RunE bodies and the MCP tool handlers construct a RunOptions and call
// the corresponding RunXxxAsync function — a single code path satisfies MCP-02.
//
// Scheduler must not be nil; BootReconApp returns an error if it is. The
// Scheduler should be the shared process-level instance when called from
// the MCP server (D-03 / Pitfall 3 avoidance), or a per-invocation scheduler
// when called from the CLI.
//
// ProgressSink is optional (nil = stderr UI). When non-nil, RunXxxAsync sends
// StageEvent values at each stage boundary so the MCP layer can emit
// server.ResourceUpdated notifications.
//
// AfterBoot is an optional callback invoked after BootReconApp succeeds but
// before the stage loop starts. The CLI uses this to wire sched.RunTask with
// the per-task progress UI (badgeForStatus + StageProgress). MCP callers
// leave it nil.
//
// ConfigTransform is applied after config.Load inside BootReconApp and before
// appctx.Boot. Used by zen/deep subcommands to override rate limits and feature
// flags in memory (D-02/D-03). nil = no-op. Must be applied before Boot so
// appctx.Boot wires the correct concurrency limits (e.g., zen lowers MaxJobs
// to 2).
type RunOptions struct {
	// Target is the domain or IP being scanned.
	Target string
	// DryRun previews tasks without executing tools.
	DryRun bool
	// ExtraFile carries --hosts (web) or --urls (vulns); unused by subs/osint.
	ExtraFile string
	// ConfigPath is the explicit --config path (may be empty).
	ConfigPath string
	// SecretsPath is the explicit --secrets path (may be empty).
	SecretsPath string
	// AxiomEnabled enables the FailoverBackend wrapping axiom + local.
	AxiomEnabled bool
	// Scheduler is the bounded task dispatcher. Must not be nil.
	Scheduler *scheduler.Scheduler
	// ProgressSink receives stage completion events. nil = no MCP notifications.
	ProgressSink chan<- StageEvent
	// AfterBoot is called after BootReconApp succeeds, before the stage loop.
	// The CLI uses this to inject per-task UI into sched.RunTask. May be nil.
	AfterBoot func(boot AppBoot)
	// ConfigTransform is applied after config.Load inside BootReconApp and before
	// appctx.Boot. Used by zen/deep subcommands to override rate limits and feature
	// flags. nil = no-op. Must be applied before Boot so appctx.Boot wires the
	// correct concurrency limits (e.g., zen's MaxJobs=2).
	ConfigTransform func(*config.Config)
	// PassiveMode enables the backend-level hard-guard (D-09): wraps the chosen
	// backend with PassiveBackend so active tools return ErrPassiveViolation.
	// Set by the passive composite subcommand.
	PassiveMode bool
	// TargetListPath carries a path to a file of target FQDNs, one per line.
	// When set, the run operates in list mode — cfgSliceJSON includes this path,
	// so checkpoint.InputHash differs from a full-target run, triggering genuine
	// re-execution for the listed assets only. Used by the monitor incremental
	// re-feed path (D-04/D-05 fix — checkpoint hash alone does not change between
	// monitor cycles with identical opts).
	TargetListPath string
	// Force is the --force / checkpoint-bypass flag. When true, BootReconApp
	// ORs it into cfg.Advanced.Diff, which then drives Scheduler.ForceRerun so
	// completed tasks re-execute while still recording fresh checkpoints
	// (INTEG-03). Dry-run must NOT bypass — the dry-run early-return in each
	// RunXAsync is the real guard, so a stray --dry-run --force is harmless.
	Force bool
	// SuppressScanNotify silences the in-scan notification seam (notifyScanStart/
	// notifyScanComplete/notifyScanFailure) for this run. Set by the monitor loop
	// so its per-cycle RunCompositeAsync calls stay quiet — the monitor owns its
	// own cross-cycle diff notifications (INTEG-04); firing the in-scan seam every
	// cycle would re-alert every critical finding on every cycle. Ordinary CLI/MCP
	// scans leave it false (INTEG-02).
	SuppressScanNotify bool
}

// AppBoot is the return bundle from BootReconApp.
type AppBoot struct {
	App           *appctx.AppContext
	WorkDir       string
	Cfg           *config.Config
	ChosenBackend backend.Backend // nil when Axiom is not enabled
}

// persistScanToStore ingests the just-completed run's merged JSONL artefacts into
// the shared store.db so `report` / monitor / SARIF / AI / faraday can read a
// completed scan. It is best-effort: any failure is logged and never aborts the
// pipeline — the JSONL artefacts on disk remain the source of truth. Callers
// invoke it once, after the final merge, before returning nil.
func persistScanToStore(ctx context.Context, boot AppBoot, opts RunOptions, mode string) {
	var dataDir string
	if boot.Cfg != nil {
		dataDir = boot.Cfg.Paths.DataDir
	}
	var logger *slog.Logger
	if boot.App != nil {
		logger = boot.App.Log
	}
	res, err := ingest.ScanIntoStore(ctx, dataDir, boot.WorkDir, opts.Target, mode, logger)
	if err != nil && logger != nil {
		logger.WarnContext(ctx, "store ingest failed (non-fatal)", "mode", mode, "err", err)
	}
	// INTEG-02: fire scan-complete + critical-finding from the SAME finalization
	// seam, reusing the ingest.Result counts and the findings.jsonl the ingest
	// already read. Best-effort — a notifier failure never aborts the pipeline.
	// On an ingest error res is the zero Result; scan-complete still fires (counts
	// may read 0) and criticals are read straight from the artefact, so a store
	// hiccup never suppresses the critical-finding alerts.
	notifyScanComplete(ctx, boot, opts, mode, res)
}

// writeCompatTree materializes the v1 bash-shape Recon/<domain>/ (_compat/) tree
// from the finalized workspace artefacts (CUT-08). This is the SOLE production
// caller of output.CompatWriter.WriteCompat — without it a completed v2 scan
// leaves an empty compat tree and the 6-month bash→Go compat contract (ADR §4.5)
// is unmet.
//
// Placement (14-02-SUMMARY "OnEnd hook-point note"): call this at end-of-scan
// finalization AFTER the final merges have written the definitive
// artefacts/*.jsonl (subdomains/hosts/urls/findings). Reading a mid-pipeline
// state would miss web/osint/vulns records that land after subs enrichment.
//
// Error isolation (ADR §4.4): WriteCompat is best-effort by contract — it always
// returns nil, logging its own per-file problems at WARN. We still check the
// return defensively and NEVER let compat writing fail or abort the scan.
//
// workdir is the workspace root (boot.WorkDir == the *output.OutputTree Root);
// it is the authoritative fallback root. app.Tree is passed through when it is a
// concrete *output.OutputTree so WriteCompat reads tree.Root directly; a mock or
// nil tree degrades to WorkspaceRoot. ReconDir is intentionally left empty: the
// _compat/ subtree under the workspace root IS the bash-shape tree (the store's
// per-target ReconDir is likewise the workspace root, ingest.ensureTarget), and
// no top-level Recon/<domain> symlink convention is established elsewhere.
func writeCompatTree(app *appctx.AppContext, workdir string) {
	var tree *output.OutputTree
	if app != nil {
		if ot, ok := app.Tree.(*output.OutputTree); ok {
			tree = ot
		}
	}
	cw := &output.CompatWriter{WorkspaceRoot: workdir}
	if err := cw.WriteCompat(tree); err != nil {
		// Defensive: WriteCompat returns nil today, but never let a future
		// non-nil return abort the scan.
		if app != nil && app.Log != nil {
			app.Log.Warn("compat: WriteCompat failed (non-fatal)", "err", err)
		}
	}
}

// BootReconApp wires config → target → workspace → backend → appctx.Boot.
// It mirrors steps 1-5a of runSubsCmd in cmd/reconftw/stub_subcommands.go
// exactly.
//
// opts.Scheduler is a per-scan instance (CLI: per-invocation; MCP: produced by
// the per-scan factory). appctx.Boot wires this scan's RunTask/Checkpoint onto
// it; because the scheduler is not shared across sessions, that is race-free.
// The global concurrency ceiling is enforced by the scheduler's shared Limiter
// (MCP-05), not by sharing the Scheduler struct.
//
// The caller must pass a non-nil opts.Scheduler; returning an error on nil
// prevents silent DoS bypass of the concurrency ceiling (T-08-03-02).
func BootReconApp(ctx context.Context, opts RunOptions) (AppBoot, error) {
	if opts.Scheduler == nil {
		return AppBoot{}, fmt.Errorf("handlers: RunOptions.Scheduler must not be nil")
	}

	// Step 1: Load config.
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: opts.ConfigPath,
		SecretsPath:        opts.SecretsPath,
	})
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: config load: %w", err)
	}

	// Apply mode transform (zen/deep) AFTER Load and BEFORE Boot.
	// This ensures appctx.Boot wires the transformed concurrency limits (D-02/D-03).
	// Pitfall 5: applying after Boot means Boot already wired stale values.
	if opts.ConfigTransform != nil {
		opts.ConfigTransform(cfg)
	}

	// --force consumption (INTEG-03): OR the flag into cfg.Advanced.Diff so a
	// single knob drives Scheduler.ForceRerun below. quick-rescan already sets
	// Diff=true via its ConfigTransform, so both paths converge here.
	if opts.Force {
		cfg.Advanced.Diff = true
	}

	// Step 2: Build target.
	tgt, err := appctx.NewTarget(opts.Target, nil, "")
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: invalid target: %w", err)
	}

	// Step 3: Workspace init with fallback.
	workdir, err := output.WorkspaceInit(cfg.Paths.DataDir, tgt.Domain)
	if err != nil {
		workdir, err = output.WorkspaceInit("workspaces", tgt.Domain)
		if err != nil {
			return AppBoot{}, fmt.Errorf("handlers: workspace init: %w", err)
		}
	}
	tgt.WorkDir = workdir

	// Step 4: Use opts.Scheduler as-is (DO NOT call scheduler.NewScheduler —
	// Pitfall 3). The shared process-level scheduler owns the MaxJobs ceiling.

	// Step 5: Choose backend.
	var chosenBackend backend.Backend
	if opts.AxiomEnabled {
		axiomBE := backend.NewAxiomBackend(cfg, backend.Default, nil)
		localBE := backend.NewLocalBackend(time.Duration(cfg.Concurrency.KillGraceSeconds) * time.Second)
		chosenBackend = &backend.FailoverBackend{
			Primary:   axiomBE,
			Fallback:  localBE,
			Threshold: cfg.Axiom.FailoverThreshold,
		}
	}
	// nil chosenBackend → Boot.pickBackend selects LocalBackend.

	// Step 5a: Boot the AppContext.
	// Logger nil → uses slog.Default(). The MCP server sets slog.Default to a
	// redacted logger before starting scans, so this is safe.
	app, err := appctx.Boot(ctx, nil, cfg, tgt, opts.Scheduler, appctx.BootOptions{
		Backend:     chosenBackend,
		PassiveMode: opts.PassiveMode,
	})
	if err != nil {
		return AppBoot{}, fmt.Errorf("handlers: appctx boot: %w", err)
	}

	// INTEG-04: consume opts.TargetListPath — the monitor incremental re-feed's
	// new-asset seed file. Fold the FQDNs into the subdomains resolve-stage
	// staging contract so the hash-forced re-run's MergeStage("resolved") folds
	// them into subdomains.jsonl (which web.httpx then probes). Best-effort: a
	// missing/unreadable seed or an empty set is logged and ignored (never abort).
	if opts.TargetListPath != "" {
		var logger *slog.Logger
		if app != nil {
			logger = app.Log
		}
		seedIncrementalStaging(workdir, opts.TargetListPath, logger)
	}

	// Checkpoint wiring happens in each RunXxxAsync (sched.Checkpoint =
	// app.Checkpoint) and is race-free because opts.Scheduler is this scan's
	// own instance, not a shared one. RunXxxAsync also owns the app.Checkpoint
	// lifecycle (closed via defer).

	// INTEG-03: wire the REAL InputHash + ForceRerun onto this scan's scheduler.
	// opts.Scheduler is a per-scan instance (per the common.go header), so
	// mutating Hash/ForceRerun here mirrors the existing per-scan Checkpoint
	// wiring and never races across concurrent sessions.
	//
	// The cfg-slice is computed ONCE (best-effort): on SnapshotBytes error we
	// fall back to nil bytes — the hash still covers taskName + target +
	// TargetListPath, so it never degenerates to taskName-only again. We fold
	// opts.TargetListPath into the slice with a null-separated "tlp=" marker so a
	// list-mode / monitor-incremental re-feed produces a DIFFERENT InputHash and
	// genuinely re-runs the listed assets (the mechanism monitor.go assumes).
	cfgSlice, _ := config.SnapshotBytes(cfg)
	hashSlice := make([]byte, 0, len(cfgSlice)+len(opts.TargetListPath)+8)
	hashSlice = append(hashSlice, cfgSlice...)
	hashSlice = append(hashSlice, 0) // null separator (prefix-collision safety)
	hashSlice = append(hashSlice, "tlp="...)
	hashSlice = append(hashSlice, opts.TargetListPath...)
	wordlistsLock := wordlistsLockContent(cfg)
	tgtDomain := tgt.Domain
	opts.Scheduler.Hash = func(taskName, _ string) string {
		// Ignore the passed-in target arg (scheduler.targetFor() returns "");
		// the closure uses the captured tgt.Domain so the hash covers the real
		// target even though the Scheduler holds no AppContext reference.
		return checkpoint.InputHash(taskName, tgtDomain, hashSlice, wordlistsLock)
	}
	opts.Scheduler.ForceRerun = cfg.Advanced.Diff

	return AppBoot{App: app, WorkDir: workdir, Cfg: cfg, ChosenBackend: chosenBackend}, nil
}

// seedIncrementalStaging consumes the monitor incremental re-feed's TargetListPath
// (INTEG-04). It reads the new-asset FQDNs (one per line; blank lines and '#'
// comments skipped) and writes them as BARE TEXT to inputs/resolved.incremental.txt
// — a resolve-stage staging file per the subdomains STAGING CONTRACT
// (internal/modules/subdomains/doc.go). The hash-forced re-run's
// MergeStage("resolved") globs inputs/resolved.*.txt, dedups (anew-equivalent, so
// re-injecting already-known hosts is idempotent), and folds these into
// artefacts/subdomains.jsonl as the single writer — which web.httpx then probes.
//
// It deliberately does NOT call app.Tree.Append for the seed: Append has REPLACE
// semantics (would clobber subdomains.jsonl), is scope-checked, and is
// schema-on-write (rejects bare-FQDN text that is not valid JSON). The staging
// file is the correct, non-clobbering seam.
//
// Best-effort throughout: a missing/unreadable seed, an empty asset set, or a
// write error is logged and ignored — it never aborts BootReconApp (mirrors the
// INTEG-01/02 finalization discipline).
func seedIncrementalStaging(workDir, seedPath string, logger *slog.Logger) {
	fqdns, err := readSeedFQDNs(seedPath)
	if err != nil {
		if logger != nil {
			logger.Warn("handlers: TargetListPath unreadable — skipping incremental seed (best-effort)",
				"path", seedPath, "err", err)
		}
		return
	}
	if len(fqdns) == 0 {
		return
	}
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		if logger != nil {
			logger.Warn("handlers: mkdir inputs/ failed — skipping incremental seed", "err", err)
		}
		return
	}
	stagePath := filepath.Join(inputsDir, "resolved.incremental.txt")
	if err := atomicWriteLines(stagePath, fqdns); err != nil {
		if logger != nil {
			logger.Warn("handlers: write resolved.incremental.txt failed — skipping incremental seed", "err", err)
		}
		return
	}
	if logger != nil {
		logger.Debug("handlers: seeded incremental assets into resolve staging",
			"count", len(fqdns), "path", stagePath)
	}
}

// readSeedFQDNs reads a newline-delimited FQDN seed file, trimming whitespace and
// skipping blank lines and '#' comments. Returns the ordered FQDN slice.
func readSeedFQDNs(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // path is the monitor-written seed under workDir
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

// atomicWriteLines writes lines (newline-terminated) to path via a temp file +
// rename so a concurrent MergeStage glob never observes a half-written file.
func atomicWriteLines(path string, lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil { //nolint:gosec
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// wordlistsLockContent returns a best-effort fingerprint of the primary wordlist
// files (path + size + modtime) to fold into the checkpoint InputHash. Wordlist
// PATHS are already captured by the cfg snapshot; this adds CONTENT sensitivity
// so an edited wordlist invalidates the checkpoint (INTEG-03/04 correctness).
// Missing/unset files contribute nothing — an empty result is the acceptable
// default (the dominant invalidation drivers are the cfg-slice + target +
// TargetListPath). Never fails: any stat error is silently skipped.
func wordlistsLockContent(cfg *config.Config) []byte {
	if cfg == nil {
		return nil
	}
	var buf bytes.Buffer
	for _, p := range []string{
		cfg.Paths.SubsWordlist,
		cfg.Paths.SubsWordlistBig,
		cfg.Paths.FuzzWordlist,
	} {
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(&buf, "%s\x00%d\x00%d\n", p, info.Size(), info.ModTime().UnixNano())
	}
	return buf.Bytes()
}

// countJSONLLines returns the number of non-empty lines in a JSONL file.
// Returns 0 if the file does not exist or cannot be read.
func countJSONLLines(path string) int {
	f, err := os.Open(path) //nolint:gosec // path derived from validated workdir
	if err != nil {
		return 0
	}
	defer f.Close() //nolint:errcheck
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) > 0 {
			n++
		}
	}
	return n
}

// mergeTakeoverFindings reads both takeover staging files and calls
// app.Tree.Append("findings", merged) exactly once (B2 fix — single-writer).
//
// TakeoverSubzyTask and TakeoverDNSTakeTask each write their own staging file
// to avoid concurrent-write data loss (OutputTree.Append uses REPLACE semantics).
// This function serializes the merge after the enrichment RunStage completes.
func mergeTakeoverFindings(ctx context.Context, app *appctx.AppContext) error {
	_ = ctx

	subzyPath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.subzy.jsonl")
	dnstakePath := filepath.Join(app.Target.WorkDir, "inputs", "takeover.dnstake.jsonl")

	var merged [][]byte
	for _, p := range []string{subzyPath, dnstakePath} {
		lines, lerr := readJSONLLines(p)
		if lerr != nil {
			if app.Log != nil {
				app.Log.Debug("mergeTakeoverFindings: skipping staging file", "path", p, "err", lerr)
			}
			continue
		}
		merged = append(merged, lines...)
	}

	if len(merged) == 0 {
		return nil
	}
	return app.Tree.Append("findings", merged)
}

// readJSONLLines reads a JSONL file and returns each non-empty line as []byte.
func readJSONLLines(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var lines [][]byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		b := sc.Bytes()
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
