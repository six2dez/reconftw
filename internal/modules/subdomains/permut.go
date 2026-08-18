// permut.go — SubPermutTask, SubRegexPermutTask, SubDNSCewlTask, SubIAPermutTask.
//
// STAGING CONTRACT (doc.go): Tasks write raw hostnames to per-source staging
// files. Tasks do NOT call app.Tree.Append directly.
//
// SUBD-03 MEMORY BACK-PRESSURE:
// Permutation stages are the heaviest in the pipeline (largest wordlist growth).
// SubPermutTask, SubRegexPermutTask, SubDNSCewlTask, and SubIAPermutTask gate
// execution on OS available memory via sysinfo.MemProvider.Available() —
// NOT runtime.ReadMemStats (which measures Go heap, not OS free RAM).
//
// Gate behavior (SUBD-03):
//   - If MinFreeMemGB == 0: gate disabled; proceed immediately.
//   - If available > threshold: proceed.
//   - If available <= threshold: poll every 5s. On context cancellation: return
//     StatusSkipped — NOT silent drop (SUBD-11 parity requires all found
//     subdomains to be processed; silent drops reduce parity coverage).
//
// REVIEWS FINDING FIX:
// OSMemProvider uses gopsutil/v3/mem.VirtualMemory().Available = OS MemAvailable.
// This is correct. runtime.ReadMemStats.Sys-runtime.MemStats.Alloc is Go heap
// reservation delta, NOT OS free memory — NEVER use that here.
//
// B1 FIX — SubDNSCewlTask:
// dnscewl is the THIRD SUBD-03 permutation tool (D-01: gotator + regulator + dnscewl).
// It generates DNS-based permutations from the resolved subdomain list.
// Input flag: -f (per tools.lock entry plan-00).
// If binary not found, returns StatusSkipped at Info level (non-critical).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/subdomains/sysinfo"
)

// -------------------------------------------------------------------------
// Memory back-pressure helper (SUBD-03)
// -------------------------------------------------------------------------

const (
	// memPollInterval is the polling interval when waiting for OS memory.
	memPollInterval = 5 * time.Second
	// bytesPerGB is the number of bytes in one gigabyte.
	bytesPerGB uint64 = 1 << 30
)

// memCheck gates execution on OS available memory.
// Returns true when it is safe to proceed (memory available or gate disabled).
// Returns false when the gate blocks and the context was cancelled — caller
// should return StatusSkipped (NOT drop silently — SUBD-11 parity).
//
// Parameters:
//   - ctx: cancellable; cancel signal causes the wait loop to exit with false.
//   - mp:  MemProvider to query (sysinfo.OSMemProvider{} in production).
//   - minGB: threshold from cfg.Subdomains.Permut.MinFreeMemGB. 0 = disabled.
func memCheck(ctx context.Context, mp sysinfo.MemProvider, minGB int) bool {
	if minGB <= 0 {
		// Gate disabled — proceed unconditionally.
		return true
	}
	threshold := uint64(minGB) * bytesPerGB
	for {
		avail := mp.Available()
		if avail > threshold {
			return true
		}
		// Memory below threshold — poll until available or cancelled.
		select {
		case <-ctx.Done():
			return false // context cancelled: caller returns StatusSkipped
		case <-time.After(memPollInterval):
			// Re-check on next iteration.
		}
	}
}

// resolvedMergedPath returns the path to the merged resolved staging file.
// This is the output of MergeStage("resolved") — permutation tasks read it.
func resolvedMergedPath(app *appctx.AppContext) string {
	return filepath.Join(app.Target.WorkDir, "inputs", "resolved.merged.txt")
}

// writePermutStagingFile writes permutation candidates (one per line) to
// inputs/permut.<tool>.txt, or REMOVES that file when lines is empty. Returns
// the staging path in both cases.
//
// F3 (phase 15): write-or-REMOVE via output.StageLines. Calling it asserts
// "this permutation source RAN and produced exactly these candidates", so a
// zero-result run clears the previous run's file instead of leaving it for
// MergeAllSubdomains (which globs inputs/permut.*.txt) to republish.
func writePermutStagingFile(app *appctx.AppContext, toolName string, lines []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("permut %s: mkdir inputs/: %w", toolName, err)
	}
	stagingPath := filepath.Join(inputsDir, "permut."+toolName+".txt")
	if err := output.StageLines(stagingPath, lines); err != nil {
		return "", fmt.Errorf("permut %s: write staging file: %w", toolName, err)
	}
	return stagingPath, nil
}

// -------------------------------------------------------------------------
// SubPermutTask — gotator permutations (SUBD-03 memory gate)
// -------------------------------------------------------------------------

// SubPermutTask generates subdomain permutations via gotator.
// Writes staging file: inputs/permut.gotator.txt
// Reads input: inputs/resolved.merged.txt (output of MergeStage("resolved"))
type SubPermutTask struct {
	// MemProv overrides the default OSMemProvider for testing.
	// When nil, uses sysinfo.OSMemProvider{}.
	MemProv sysinfo.MemProvider
}

func (t *SubPermutTask) Name() string        { return "subdomains.permut" }
func (t *SubPermutTask) Module() string      { return "subdomains" }
func (t *SubPermutTask) DependsOn() []string { return nil }

func (t *SubPermutTask) Description() string {
	return "Subdomain permutation via gotator with OS memory back-pressure (SUBD-03)"
}

func (t *SubPermutTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Permut.Enabled
}

func (t *SubPermutTask) memProvider() sysinfo.MemProvider {
	if t.MemProv != nil {
		return t.MemProv
	}
	return sysinfo.OSMemProvider{}
}

// Run generates permutations via gotator with SUBD-03 memory back-pressure.
//
// Flow:
//  1. memCheck — wait until OS memory > MinFreeMemGB*GB, or cancel → StatusSkipped.
//  2. Read inputs/resolved.merged.txt as gotator input seed.
//  3. Run gotator via Stream (XCUT-09 heartbeat for long permutation runs).
//  4. Write candidates to inputs/permut.gotator.txt.
func (t *SubPermutTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	mp := t.memProvider()

	// SUBD-03: memory back-pressure gate.
	if !memCheck(ctx, mp, cfg.Subdomains.Permut.MinFreeMemGB) {
		if app.Log != nil {
			app.Log.Info("permut_skipped_memory_gate",
				"event", "permut_skipped_memory_gate",
				"min_free_mem_gb", cfg.Subdomains.Permut.MinFreeMemGB,
			)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputFile := resolvedMergedPath(app)
	args := []string{
		"-sub", inputFile,
		"-depth", "1",
		"-numbers", "3",
		"-md",
	}

	// Run gotator via Stream for XCUT-09 heartbeat.
	ch, err := app.Tools.Stream(ctx, "gotator", args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("gotator: Stream failed: %w", err)
	}

	// F6 (phase 15): ACCUMULATOR shape — latch the terminal Event.Err inside the
	// loop and check it after. gotator is the heaviest stage in the pipeline; a
	// run killed by the OOM killer part way through emits a fraction of its
	// permutations, and staging that fraction as the run's candidate set is
	// indistinguishable from a genuinely small permutation space.
	//
	// The Stream() error above (gotator not on PATH) keeps its existing
	// handling untouched.
	var lines []string
	var streamErr error
	for ev := range ch {
		if ev.Err != nil {
			if streamErr == nil {
				streamErr = ev.Err
			}
			continue
		}
		if ev.IsErr {
			continue
		}
		line := strings.ToLower(strings.TrimSpace(string(ev.Line)))
		if line != "" {
			lines = append(lines, line)
		}
	}
	if streamErr != nil {
		// Discard the partial permutation set and stage nothing.
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("gotator: tool stream ended badly: %w", streamErr)
	}

	// A clean run with zero output (typically an empty input file) still goes
	// through the helper: F3 requires "ran and found nothing" to CLEAR the
	// staging file rather than leave the previous run's permutations behind.
	stagingPath, writeErr := writePermutStagingFile(app, "gotator", lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"gotator_candidates": len(lines)},
	}, nil
}

// -------------------------------------------------------------------------
// SubRegexPermutTask — regex-based permutations (regulator)
// -------------------------------------------------------------------------

// SubRegexPermutTask generates subdomain permutations via regulator (regex-based).
// Writes staging file: inputs/permut.regex.txt
type SubRegexPermutTask struct {
	// MemProv overrides the default OSMemProvider for testing.
	MemProv sysinfo.MemProvider
}

func (t *SubRegexPermutTask) Name() string        { return "subdomains.permut.regex" }
func (t *SubRegexPermutTask) Module() string      { return "subdomains" }
func (t *SubRegexPermutTask) DependsOn() []string { return nil }

func (t *SubRegexPermutTask) Description() string {
	return "Subdomain permutation via regulator (regex-based) with OS memory back-pressure"
}

func (t *SubRegexPermutTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Permut.Enabled && cfg.Subdomains.Permut.RegexEnabled
}

func (t *SubRegexPermutTask) memProvider() sysinfo.MemProvider {
	if t.MemProv != nil {
		return t.MemProv
	}
	return sysinfo.OSMemProvider{}
}

// Run generates regex-based permutations via regulator with memory back-pressure.
func (t *SubRegexPermutTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	mp := t.memProvider()

	if !memCheck(ctx, mp, cfg.Subdomains.Permut.MinFreeMemGB) {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputFile := resolvedMergedPath(app)
	res, err := app.Tools.Run(ctx, "regulator", []string{inputFile, app.Target.Domain})
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("regulator: Run failed: %w", err)
	}

	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writePermutStagingFile(app, "regex", lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"regex_candidates": len(lines)},
	}, nil
}

// -------------------------------------------------------------------------
// SubDNSCewlTask — DNS permutation wordlist generator (B1 fix — SUBD-03)
// -------------------------------------------------------------------------

// SubDNSCewlTask generates DNS-based subdomain permutations via dnscewl.
// dnscewl is the THIRD permutation tool named in D-01 (gotator + regulator + dnscewl).
// Writes staging file: inputs/permut.dnscewl.txt
//
// If dnscewl binary is not found (non-critical per tools.lock), returns
// StatusSkipped at Info level — does NOT error.
//
// Input flag: -f (per tools.lock plan-00 entry input_flag="-f").
type SubDNSCewlTask struct {
	// MemProv overrides the default OSMemProvider for testing.
	MemProv sysinfo.MemProvider
}

func (t *SubDNSCewlTask) Name() string        { return "subdomains.permut.dnscewl" }
func (t *SubDNSCewlTask) Module() string      { return "subdomains" }
func (t *SubDNSCewlTask) DependsOn() []string { return nil }

func (t *SubDNSCewlTask) Description() string {
	return "DNS-based subdomain permutation via dnscewl (SUBD-03 third tool — B1 fix)"
}

func (t *SubDNSCewlTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Permut.Enabled
}

func (t *SubDNSCewlTask) memProvider() sysinfo.MemProvider {
	if t.MemProv != nil {
		return t.MemProv
	}
	return sysinfo.OSMemProvider{}
}

// Run generates DNS-based permutation candidates using dnscewl.
//
// Flow:
//  1. memCheck — wait for memory or cancel → StatusSkipped.
//  2. Run dnscewl -f <resolvedMergedFile> -r <resolversFile>.
//  3. Parse stdout (one candidate per line).
//  4. Write to inputs/permut.dnscewl.txt.
//  5. If dnscewl not found: return StatusSkipped at Info level.
func (t *SubDNSCewlTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	mp := t.memProvider()

	// SUBD-03: memory back-pressure gate.
	if !memCheck(ctx, mp, cfg.Subdomains.Permut.MinFreeMemGB) {
		if app.Log != nil {
			app.Log.Info("dnscewl_skipped_memory_gate",
				"event", "dnscewl_skipped_memory_gate",
				"min_free_mem_gb", cfg.Subdomains.Permut.MinFreeMemGB,
			)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputFile := resolvedMergedPath(app)
	args := []string{"-f", inputFile}
	if cfg.Paths.Resolvers != "" {
		args = append(args, "-r", cfg.Paths.Resolvers)
	}

	res, err := app.Tools.Run(ctx, "dnscewl", args)
	if err != nil {
		// dnscewl not found or failed — treat as non-critical: StatusSkipped.
		if app.Log != nil {
			app.Log.Info("dnscewl_skipped",
				"event", "dnscewl_skipped",
				"reason", "tool_not_available",
				"error", err.Error(),
			)
		}
		// Still write an empty staging file so MergeStage finds no orphaned glob.
		stagingPath, _ := writePermutStagingFile(app, "dnscewl", nil)
		return task.Result{
			Status:  task.StatusSkipped,
			Outputs: []string{stagingPath},
		}, nil
	}

	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writePermutStagingFile(app, "dnscewl", lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"dnscewl_candidates": len(lines)},
	}, nil
}

// -------------------------------------------------------------------------
// SubIAPermutTask — Internet Archive wordlist permutations
// -------------------------------------------------------------------------

// SubIAPermutTask generates subdomain permutations using the Internet Archive
// wordlist via subwiz (ML-based prediction). Mirrors v1 sub_ia_permut.
// Writes staging file: inputs/permut.ia.txt
type SubIAPermutTask struct {
	// MemProv overrides the default OSMemProvider for testing.
	MemProv sysinfo.MemProvider
}

func (t *SubIAPermutTask) Name() string        { return "subdomains.permut.ia" }
func (t *SubIAPermutTask) Module() string      { return "subdomains" }
func (t *SubIAPermutTask) DependsOn() []string { return nil }

func (t *SubIAPermutTask) Description() string {
	return "Internet Archive wordlist subdomain permutation via subwiz (SUBD-03)"
}

func (t *SubIAPermutTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Permut.Enabled && cfg.Subdomains.Permut.IAEnabled
}

func (t *SubIAPermutTask) memProvider() sysinfo.MemProvider {
	if t.MemProv != nil {
		return t.MemProv
	}
	return sysinfo.OSMemProvider{}
}

// Run generates Internet Archive-based permutation candidates using subwiz.
//
// Flow:
//  1. memCheck — wait for memory or cancel → StatusSkipped.
//  2. Run subwiz -i <resolvedMergedFile> --no-resolve.
//  3. Write candidates to inputs/permut.ia.txt.
func (t *SubIAPermutTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	mp := t.memProvider()

	if !memCheck(ctx, mp, cfg.Subdomains.Permut.MinFreeMemGB) {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputFile := resolvedMergedPath(app)
	res, err := app.Tools.Run(ctx, "subwiz", []string{
		"-i", inputFile,
		"--no-resolve",
	})
	if err != nil {
		// subwiz not found or failed — non-critical.
		if app.Log != nil {
			app.Log.Info("ia_permut_skipped",
				"event", "ia_permut_skipped",
				"reason", "tool_not_available",
				"error", err.Error(),
			)
		}
		stagingPath, _ := writePermutStagingFile(app, "ia", nil)
		return task.Result{
			Status:  task.StatusSkipped,
			Outputs: []string{stagingPath},
		}, nil
	}

	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writePermutStagingFile(app, "ia", lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"ia_candidates": len(lines)},
	}, nil
}

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(&SubPermutTask{}) }
func init() { task.Register(&SubRegexPermutTask{}) }
func init() { task.Register(&SubDNSCewlTask{}) }
func init() { task.Register(&SubIAPermutTask{}) }
