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

// permutationsFullList / permutationsShortList are v1's file names, deliberately.
// An operator migrating from v1 points paths.wordlists_dir at their existing
// data/wordlists and the tool finds what it expects; a new name would silently
// leave them with a skipping permutation stage.
const (
	permutationsFullList  = "permutations_list.txt"
	permutationsShortList = "permutations_list_short.txt"
)

// selectPermutationsWordlist implements v1's _select_permutations_wordlist
// (modules/subdomains.sh:1478) against cfg.Subdomains.Permut.WordlistMode,
// cfg.Subdomains.Permut.ShortThreshold and cfg.Paths.WordlistsDir.
//
// Returns ("", reason) when no usable list exists. The reason is returned rather
// than logged here so the caller can put it on task.Result.Reason: a permutation
// stage that produces nothing must say why, in the run's own output.
//
// The derivation is ONLY from paths.wordlists_dir. It deliberately does not fall
// back to paths.data_dir: data_dir already means two different things in v2 (the
// workspace root in stateful_subcommands.go, the tools root in
// web.resolveToolsDir), and guessing a third meaning would put an unpredictable
// path on a command line. An unset wordlists_dir skips loudly instead.
func selectPermutationsWordlist(cfg *config.Config, sourceFile string) (string, string) {
	dir := strings.TrimSpace(cfg.Paths.WordlistsDir)
	if dir == "" {
		return "", "no permutation wordlist: paths.wordlists_dir is not configured (v1: WORDLISTS_DIR, holding " +
			permutationsFullList + " and " + permutationsShortList + ")"
	}
	full := filepath.Join(dir, permutationsFullList)
	short := filepath.Join(dir, permutationsShortList)

	var want string
	switch strings.ToLower(strings.TrimSpace(cfg.Subdomains.Permut.WordlistMode)) {
	case "full":
		want = full
	case "short":
		want = short
	case "auto", "":
		// v1's deep short-circuit: deep mode always takes the full list, however
		// large the seed set is.
		switch {
		case cfg.Advanced.Deep:
			want = full
		case countNonEmptyFileLines(sourceFile) <= cfg.Subdomains.Permut.ShortThreshold:
			want = full
		default:
			want = short
		}
	default:
		// v1's `*)` arm.
		want = full
	}

	if !wordlistReadable(want) {
		return "", "no permutation wordlist: " + want + " is missing or empty"
	}
	return want, ""
}

// countNonEmptyFileLines counts non-blank lines; an unreadable file counts 0,
// which sends the "auto" branch to the full list — the same way v1's
// `[[ -s "$source_file" ]] && count=…` leaves count at 0.
func countNonEmptyFileLines(path string) int {
	f, err := os.Open(path) //nolint:gosec // path derived from the run's own workspace
	if err != nil {
		return 0
	}
	defer f.Close() //nolint:errcheck
	n := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			n++
		}
	}
	return n
}

// looksLikeHostnameCandidate reports whether line can be staged as a subdomain
// candidate. Conservative by design: a permutation tool's stdout is the input to
// the resolve stage, and anything that is not hostname-shaped there is noise at
// best and an injected candidate at worst.
func looksLikeHostnameCandidate(line string) bool {
	if line == "" || len(line) > 253 {
		return false
	}
	if !strings.Contains(line, ".") {
		return false
	}
	for _, r := range line {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	// A leading or trailing dot, or an empty label, is not a hostname.
	if strings.HasPrefix(line, ".") || strings.HasSuffix(line, ".") || strings.Contains(line, "..") {
		return false
	}
	return true
}

// capCandidateBytes truncates candidates at limit bytes (newline included per
// line), mirroring v1's `head -c "$PERMUTATIONS_LIMIT"`. limit <= 0 disables it.
// Truncation is on a LINE boundary: v1's head -c can cut a hostname in half, and
// half a hostname is a candidate that is simply wrong.
func capCandidateBytes(lines []string, limit int64) []string {
	if limit <= 0 {
		return lines
	}
	var used int64
	for i, l := range lines {
		used += int64(len(l)) + 1
		if used > limit {
			return lines[:i]
		}
	}
	return lines
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

	// CR-03. gotator's -perm is the word list it permutes WITH, and until now v2
	// never passed one — while cfg.Subdomains.Permut.WordlistMode and
	// ShortThreshold sat in config read by NOTHING and `deep --help` advertised
	// "Permut wordlist mode = full". That is the uncommon_ports shape: a
	// capability ported into config only.
	//
	// The review's stated mechanism was WRONG in two places, and the corrections
	// matter because the fix is built from the mechanism (gotator v1.1, measured):
	//
	//   - "without it there is nothing to permute and the tool errors" — FALSE.
	//     `gotator -sub seed -depth 1 -numbers 3 -md` exits 0 and emits 1602
	//     candidates for a 5-host seed; it permutes with words it derives from
	//     the seed list itself. The stage was not producing NOTHING, it was
	//     producing the wrong, much smaller thing (15185 with the full list).
	//   - "gotator's banner goes to stdout" — FALSE. The banner is on STDERR,
	//     and the collector below already drops stderr events. -silent is passed
	//     anyway: v1 passes it, and it keeps run.log readable.
	//
	// What IS unambiguous: `-perm <missing file>` makes gotator PANIC (exit 2),
	// so the readable gate has to run BEFORE dispatch.
	wordlist, wlWhy := selectPermutationsWordlist(cfg, inputFile)
	if wordlist == "" {
		if app.Log != nil {
			app.Log.Info("subdomains.permut: no permutation wordlist — skipping",
				"reason", wlWhy,
				"wordlists_dir", cfg.Paths.WordlistsDir,
				"mode", cfg.Subdomains.Permut.WordlistMode,
			)
		}
		return task.Result{Status: task.StatusSkipped, Reason: wlWhy}, nil
	}

	args := []string{
		"-sub", inputFile,
		"-perm", wordlist,
		"-depth", "1",
		"-numbers", "3",
		"-md",
		"-silent",
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
		// T-17-06-02. The collector stages what it is given, so what it is given
		// has to be a hostname. gotator v1.1 puts its banner on stderr (dropped
		// above), but "the current version prints decoration on the other stream"
		// is not a property worth depending on — one banner line on stdout would
		// otherwise become a subdomain candidate.
		if looksLikeHostnameCandidate(line) {
			lines = append(lines, line)
		}
	}
	if streamErr != nil {
		// Discard the partial permutation set and stage nothing.
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("gotator: tool stream ended badly: %w", streamErr)
	}

	// SUBD-03 / T-17-06-04. cfg.Subdomains.Permut.LimitBytes was the THIRD field
	// in this struct that nothing read (WordlistMode and ShortThreshold were the
	// other two). v1 applies it — `head -c "$PERMUTATIONS_LIMIT"`,
	// modules/subdomains.sh:1517 — and it matters more now than before: giving
	// gotator a real word list takes a 5-host seed from 1602 candidates to 15185.
	lines = capCandidateBytes(lines, cfg.Subdomains.Permut.LimitBytes)

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

	// CR-04, proven behaviourally against regulator at commit 2371a06 (the clone
	// install.sh creates, run through its own venv). Both halves of the review's
	// mechanism hold — unusually, since CR-01's did not:
	//
	//	$ main.py hosts.txt example.com                       # what v2 dispatched
	//	main.py: error: the following arguments are required: -t/--target, -f/--hosts
	//	exit=2, 0 lines on stdout
	//	$ main.py -t example.com -f hosts.txt -o regulator.out # v1, subdomains.sh:1650
	//	exit=0, 0 lines on STDOUT, 9 candidates in regulator.out
	//
	// regulator's interface is `-t TARGET -f HOSTS [-o OUTPUT]` and it prints
	// NOTHING on stdout even when it succeeds, so the old vector failed twice
	// over: it could not parse, and there was nothing to read if it had.
	// RegexEnabled defaults to true, so every all/deep run took this path and
	// staged zero candidates.
	outputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(outputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("regulator: mkdir inputs/: %w", err)
	}
	rawOutput := filepath.Join(outputsDir, "permut.regex.raw.txt")
	// Remove any previous run's file FIRST. Without this, a regulator that failed
	// to start would be indistinguishable from one that succeeded, because the
	// stale file would be read as this run's result.
	if err := os.Remove(rawOutput); err != nil && !os.IsNotExist(err) {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("regulator: clear stale output %s: %w", rawOutput, err)
	}

	if _, err := app.Tools.Run(ctx, "regulator", []string{
		"-t", app.Target.Domain,
		"-f", inputFile,
		"-o", rawOutput,
	}); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("regulator: Run failed: %w", err)
	}

	raw, readErr := os.ReadFile(rawOutput) //nolint:gosec // path inside the run's own workspace
	if readErr != nil || len(bytes.TrimSpace(raw)) == 0 {
		reason := "regulator produced no output file at " + rawOutput
		if readErr == nil {
			reason = "regulator ran and its output file was empty (" + rawOutput + ")"
		}
		if app.Log != nil {
			app.Log.Info("subdomains.permut.regex: no candidates — skipping", "reason", reason)
		}
		// Still clear the staging file: F3 requires "ran and found nothing" to
		// remove the previous run's candidates rather than republish them.
		if _, werr := writePermutStagingFile(app, "regex", nil); werr != nil {
			return task.Result{Status: task.StatusErrored}, werr
		}
		return task.Result{Status: task.StatusSkipped, Reason: reason}, nil
	}

	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		// Same rule as the gotator collector (T-17-06-02): only hostname-shaped
		// lines may become candidates.
		if looksLikeHostnameCandidate(line) {
			lines = append(lines, line)
		}
	}
	lines = capCandidateBytes(lines, cfg.Subdomains.Permut.LimitBytes)

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
	// resolverListUsable, not `!= ""`: paths.resolvers now always carries a
	// default path, so an emptiness test no longer proves the file exists.
	if resolverListUsable(cfg.Paths.Resolvers) {
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
