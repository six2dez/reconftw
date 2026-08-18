// recursive.go — SubRecursivePassiveTask + SubRecursiveBruteTask.
//
// STAGING CONTRACT (doc.go): Tasks write raw hostnames to staging files.
// Tasks do NOT call app.Tree.Append directly — MergeStage is the single writer.
//
// SEQUENTIAL MODEL: DependsOn() returns nil for both tasks. The command layer
// (newSubsCmd) calls recursive RunStage after the permut MergeStage completes.
// No barrier Tasks needed.
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
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Recursive staging file helpers
// -------------------------------------------------------------------------

// writeRecursiveStagingFile writes hostnames to inputs/recursive.<name>.txt, or
// REMOVES that file when lines is empty. Returns the staging path in both cases.
//
// F3 (phase 15): write-or-REMOVE via output.StageLines. Calling it asserts
// "this recursive source RAN and found exactly these hostnames", so a
// zero-result run clears the previous run's file instead of leaving it for
// MergeAllSubdomains (which globs inputs/recursive.*.txt) to republish.
func writeRecursiveStagingFile(app *appctx.AppContext, name string, lines []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("recursive %s: mkdir inputs/: %w", name, err)
	}
	stagingPath := filepath.Join(inputsDir, "recursive."+name+".txt")
	if err := output.StageLines(stagingPath, lines); err != nil {
		return "", fmt.Errorf("recursive %s: write staging file: %w", name, err)
	}
	return stagingPath, nil
}

// readLines reads all non-empty lines from a file.
// Returns nil (not error) if the file does not exist (empty input is valid).
func readLines(fpath string) ([]string, error) {
	f, err := os.Open(fpath) //nolint:gosec
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("readLines %q: %w", fpath, err)
	}
	defer f.Close() //nolint:errcheck // read/cleanup path

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// dsieveTopN selects the top-N recursion seeds via dsieve frequency filtering,
// mirroring bash sub_recursive_passive (modules/subdomains.sh:1802):
//
//	dsieve -if <resolved.merged> -f 3 -top <depth>
//
// `-f 3` groups/filters by DNS depth level 3; `-top N` keeps the N most frequent
// hosts. This replaces the previous naive subdomains[:depth] first-N prefix slice
// with bash's frequency-ranked selection so recursion targets the right
// high-value seeds instead of an arbitrary list prefix (PAR-01).
//
// Degrade (T-13-02-02): on a dsieve tool-execution error OR empty output it logs
// a warning and falls back to the first-N slice of fallback — recursion is a
// best-effort deep aux source, so a dsieve failure must never abort it.
func dsieveTopN(ctx context.Context, app *appctx.AppContext, inputFile string, depth int, fallback []string) []string {
	firstN := func() []string {
		n := depth
		if n > len(fallback) {
			n = len(fallback)
		}
		if n < 0 {
			n = 0
		}
		return fallback[:n]
	}

	res, err := app.Tools.Run(ctx, "dsieve", []string{
		"-if", inputFile,
		"-f", "3",
		"-top", strconv.Itoa(depth),
	})
	if err != nil {
		if app.Log != nil {
			app.Log.Warn("recursive.passive: dsieve failed — falling back to first-N slice",
				"tool", "dsieve", "error", err.Error())
		}
		return firstN()
	}

	seen := make(map[string]struct{})
	var seeds []string
	for _, raw := range strings.Split(string(res.Stdout), "\n") {
		line := strings.ToLower(strings.TrimSpace(raw))
		if line == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		seeds = append(seeds, line)
	}
	if len(seeds) == 0 {
		if app.Log != nil {
			app.Log.Warn("recursive.passive: dsieve returned no seeds — falling back to first-N slice",
				"tool", "dsieve")
		}
		return firstN()
	}
	return seeds
}

// -------------------------------------------------------------------------
// SubRecursivePassiveTask
// -------------------------------------------------------------------------

// SubRecursivePassiveTask runs subfinder passively on each resolved subdomain
// up to cfg.Subdomains.Recursive.PassiveDepth levels. This mirrors v1
// sub_recursive_passive (dsieve filtering + subfinder per top-N subdomain).
// Writes staging file: inputs/recursive.passive.txt
type SubRecursivePassiveTask struct{}

func (SubRecursivePassiveTask) Name() string        { return "subdomains.recursive.passive" }
func (SubRecursivePassiveTask) Module() string      { return "subdomains" }
func (SubRecursivePassiveTask) DependsOn() []string { return nil }

func (SubRecursivePassiveTask) Description() string {
	return "Recursive passive subdomain discovery via subfinder per top-N subdomain (SUBD-03)"
}

func (SubRecursivePassiveTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Recursive.PassiveEnabled
}

// Run runs subfinder on each subdomain found in inputs/resolved.merged.txt,
// accumulating results and writing inputs/recursive.passive.txt.
func (SubRecursivePassiveTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	inputFile := resolvedMergedPath(app)

	subdomains, err := readLines(inputFile)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("recursive.passive: read resolved.merged.txt: %w", err)
	}
	if len(subdomains) == 0 {
		// No input — write empty staging file and return done.
		stagingPath, _ := writeRecursiveStagingFile(app, "passive", nil)
		return task.Result{
			Status:  task.StatusDone,
			Outputs: []string{stagingPath},
			Stats:   map[string]int{"recursive_passive_found": 0},
		}, nil
	}

	// Select the top-N recursion seeds via dsieve frequency filtering (bash
	// sub_recursive_passive parity) instead of the naive subdomains[:depth]
	// first-N prefix slice. PassiveDepth maps to bash DEEP_RECURSIVE_PASSIVE.
	// dsieveTopN degrades to the first-N slice on a dsieve error/empty output.
	depth := cfg.Subdomains.Recursive.PassiveDepth
	if depth <= 0 {
		depth = 1
	}
	targets := dsieveTopN(ctx, app, inputFile, depth, subdomains)

	// Deduplicate seen hostnames across subfinder calls.
	seen := make(map[string]struct{})
	var allFound []string

	timeoutSecs := cfg.Advanced.Tools.Subfinder.TimeoutMinutes * 60
	if timeoutSecs <= 0 {
		timeoutSecs = 180 // default 3 minutes per call
	}

	for _, sub := range targets {
		if ctx.Err() != nil {
			break // context cancelled; write what we have
		}
		args := []string{
			"-all",
			"-d", sub,
			"-max-time", strconv.Itoa(timeoutSecs),
			"-silent",
		}
		res, runErr := app.Tools.Run(ctx, "subfinder", args)
		if runErr != nil {
			// Subfinder failure on one target is non-fatal — log and continue.
			if app.Log != nil {
				app.Log.Info("recursive_passive_skip_subfinder",
					"subdomain", sub,
					"error", runErr.Error(),
				)
			}
			continue
		}

		scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line == "" {
				continue
			}
			if _, dup := seen[line]; !dup {
				seen[line] = struct{}{}
				allFound = append(allFound, line)
			}
		}
	}

	stagingPath, writeErr := writeRecursiveStagingFile(app, "passive", allFound)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"recursive_passive_found": len(allFound)},
	}, nil
}

// -------------------------------------------------------------------------
// SubRecursiveBruteTask
// -------------------------------------------------------------------------

// SubRecursiveBruteTask runs puredns bruteforce on each resolved subdomain.
// This mirrors v1 sub_recursive_brute, which brute-forces EVERY resolved sub
// with a short wordlist via puredns — NOT a dsieve top-N subset (unlike
// SubRecursivePassiveTask). That full-set behavior is intentional bash parity
// and is deliberately left unchanged here (13-02 Task 2 scope note).
// Writes staging file: inputs/recursive.brute.txt
type SubRecursiveBruteTask struct{}

func (SubRecursiveBruteTask) Name() string        { return "subdomains.recursive.brute" }
func (SubRecursiveBruteTask) Module() string      { return "subdomains" }
func (SubRecursiveBruteTask) DependsOn() []string { return nil }

func (SubRecursiveBruteTask) Description() string {
	return "Recursive brute-force discovery via puredns per top-N subdomain (SUBD-03)"
}

func (SubRecursiveBruteTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Recursive.BruteEnabled
}

// Run runs puredns bruteforce on each subdomain in inputs/resolved.merged.txt,
// accumulating results and writing inputs/recursive.brute.txt.
// Uses Stream for XCUT-09 heartbeat.
func (SubRecursiveBruteTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	inputFile := resolvedMergedPath(app)

	subdomains, err := readLines(inputFile)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("recursive.brute: read resolved.merged.txt: %w", err)
	}
	if len(subdomains) == 0 {
		stagingPath, _ := writeRecursiveStagingFile(app, "brute", nil)
		return task.Result{
			Status:  task.StatusDone,
			Outputs: []string{stagingPath},
			Stats:   map[string]int{"recursive_brute_found": 0},
		}, nil
	}

	wordlistPath := cfg.Paths.SubsWordlist
	resolverPath := cfg.Paths.Resolvers

	// Same gate as SubBruteTask: without a usable wordlist every per-subdomain
	// puredns invocation fails instantly and the task still reports success.
	if !wordlistReadable(wordlistPath) {
		if app.Log != nil {
			app.Log.Info("subdomains.recursive.brute: subs wordlist missing or unreadable — skipping",
				"wordlist", wordlistPath)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	seen := make(map[string]struct{})
	var allFound []string

	for _, sub := range subdomains {
		if ctx.Err() != nil {
			break
		}

		args := []string{
			"bruteforce", wordlistPath,
			"-d", sub,
			"--quiet",
		}
		if resolverPath != "" {
			args = append(args, "-r", resolverPath)
		}
		if cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit > 0 {
			args = append(args, "--wildcard-tests",
				fmt.Sprintf("%d", cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit))
		}

		// Use Stream for XCUT-09 heartbeat.
		ch, streamErr := app.Tools.Stream(ctx, "puredns", args)
		if streamErr != nil {
			// Non-fatal: log and continue to next subdomain.
			if app.Log != nil {
				app.Log.Info("recursive_brute_skip_puredns",
					"subdomain", sub,
					"error", streamErr.Error(),
				)
			}
			continue
		}

		// F6 (phase 15): ACCUMULATOR shape — latch the terminal Event.Err inside
		// the loop and check it immediately after. Note the variable above,
		// streamErr, is the DISPATCH error ("puredns is not on PATH") and keeps
		// its non-fatal log-and-continue handling verbatim; termErr is the
		// different thing — puredns RAN on this subdomain and ended badly, so
		// what it emitted is a partial bruteforce.
		var termErr error
		for ev := range ch {
			if ev.Err != nil {
				if termErr == nil {
					termErr = ev.Err
				}
				continue
			}
			if ev.IsErr {
				continue
			}
			line := strings.ToLower(strings.TrimSpace(string(ev.Line)))
			if line == "" {
				continue
			}
			if _, dup := seen[line]; !dup {
				seen[line] = struct{}{}
				allFound = append(allFound, line)
			}
		}
		if termErr != nil {
			// Discard everything accumulated across ALL subdomains and stage
			// nothing: a recursive brute that failed on one branch has not
			// enumerated the tree, and publishing the branches that did finish
			// would understate the remaining surface.
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("puredns: tool stream ended badly for %s: %w", sub, termErr)
		}
	}

	stagingPath, writeErr := writeRecursiveStagingFile(app, "brute", allFound)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"recursive_brute_found": len(allFound)},
	}, nil
}

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(SubRecursivePassiveTask{}) }
func init() { task.Register(SubRecursiveBruteTask{}) }
