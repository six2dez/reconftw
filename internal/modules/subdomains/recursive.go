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
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Recursive staging file helpers
// -------------------------------------------------------------------------

// writeRecursiveStagingFile writes hostnames to inputs/recursive.<name>.txt.
func writeRecursiveStagingFile(app *appctx.AppContext, name string, lines []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("recursive %s: mkdir inputs/: %w", name, err)
	}
	stagingPath := filepath.Join(inputsDir, "recursive."+name+".txt")
	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	if err := os.WriteFile(stagingPath, []byte(content), 0o644); err != nil { //nolint:gosec
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
	defer f.Close()

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

	// Limit to PassiveDepth top-level subdomains (first N from list).
	depth := cfg.Subdomains.Recursive.PassiveDepth
	if depth <= 0 {
		depth = 1
	}
	if depth > len(subdomains) {
		depth = len(subdomains)
	}
	targets := subdomains[:depth]

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
// This mirrors v1 sub_recursive_brute (brute each top-N subdomain with
// short wordlist via puredns).
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

		for ev := range ch {
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
