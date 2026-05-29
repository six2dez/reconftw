// brute.go — SubBruteTask + SubResolversHealthTask.
//
// STAGING CONTRACT (doc.go): SubBruteTask writes raw hostnames to
// inputs/resolved.brute.txt — NOT app.Tree.Append.
//
// SUBD-02 RESOLVER HEALTH GATE:
// SubBruteTask.Run independently checks the resolver file line count before
// running puredns bruteforce. This in-Run() check is MANDATORY because
// Scheduler.runOne does NOT call Enabled() — only the command layer's
// filterByModuleAndEnabled calls Enabled(). Enabled() returning false is
// used only for config-based disablement (Brute.Enabled = false). Runtime
// conditions like resolver health MUST live in Run().
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-02-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Resolver health helper
// -------------------------------------------------------------------------

// countResolverLines returns the count of non-empty lines in the resolver file.
// Returns 0 and an error if the file cannot be read.
func countResolverLines(path string) (int, error) {
	if path == "" {
		return 0, fmt.Errorf("resolver file path is empty")
	}
	f, err := os.Open(path) //nolint:gosec // path comes from cfg.Paths.Resolvers (nopath_traversal validated at config load)
	if err != nil {
		return 0, fmt.Errorf("open resolver file %q: %w", path, err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count, scanner.Err()
}

// -------------------------------------------------------------------------
// SubResolversHealthTask
// -------------------------------------------------------------------------

// SubResolversHealthTask is a lightweight pre-check that verifies the DNS
// resolver file has at least cfg.Subdomains.Brute.MinResolvers non-empty lines.
// Returns StatusSkipped if the gate fails so the command layer can surface
// the warning without aborting the entire phase.
type SubResolversHealthTask struct{}

func (SubResolversHealthTask) Name() string        { return "subdomains.resolvers.health" }
func (SubResolversHealthTask) Module() string      { return "subdomains" }
func (SubResolversHealthTask) DependsOn() []string { return nil }

func (SubResolversHealthTask) Description() string {
	return "Resolver file health check: verifies >= MinResolvers non-empty lines (SUBD-02)"
}

// Enabled returns false when brute is disabled — no point checking resolvers if
// brute won't run.
func (SubResolversHealthTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Brute.Enabled
}

// Run reads cfg.Paths.Resolvers and counts non-empty lines. Returns
// StatusSkipped (not StatusErrored) when the count is below MinResolvers —
// the operator may have intentionally reduced the resolver set, so a hard
// error would be too aggressive. The warning log is enough to surface it.
func (SubResolversHealthTask) Run(_ context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	minResolvers := cfg.Subdomains.Brute.MinResolvers
	resolverPath := cfg.Paths.Resolvers

	count, err := countResolverLines(resolverPath)
	if err != nil {
		// File unreadable — log and skip (not error; user may have not set up resolvers yet).
		if app.Log != nil {
			app.Log.Warn("resolver_health_check_failed",
				"resolver_file", resolverPath,
				"error", err.Error(),
			)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	if count < minResolvers {
		if app.Log != nil {
			app.Log.Warn("resolver_health_check_failed",
				"resolver_file", resolverPath,
				"count", count,
				"min", minResolvers,
			)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"resolver_count": count},
	}, nil
}

// -------------------------------------------------------------------------
// SubBruteTask
// -------------------------------------------------------------------------

// SubBruteTask runs puredns bruteforce using the configured subdomain wordlist.
// Writes staging file: inputs/resolved.brute.txt
//
// SUBD-02: This task independently gates on resolver file health in Run()
// (not only in Enabled()) because the Scheduler never calls Enabled().
type SubBruteTask struct{}

func (SubBruteTask) Name() string        { return "subdomains.brute" }
func (SubBruteTask) Module() string      { return "subdomains" }
func (SubBruteTask) DependsOn() []string { return nil }

func (SubBruteTask) Description() string {
	return "Subdomain brute-force via puredns with wordlist (SUBD-02 resolver gate in Run)"
}

// Enabled returns false when brute is config-disabled. This gates the command
// layer's filterByModuleAndEnabled pass (which runs before Scheduler dispatch).
// NOTE: Scheduler.runOne does NOT call Enabled(); runtime guards must be in Run().
func (SubBruteTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Brute.Enabled
}

// Run executes puredns bruteforce with SUBD-02 resolver health gate.
//
// Gate order:
//  1. Count resolver file lines. If < MinResolvers → StatusSkipped + structured log.
//  2. Select wordlist (big wordlist when cfg.Advanced.Deep; standard otherwise).
//  3. Run puredns bruteforce via Stream (XCUT-09 heartbeat).
//  4. Write results to inputs/resolved.brute.txt.
func (SubBruteTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "puredns"
	cfg := app.Cfg

	// SUBD-02: in-Run() resolver health gate (Scheduler never calls Enabled()).
	minResolvers := cfg.Subdomains.Brute.MinResolvers
	resolverPath := cfg.Paths.Resolvers

	count, readErr := countResolverLines(resolverPath)
	if readErr != nil || count < minResolvers {
		if app.Log != nil {
			app.Log.Warn("brute_skipped_resolver_gate",
				"event", "brute_skipped_resolver_gate",
				"resolver_file", resolverPath,
				"count", count,
				"min", minResolvers,
			)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Select wordlist based on deep mode.
	wordlistPath := cfg.Paths.SubsWordlist
	if cfg.Advanced.Deep && cfg.Paths.SubsWordlistBig != "" {
		wordlistPath = cfg.Paths.SubsWordlistBig
	}

	args := []string{
		"bruteforce", wordlistPath,
		"-d", app.Target.Domain,
		"-r", resolverPath,
		"--quiet",
	}
	if cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit > 0 {
		args = append(args, "--wildcard-tests",
			fmt.Sprintf("%d", cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit))
	}

	// Stream for XCUT-09 heartbeat.
	ch, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("puredns bruteforce: Stream failed: %w", err)
	}

	var lines []string
	for ev := range ch {
		if ev.IsErr {
			continue
		}
		line := strings.ToLower(strings.TrimSpace(string(ev.Line)))
		if line != "" {
			lines = append(lines, line)
		}
	}

	stagingPath, writeErr := writeResolvedStagingFile(app, "brute", lines)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"brute_candidates": len(lines)},
	}, nil
}

// -------------------------------------------------------------------------
// init() — self-registration (staging contract doc.go)
// -------------------------------------------------------------------------

func init() { task.Register(SubResolversHealthTask{}) }
func init() { task.Register(SubBruteTask{}) }
