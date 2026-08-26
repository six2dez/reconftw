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
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/resolvers"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Resolver health helper
// -------------------------------------------------------------------------

// countResolverLines returns the number of resolver-shaped lines in the resolver
// file. Returns 0 and an error if the file cannot be read.
//
// Delegates to resolvers.CountResolverLines so this gate and the boot-time
// acquisition in internal/core/resolvers share ONE definition of "usable". They
// used to differ: this counted any non-empty line, so an HTML error page saved
// by a mirror that answered 200 passed the gate and was handed to puredns as a
// nameserver list. Two functions answering the same question differently is how
// one of them ends up wrong.
func countResolverLines(path string) (int, error) {
	return resolvers.CountResolverLines(path)
}

// -------------------------------------------------------------------------
// SubResolversHealthTask
// -------------------------------------------------------------------------

// SubResolversHealthTask is a lightweight pre-check that verifies the DNS
// resolver file has at least cfg.Subdomains.Brute.MinResolvers non-empty lines.
//
// It distinguishes two outcomes that used to be collapsed into one SKIP:
//
//   - ZERO usable resolvers (missing file, unreadable file, empty file, empty
//     path) is a HARD ERROR. Nothing downstream can resolve DNS, and every task
//     that tries dies on `puredns -r ""` four steps later with an error that
//     names puredns rather than the resolver list. On 2026-08-20 this exact
//     shape cost a 10-hour parity run: the check DETECTED the empty path, logged
//     a WARN, marked itself SKIP, and let the run proceed to its real death. A
//     precondition check that cannot fail the run is decoration.
//   - A NON-EMPTY list that merely falls below MinResolvers stays a WARN + SKIP.
//     That is a plausible deliberate operator choice (a small trusted-only set);
//     zero resolvers never is.
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

// Run reads cfg.Paths.Resolvers and counts non-empty lines. Zero usable
// resolvers returns StatusErrored with an actionable message; a non-empty list
// below MinResolvers keeps the historical WARN + StatusSkipped.
func (SubResolversHealthTask) Run(_ context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg
	minResolvers := cfg.Subdomains.Brute.MinResolvers
	resolverPath := cfg.Paths.Resolvers

	count, err := countResolverLines(resolverPath)
	if err != nil || count == 0 {
		if app.Log != nil {
			app.Log.Error("resolver_health_check_failed",
				"resolver_file", resolverPath,
				"count", count,
				"error", errText(err),
			)
		}
		return task.Result{Status: task.StatusErrored}, errNoResolvers(resolverPath, err)
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

// errNoResolvers builds the one message the operator needs when DNS resolution
// cannot proceed. It names the file, the cause, and the fix — deliberately, so
// nobody has to read a puredns exit code to learn that a list is missing.
func errNoResolvers(path string, cause error) error {
	where := path
	if where == "" {
		where = "<unset paths.resolvers>"
	}
	if cause != nil {
		return fmt.Errorf("no usable DNS resolvers in %s: %w "+
			"(fix: run `reconftw gen-resolvers`, or point paths.resolvers at an existing list)", where, cause)
	}
	return fmt.Errorf("no usable DNS resolvers in %s: file is empty "+
		"(fix: run `reconftw gen-resolvers`, or point paths.resolvers at an existing list)", where)
}

// errText renders an optional error for a structured log field.
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// resolverListUsable reports whether path holds at least one non-empty line.
// Shared by the tasks that pass a resolver file to an external tool, so their
// guard cannot drift from the health task's definition of "usable".
func resolverListUsable(path string) bool {
	n, err := countResolverLines(path)
	return err == nil && n > 0
}

// wordlistReadable reports whether path names an existing, non-empty regular file.
// An empty path (the default when subs_wordlist is not configured) is never usable.
func wordlistReadable(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Size() > 0
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

	// Wordlist gate. Without it an unset or missing subs_wordlist ran
	// `puredns bruteforce "" -d <domain>`, which fails instantly — and because the
	// stream loop ignores tool errors the task still reported StatusDone, so brute
	// showed up as a healthy "[OK] subdomains.brute 0s" while contributing nothing.
	// Skip loudly instead, mirroring web.ffuf's "no fuzz wordlist configured".
	if !wordlistReadable(wordlistPath) {
		if app.Log != nil {
			app.Log.Info("subdomains.brute: subs wordlist missing or unreadable — skipping",
				"wordlist", wordlistPath, "deep", cfg.Advanced.Deep)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// THE DOMAIN IS POSITIONAL. `puredns bruteforce --help` (v2.1.1):
	//
	//	Usage: puredns bruteforce <wordlist> domain [flags]
	//	  -d, --domains string   text file containing domains to bruteforce
	//
	// `-d` takes a FILE. Passing the bare domain made puredns try to OPEN it:
	//
	//	$ puredns bruteforce wl.txt -d example.com -r res.txt --quiet
	//	puredns error: open example.com: no such file or directory   (exit 1)
	//	$ puredns bruteforce wl.txt example.com -r res.txt --quiet
	//	www.example.com                                              (exit 0)
	//
	// So this Task produced NOTHING for as long as the vector existed (CR-01,
	// 16-06 §6.3). v1 passes it positionally too — modules/utils.sh:1550.
	args := []string{
		"bruteforce", wordlistPath,
		app.Target.Domain,
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

	// F6 (phase 15): ACCUMULATOR shape — latch the terminal Event.Err inside the
	// loop and check it after. A puredns bruteforce killed part way through a
	// multi-million-word list yields a fraction of the resolvable hosts;
	// staging that as this run's brute result would silently shrink the
	// subdomain corpus while the task reported success.
	//
	// The Stream() error above is left as-is: it is the DISPATCH failure (the
	// binary is absent) and already returns StatusErrored here by this task's
	// own pre-existing choice — do not conflate the two branches.
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
		// Discard the partial candidate set and stage nothing.
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: tool stream ended badly: %w", toolName, streamErr)
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
