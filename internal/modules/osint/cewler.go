// cewler.go — CewlerTask: custom wordlist generation via cewler (OSINT-14).
//
// CewlerTask runs cewler over the discovered web hosts (v1 modules/web.sh:2754,
// password_dict generation: cewler -d <depth> -m <minlen> -l -o <out> <target>)
// to crawl each host and harvest target-specific words into a custom wordlist.
//
// THE ARTEFACT IS THE WORDLIST (D-O5): cewler's product is the aggregated wordlist
// itself, written as the single-writer human file osint/cewler_wordlist.txt — NOT
// a findings record. A single informational OSINTFindingRecord noting the wordlist
// size is emitted so the run is visible in the findings stream; the words
// themselves are never findings.
//
// OPPORTUNISTIC ENRICHMENT (D-O2): cewler is a v1 web.sh function (host-corpus
// seeded). It reads the discovered hosts from the workspace artefacts
// (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present. When NO workspace
// hosts exist it logs an Info note and returns StatusSkipped — it NEVER fails or
// bootstraps subs/web (best_effort, D-O1/D-O2). Hosts are scope-filtered by Phase 5.
//
// SEEDING (D-O1): no DependsOn edges — the workspace-host enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 2.
package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// cewler v1 conservative defaults (web.sh:2768-2787): cap targets, crawl depth 1,
// min word length 5 (D-O8 conservative caps).
const (
	cewlerMaxTargets = 50
	cewlerDepth      = 1
	cewlerMinLength  = 5
)

// CewlerTask runs cewler for OSINT-14 (custom wordlist generation).
type CewlerTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *CewlerTask) Name() string { return "osint.cewler" }

// Module returns the owning module group.
func (t *CewlerTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *CewlerTask) Description() string {
	return "Custom wordlist generation (cewler, OSINT-14)"
}

// Enabled reports whether custom wordlist generation is configured.
func (t *CewlerTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Cewler.Enabled
}

// DependsOn returns nil — the workspace-host enrichment (D-O2) is OPPORTUNISTIC,
// not a DAG edge.
func (t *CewlerTask) DependsOn() []string { return nil }

// Run executes cewler over the workspace hosts and writes the aggregated wordlist.
//
// Steps:
//  1. D-O2: read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     absent → log Info + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Loop cewler per host (LITERAL web.sh:2782 arg vector); aggregate words.
//  3. Write osint/cewler_wordlist.txt (D-O5 single-writer artefact).
//  4. Emit ONE informational size record; write inputs/findings.cewler.jsonl.
func (t *CewlerTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: D-O2 opportunistic host read.
	hosts := readWorkspaceHosts(app.Target.WorkDir)
	if len(hosts) == 0 {
		// D-O2: log-skip when absent — best_effort, NOT an error/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.cewler: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — skipping (D-O2)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.cewler: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	if len(hosts) > cewlerMaxTargets {
		hosts = hosts[:cewlerMaxTargets] // conservative cap (D-O8)
	}

	// Step 2: loop cewler per host, aggregating words into a deduped set.
	wordSet := make(map[string]struct{})
	partFile := filepath.Join(inputsDir, "cewler.part.txt")
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		// LITERAL v1 cewler arg vector (web.sh:2782-2784):
		//   cewler -d <depth> -m <minlen> -l -o <part> <target>
		args := []string{
			"-d", fmt.Sprintf("%d", cewlerDepth),
			"-m", fmt.Sprintf("%d", cewlerMinLength),
			"-l",
			"-o", partFile,
			host,
		}
		if _, err := app.Tools.Run(ctx, "cewler", args); err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.cewler: cewler run failed (best_effort)", "host", host, "err", err)
			}
			continue
		}
		if data, rErr := os.ReadFile(partFile); rErr == nil { //nolint:gosec // within WorkDir
			for _, w := range splitNonEmptyLines(data) {
				if len(w) >= cewlerMinLength {
					wordSet[w] = struct{}{}
				}
			}
		}
		_ = os.Remove(partFile) //nolint:errcheck // best_effort cleanup between hosts
	}

	// Step 3: write the aggregated wordlist (D-O5 single-writer artefact).
	words := make([]string, 0, len(wordSet))
	for w := range wordSet {
		words = append(words, w)
	}
	sort.Strings(words)
	wordlistFile := filepath.Join(osintDir, "cewler_wordlist.txt")
	if len(words) > 0 {
		if wErr := os.WriteFile(wordlistFile,
			[]byte(strings.Join(words, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.cewler: write cewler_wordlist.txt failed", "err", wErr)
		}
	}

	// Step 4: emit ONE informational size record (the words are NOT findings).
	var records []OSINTFindingRecord
	if len(words) > 0 {
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "cewler",
			Category:    "custom-wordlist",
			PoCRedacted: fmt.Sprintf("cewler_wordlist.txt: %d words from %d hosts", len(words), len(hosts)),
		})
	}
	writeOSINTStaging(app, inputsDir, "findings.cewler.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.cewler: completed", "words", len(words), "hosts_scanned", len(hosts))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"words": len(words), "hosts_scanned": len(hosts)},
	}, nil
}

// init self-registers CewlerTask with the Default task registry.
func init() { task.Register(&CewlerTask{}) }
