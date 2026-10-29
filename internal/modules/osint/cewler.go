// cewler.go — CewlerTask: custom wordlist generation via cewler (OSINT-14).
//
// CewlerTask runs cewler over the discovered web hosts (v1 modules/web.sh:2754,
// password_dict generation: cewler -d <depth> -m <minlen> -l -o <out> <target>)
// to crawl each host and harvest target-specific words into a custom wordlist.
//
// THE ARTEFACT IS THE WORDLIST: cewler's product is the aggregated wordlist
// itself, written as the single-writer human file osint/cewler_wordlist.txt — NOT
// a findings record. A single informational OSINTFindingRecord noting the wordlist
// size is emitted so the run is visible in the findings stream; the words
// themselves are never findings.
//
// OPPORTUNISTIC ENRICHMENT: cewler is a v1 web.sh function (host-corpus
// seeded). It reads the discovered hosts from the workspace artefacts
// (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present. When NO workspace
// hosts exist it logs an Info note and returns StatusSkipped — it NEVER fails or
// bootstraps subs/web (best_effort). Hosts are scope-filtered by the web stage.
//
// SEEDING: no DependsOn edges — the workspace-host enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (ARCH-09): best_effort.
package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/v5/internal/core/appctx"
	"github.com/six2dez/reconftw/v5/internal/core/config"
	"github.com/six2dez/reconftw/v5/internal/core/task"
)

// cewler v1 conservative defaults (web.sh:2768-2787): cap targets, crawl depth 1,
// min word length 5 (conservative caps).
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

// DependsOn returns nil — the workspace-host enrichment is OPPORTUNISTIC,
// not a DAG edge.
func (t *CewlerTask) DependsOn() []string { return nil }

// Run executes cewler over the workspace hosts and writes the aggregated wordlist.
//
// Steps:
//  1. read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     absent → log Info + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Loop cewler per host (LITERAL web.sh:2782 arg vector); aggregate words.
//  3. Write osint/cewler_wordlist.txt (single-writer artefact).
//  4. Emit ONE informational size record; write inputs/findings.cewler.jsonl.
func (t *CewlerTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: opportunistic host read.
	hosts := readWorkspaceHosts(app.Target.WorkDir)
	if len(hosts) == 0 {
		// log-skip when absent — best_effort, NOT an error/bootstrap.
		app.Log.Info("osint.cewler: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — skipping")
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
		hosts = hosts[:cewlerMaxTargets] // conservative cap
	}

	// Step 2: loop cewler per host, aggregating words into a deduped set.
	wordSet := make(map[string]struct{})
	partFile := filepath.Join(inputsDir, "cewler.part.txt")
	// cewlerRan records whether AT LEAST ONE host was actually crawled. An absent
	// cewler means this task observed nothing and must not clear a previous run's
	// staging (did-not-run rule — see writeOSINTStaging). A cancelled loop is
	// covered by the same flag when it fires before the first successful crawl.
	cewlerRan := false
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
			app.Log.Debug("osint.cewler: cewler run failed (best_effort)", "host", host, "err", err)
			continue
		}
		cewlerRan = true
		if data, rErr := os.ReadFile(partFile); rErr == nil { //nolint:gosec // within WorkDir
			for _, w := range splitNonEmptyLines(data) {
				if len(w) >= cewlerMinLength {
					wordSet[w] = struct{}{}
				}
			}
		}
		_ = os.Remove(partFile) //nolint:errcheck // best_effort cleanup between hosts
	}

	// Step 3: write the aggregated wordlist (single-writer artefact).
	words := make([]string, 0, len(wordSet))
	for w := range wordSet {
		words = append(words, w)
	}
	sort.Strings(words)
	wordlistFile := filepath.Join(osintDir, "cewler_wordlist.txt")
	if len(words) > 0 {
		if wErr := os.WriteFile(wordlistFile,
			[]byte(strings.Join(words, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
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
	// Run isolation: a run that crawled no word REMOVES the staging file rather than
	// republishing the previous run's wordlist-size record.
	if cewlerRan {
		writeOSINTStaging(app, inputsDir, "findings.cewler.jsonl", records)
	} else {
		app.Log.Debug("osint.cewler: cewler did not run — staging preserved (did-not-run rule)")
	}

	app.Log.Info("osint.cewler: completed", "words", len(words), "hosts_scanned", len(hosts))
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"words": len(words), "hosts_scanned": len(hosts)},
	}, nil
}

// init self-registers CewlerTask with the Default task registry.
func init() { task.Register(&CewlerTask{}) }
