// cmseek.go — CMSeeKTask: CMS fingerprint via CMSeeK (OSINT-12).
//
// CMSeeKTask runs CMSeeK over the discovered web hosts (v1 modules/web.sh:1781,
// cmseek.py -l webs/webs_all.txt --batch -r) to fingerprint the CMS powering each
// host (WordPress, Joomla, Drupal, …). Each fingerprint becomes an informational
// OSINTFindingRecord (D-O4) — a CMS identity is OSINT context, not a vuln.
//
// OPPORTUNISTIC ENRICHMENT (D-O2): CMSeeK is a v1 web.sh function (host-corpus
// seeded). It reads the discovered hosts from the workspace artefacts
// (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present, looping per host.
// When NO workspace hosts exist it logs an Info note and returns StatusSkipped —
// it NEVER fails or bootstraps subs/web (best_effort, D-O1/D-O2). Workspace hosts
// are already scope-filtered by Phase 5, bounding the probe set (T-07-05-05).
//
// SEEDING (D-O1): no DependsOn edges — the workspace-host enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// THREAT MODEL (T-07-05-05): host list read from scope-filtered workspace
// artefacts only; per-host []string argv (never a shell string); a conservative
// host cap bounds the probe volume.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 1.
package osint

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// cmseekMaxHosts bounds the opportunistic per-host CMSeeK loop (D-O8 conservative
// cap against attacker-influenced workspace hosts — T-07-05-05).
const cmseekMaxHosts = 100

// CMSeeKTask runs CMSeeK for OSINT-12 (CMS fingerprint).
type CMSeeKTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *CMSeeKTask) Name() string { return "osint.cmseek" }

// Module returns the owning module group.
func (t *CMSeeKTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *CMSeeKTask) Description() string {
	return "CMS fingerprint (CMSeeK, OSINT-12)"
}

// Enabled reports whether CMSeeK fingerprinting is configured.
func (t *CMSeeKTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.CMS.Enabled && cfg.OSINT.CMS.CMSeeKEnabled
}

// DependsOn returns nil — the workspace-host enrichment (D-O2) is OPPORTUNISTIC,
// not a DAG edge.
func (t *CMSeeKTask) DependsOn() []string { return nil }

// Run executes CMSeeK per workspace host (D-O2 opportunistic enrichment).
//
// Steps:
//  1. D-O2: read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     absent → log Info + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Loop CMSeeK per host (web.sh:1784 arg vector -u <host> --batch -r).
//  3. Parse CMS fingerprints into informational records.
//  4. Write inputs/findings.cmseek.jsonl (multi-writer staging).
func (t *CMSeeKTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: D-O2 opportunistic host read.
	hosts := readWorkspaceHosts(app.Target.WorkDir)
	if len(hosts) == 0 {
		// D-O2: log-skip when absent — best_effort, NOT an error/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.cmseek: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — skipping (D-O2)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.cmseek: mkdir inputs/: %w", err)
	}

	if len(hosts) > cmseekMaxHosts {
		hosts = hosts[:cmseekMaxHosts] // conservative cap (D-O8)
	}

	var records []OSINTFindingRecord
	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		// v1 CMSeeK arg vector (web.sh:1784): cmseek.py -u <host> --batch -r.
		// The batch flag is non-interactive; -r reads the bundled signature DB.
		res, err := app.Tools.Run(ctx, "cmseek", []string{"-u", host, "--batch", "-r"})
		if err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.cmseek: CMSeeK run failed (best_effort)", "host", host, "err", err)
			}
			continue
		}
		if cms := parseCMSeeKOutput(res.Stdout); cms != "" {
			records = append(records, OSINTFindingRecord{
				Severity:    "informational",
				Class:       "osint",
				Source:      "cmseek",
				Category:    "cms",
				PoCRedacted: host + " [" + cms + "]", // host + CMS — non-secret OSINT value
			})
		}
	}

	// Step 4: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.cmseek.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.cmseek: completed", "findings", len(records), "hosts_scanned", len(hosts))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "hosts_scanned": len(hosts)},
	}, nil
}

// parseCMSeeKOutput extracts the detected CMS name from CMSeeK stdout. CMSeeK
// reports the result on a "CMS: <name>" / "Detected CMS: <name>" line; the v1
// pipeline reads it from cms.json's cms_id (web.sh:1810). For the streamed-stdout
// path we scan for the human marker. Returns "" when no CMS is detected.
func parseCMSeeKOutput(data []byte) string {
	if len(bytes.TrimSpace(data)) == 0 {
		return ""
	}
	for _, line := range splitNonEmptyLines(data) {
		lower := strings.ToLower(line)
		for _, marker := range []string{"detected cms:", "cms:", "cms id:", "cms_id:"} {
			if idx := strings.Index(lower, marker); idx >= 0 {
				val := strings.TrimSpace(line[idx+len(marker):])
				// Strip trailing ANSI/markers and noise.
				val = strings.Trim(val, " \t[](){}")
				if val != "" && !strings.EqualFold(val, "unknown") && !strings.EqualFold(val, "none") {
					return val
				}
			}
		}
	}
	return ""
}

// init self-registers CMSeeKTask with the Default task registry.
func init() { task.Register(&CMSeeKTask{}) }
