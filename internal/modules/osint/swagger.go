// swagger.go — SwaggerTask: Swagger/OpenAPI leak scan (OSINT-09).
//
// *** SECRET-EMITTING TASK — XCUT-07 REDACTION MANDATORY ***
//
// SwaggerTask runs BOTH Swagger/OpenAPI engines per OSINT-09 (v1 osint.sh:435
// apileaks → SwaggerSpy + sj) to surface exposed API specs that frequently embed
// auth tokens, API keys, and example credentials:
//   - SwaggerSpy — public Swagger/OpenAPI leak search seeded by the domain
//   - sj         — Swagger/OpenAPI endpoint auto-analysis per discovered host/URL
//
// XCUT-07 three-layer redaction (mirrors github_leaks.go / mantra.go:162-193):
//
//	L2 (runtime registry): every surfaced secret VALUE is fed to app.Log's
//	    Redactor (registerSecret → RegisterHandlerSecret) BEFORE any log line.
//	L3 (field-level): the OSINTFindingRecord carries ONLY the non-secret locator
//	    (the spec/endpoint URL); ValueRedacted="***".
//
// Logs report ONLY counts (T-07-04-01 mitigate).
//
// OPPORTUNISTIC ENRICHMENT (D-O2): SwaggerTask reads discovered hosts from the
// workspace artefacts (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present,
// looping sj per host/URL (graphql.go per-URL pattern). When NO workspace hosts
// exist, it logs an Info note and runs the company-seeded SwaggerSpy pass only —
// it NEVER fails or bootstraps subs/web (best_effort, D-O1). Workspace hosts are
// already scope-filtered by Phase 5, bounding the probe set (T-07-04-03).
//
// SEEDING (D-O1): root-domain-seeded — no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — engine failure / empty output logs Debug
// and returns StatusDone.
//
// Source: .planning/phases/07-osint-e2e/07-04-PLAN.md Task 2.
package osint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// swaggerMaxHosts bounds the opportunistic per-host sj loop (D-O8 conservative
// cap against attacker-influenced workspace hosts — T-07-04-03).
const swaggerMaxHosts = 100

// SwaggerTask runs SwaggerSpy + sj for OSINT-09 (secret-emitting).
type SwaggerTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SwaggerTask) Name() string { return "osint.swagger" }

// Module returns the owning module group.
func (t *SwaggerTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *SwaggerTask) Description() string {
	return "Swagger/OpenAPI leak scan (sj + SwaggerSpy, OSINT-09) — XCUT-07 redacted"
}

// Enabled reports whether Swagger leak scanning is configured.
func (t *SwaggerTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Swagger.Enabled
}

// DependsOn returns nil — Swagger scanning is root-domain-seeded (D-O1). The
// workspace-host enrichment (D-O2) is OPPORTUNISTIC, not a DAG edge.
func (t *SwaggerTask) DependsOn() []string { return nil }

// Run executes SwaggerSpy (company-seeded) + sj (per workspace host, D-O2) with
// full XCUT-07 redaction.
//
// Steps:
//  1. Derive + validate the root domain (T-07-04-04).
//  2. Run SwaggerSpy (-s <domain>); parse stdout → redacted records.
//  3. D-O2: read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     when absent, log Info and skip the sj per-host loop (best_effort).
//  4. Loop sj per host/URL; parse output → redacted records.
//  5. Write inputs/findings.swagger.jsonl (multi-writer staging) — all redacted.
func (t *SwaggerTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.swagger: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.swagger: mkdir inputs/: %w", err)
	}

	var logger *slog.Logger
	if app.Log != nil {
		logger = app.Log
	}
	var records []OSINTFindingRecord
	// engineRan records whether AT LEAST ONE engine invocation was dispatched.
	// If neither SwaggerSpy nor sj is installed the task observed nothing and
	// must not clear a previous run's staging (F3 did-not-run — see
	// writeOSINTStaging).
	engineRan := false

	// --- Engine 1: SwaggerSpy (company/domain-seeded public leak search) -------
	// v1 arg vector (osint.sh:452): swaggerspy.py <domain>. Output may embed raw
	// secrets — parsed for non-secret locators with L2 registration, NEVER logged.
	if res, err := app.Tools.Run(ctx, "SwaggerSpy", []string{root}); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.swagger: SwaggerSpy run failed (best_effort)", "err", err)
		}
	} else {
		engineRan = true
		records = append(records, parseSwaggerOutput(res.Stdout, "swaggerspy", logger)...)
	}

	// --- Engine 2: sj (per workspace host, D-O2 opportunistic enrichment) ------
	hosts := readWorkspaceHosts(app.Target.WorkDir)
	if len(hosts) == 0 {
		// D-O2: log-skip when absent — best_effort, NOT an error/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.swagger: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — running company-seeded only")
		}
	} else {
		if len(hosts) > swaggerMaxHosts {
			hosts = hosts[:swaggerMaxHosts] // conservative cap (D-O8)
		}
		for _, host := range hosts {
			if ctx.Err() != nil {
				break
			}
			// v1 sj auto-analysis arg vector: sj automate -u <host/url>.
			res, err := app.Tools.Run(ctx, "sj", []string{"automate", "-u", host})
			if err != nil {
				if app.Log != nil {
					app.Log.Debug("osint.swagger: sj run failed (best_effort)", "host", host, "err", err)
				}
				continue
			}
			engineRan = true
			records = append(records, parseSwaggerOutput(res.Stdout, "sj", logger)...)
		}
	}

	// Step 5: write staging JSONL — every record is already REDACTED.
	// F3: a run that found no exposed Swagger/OpenAPI document REMOVES the
	// staging file rather than republishing one that has since been secured.
	if engineRan {
		writeOSINTStaging(app, inputsDir, "findings.swagger.jsonl", records)
	} else if app.Log != nil {
		app.Log.Debug("osint.swagger: no engine ran — staging preserved (F3 did-not-run)")
	}

	// XCUT-07: log ONLY the count, never the raw matches.
	if app.Log != nil {
		app.Log.Info("osint.swagger: completed", "leaks_found", len(records), "hosts_scanned", len(hosts))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"leaks_found": len(records), "hosts_scanned": len(hosts)},
	}, nil
}

// parseSwaggerOutput parses SwaggerSpy/sj stdout into REDACTED records. Each
// non-empty line may carry a spec/endpoint URL alongside an embedded secret. The
// WHOLE line is registered as a potential secret (L2); only the extracted URL
// locator survives with ValueRedacted="***" (L3).
func parseSwaggerOutput(data []byte, engine string, logger *slog.Logger) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []OSINTFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// L2: register the raw line AND each non-URL secret-bearing token BEFORE
		// any log/record (registerSecretTokens scrubs the discrete value too).
		registerSecret(logger, line)
		registerSecretTokens(logger, line)
		locator := extractURLToken(line)
		if locator == "" {
			continue // no non-secret locator — register-only, do not emit
		}
		records = append(records, OSINTFindingRecord{
			Severity:      "high",
			Confidence:    "medium",
			Class:         "osint",
			Source:        "swagger",
			Category:      "swagger-leak",
			ValueRedacted: "***", // L3: raw secret NEVER propagated
			PoCRedacted:   engine + " " + locator,
		})
	}
	return records
}

// readWorkspaceHosts reads discovered hosts opportunistically (D-O2) from the
// workspace artefacts: artefacts/hosts.jsonl first, then artefacts/urls.jsonl.
// Returns nil when neither is present (the log-skip path). Each line may be a
// plain string or a JSON object with a "host"/"url" field. Already scope-filtered
// by Phase 5 (T-07-04-03).
func readWorkspaceHosts(workDir string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}

	// 1) artefacts/hosts.jsonl
	hostsPath := filepath.Join(workDir, "artefacts", "hosts.jsonl")
	if data, err := os.ReadFile(hostsPath); err == nil { //nolint:gosec // within WorkDir
		for _, h := range parseHostLines(data, "host") {
			add(h)
		}
	}
	// 2) artefacts/urls.jsonl (host extracted from each URL)
	urlsPath := filepath.Join(workDir, "artefacts", "urls.jsonl")
	if data, err := os.ReadFile(urlsPath); err == nil { //nolint:gosec // within WorkDir
		for _, u := range parseHostLines(data, "url") {
			add(u)
		}
	}
	return out
}

// parseHostLines parses a JSONL artefact, extracting the named field from each
// JSON object (or the raw line when it is a plain string).
func parseHostLines(data []byte, field string) []string {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if line[0] == '{' {
			var rec map[string]json.RawMessage
			if err := json.Unmarshal(line, &rec); err == nil {
				if v, ok := rec[field]; ok {
					var s string
					if json.Unmarshal(v, &s) == nil && s != "" {
						out = append(out, s)
						continue
					}
				}
			}
			continue
		}
		out = append(out, strings.TrimSpace(string(line)))
	}
	return out
}

// init self-registers SwaggerTask with the Default task registry.
func init() { task.Register(&SwaggerTask{}) }
