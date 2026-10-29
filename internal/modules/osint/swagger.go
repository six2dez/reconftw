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
// Logs report ONLY counts.
//
// OPPORTUNISTIC ENRICHMENT: SwaggerTask reads discovered hosts from the
// workspace artefacts (artefacts/hosts.jsonl or artefacts/urls.jsonl) IF present,
// looping sj per host/URL (graphql.go per-URL pattern). When NO workspace hosts
// exist, it logs an Info note and runs the company-seeded SwaggerSpy pass only —
// it NEVER fails or bootstraps subs/web (best_effort). Workspace hosts are
// already scope-filtered by the web stage, bounding the probe set.
//
// SEEDING: root-domain-seeded — no DependsOn edges.
// FAILURE POLICY: best_effort — engine failure / empty output logs Debug
// and returns StatusDone.
package osint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// swaggerMaxHosts bounds the opportunistic per-host sj loop (conservative
// cap against attacker-influenced workspace hosts).
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

// DependsOn returns nil — Swagger scanning is root-domain-seeded. The
// workspace-host enrichment is OPPORTUNISTIC, not a DAG edge.
func (t *SwaggerTask) DependsOn() []string { return nil }

// Run executes SwaggerSpy (company-seeded) + sj (per workspace host) with
// full XCUT-07 redaction.
//
// Steps:
//  1. Derive + validate the root domain.
//  2. Run SwaggerSpy (-s <domain>); parse stdout → redacted records.
//  3. read workspace hosts (artefacts/hosts.jsonl|urls.jsonl) IF present;
//     when absent, log Info and skip the sj per-host loop (best_effort).
//  4. Loop sj per host/URL; parse output → redacted records.
//  5. Write inputs/findings.swagger.jsonl (multi-writer staging) — all redacted.
func (t *SwaggerTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		app.Log.Info("osint.swagger: no valid root domain — skipping")
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.swagger: mkdir inputs/: %w", err)
	}

	logger := app.Log
	var records []OSINTFindingRecord
	// engineRan records whether AT LEAST ONE engine invocation was dispatched.
	// If neither SwaggerSpy nor sj is installed the task observed nothing and
	// must not clear a previous run's staging (did-not-run rule — see
	// writeOSINTStaging).
	engineRan := false

	// --- Engine 1: SwaggerSpy (company/domain-seeded public leak search) -------
	// v1 arg vector (osint.sh:452): swaggerspy.py <domain>. Output may embed raw
	// secrets — parsed for non-secret locators with L2 registration, NEVER logged.
	if res, err := app.Tools.Run(ctx, "SwaggerSpy", []string{root}); err != nil {
		app.Log.Debug("osint.swagger: SwaggerSpy run failed (best_effort)", "err", err)
	} else {
		engineRan = true
		records = append(records, parseSwaggerOutput(res.Stdout, "swaggerspy", logger)...)
	}

	// --- Engine 2: sj (per workspace host, opportunistic enrichment) ------
	//
	// SCHEME-BEARING URLs, not bare hosts. sj resolves the `-u` value as a URL:
	//
	//	$ sj automate -q -u api.example.com
	//	[✗] Error: response not received.
	//	Get "api.example.com": unsupported protocol scheme ""              (exit 1)
	//	$ sj automate -q -u http://127.0.0.1:9/swagger.json
	//	Get "http://…": dial tcp 127.0.0.1:9: connect: connection refused  (accepted)
	//
	// readWorkspaceHosts returns hosts.jsonl's "host" field, which is a BARE
	// HOST — so all 100 sj invocations in the phase-16 parity run were dead
	// (a live-run finding).
	//
	// The scheme is READ, never fabricated: hosts.jsonl carries a "url" field
	// written by HTTPXTask from httpx's own JSONL output, so it records the
	// scheme httpx actually observed on that host. Concatenating a default
	// "https://" would have invented a fact — and half the time the wrong one.
	hosts, droppedNoScheme := readWorkspaceHostURLs(app.Target.WorkDir)
	if droppedNoScheme > 0 {
		app.Log.Info("osint.swagger: workspace entries without a scheme were skipped for sj",
			"dropped", droppedNoScheme,
			"reason", "sj resolves -u as a URL; a bare host yields `unsupported protocol scheme`")
	}
	if len(hosts) == 0 {
		// log-skip when absent — best_effort, NOT an error/bootstrap.
		app.Log.Info("osint.swagger: no workspace hosts (artefacts/hosts.jsonl|urls.jsonl) — running company-seeded only")
	} else {
		if len(hosts) > swaggerMaxHosts {
			hosts = hosts[:swaggerMaxHosts] // conservative cap
		}
		for _, host := range hosts {
			if ctx.Err() != nil {
				break
			}
			// v1 sj auto-analysis arg vector: sj automate -u <url>.
			res, err := app.Tools.Run(ctx, "sj", []string{"automate", "-u", host})
			if err != nil {
				app.Log.Debug("osint.swagger: sj run failed (best_effort)", "host", host, "err", err)
				continue
			}
			engineRan = true
			records = append(records, parseSwaggerOutput(res.Stdout, "sj", logger)...)
		}
	}

	// Step 5: write staging JSONL — every record is already REDACTED.
	// Run isolation: a run that found no exposed Swagger/OpenAPI document REMOVES the
	// staging file rather than republishing one that has since been secured.
	if engineRan {
		writeOSINTStaging(app, inputsDir, "findings.swagger.jsonl", records)
	} else {
		app.Log.Debug("osint.swagger: no engine ran — staging preserved (did-not-run rule)")
	}

	// XCUT-07: log ONLY the count, never the raw matches.
	app.Log.Info("osint.swagger: completed", "leaks_found", len(records), "hosts_scanned", len(hosts))
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

// readWorkspaceHosts reads discovered hosts opportunistically from the
// workspace artefacts: artefacts/hosts.jsonl first, then artefacts/urls.jsonl.
// Returns nil when neither is present (the log-skip path). Each line may be a
// plain string or a JSON object with a "host"/"url" field. Already scope-filtered
// by the web stage.
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
	for _, h := range readHostLines(filepath.Join(workDir, "artefacts", "hosts.jsonl"), "host") {
		add(h)
	}
	// 2) artefacts/urls.jsonl (host extracted from each URL)
	for _, u := range readHostLines(filepath.Join(workDir, "artefacts", "urls.jsonl"), "url") {
		add(u)
	}
	return out
}

// readHostLines reads a JSONL artefact, extracting the named field from each
// JSON object (or the raw line when it is a plain string). A missing or
// unreadable file yields nothing: these are best-effort input sources.
func readHostLines(path, field string) []string {
	var out []string
	_ = output.ForEachJSONLLine(path, 0, func(line []byte) error {
		line = bytes.TrimSpace(line)
		if line[0] == '{' {
			var rec map[string]json.RawMessage
			if err := json.Unmarshal(line, &rec); err == nil {
				if v, ok := rec[field]; ok {
					var s string
					if json.Unmarshal(v, &s) == nil && s != "" {
						out = append(out, s)
					}
				}
			}
			return nil
		}
		out = append(out, string(line))
		return nil
	})
	return out
}

// init self-registers SwaggerTask with the Default task registry.
func init() { task.Register(&SwaggerTask{}) }

// readWorkspaceHostURLs returns the workspace's SCHEME-BEARING URLs, plus the
// number of entries dropped for having no scheme.
//
// It is deliberately separate from readWorkspaceHosts, which four other Tasks
// (osint.cewler, osint.cmseek, osint.favirecon, osint.gqlspection) depend on for
// BARE HOSTS. Changing that shared function's contract to satisfy sj would have
// altered four Tasks this plan does not touch and cannot verify.
//
// Sources, in order: artefacts/hosts.jsonl "url" (written by HTTPXTask from
// httpx's own output, so the scheme is observed rather than assumed), then
// artefacts/urls.jsonl "url".
//
// A scheme-less entry is COUNTED AND DROPPED, never repaired with a default. The
// count is returned so the caller can log it: silently discarding input is how a
// coverage loss disguises itself as a clean run.
func readWorkspaceHostURLs(workDir string) (urls []string, droppedNoScheme int) {
	seen := make(map[string]struct{})
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			droppedNoScheme++
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		urls = append(urls, raw)
	}

	for _, src := range []struct{ file, field string }{
		{"hosts.jsonl", "url"},
		{"urls.jsonl", "url"},
	} {
		for _, v := range readHostLines(filepath.Join(workDir, "artefacts", src.file), src.field) {
			add(v)
		}
	}
	return urls, droppedNoScheme
}
