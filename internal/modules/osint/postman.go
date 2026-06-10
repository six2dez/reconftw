// postman.go — PostmanTask: Postman public-workspace leak scan (OSINT-08).
//
// *** SECRET-EMITTING TASK — XCUT-07 REDACTION MANDATORY ***
//
// PostmanTask runs BOTH Postman leak engines per OSINT-08 (v1 osint.sh:435
// apileaks → porch-pirate + osint.sh:473 postleaksNg) seeded by the company name:
//   - porch-pirate — Postman public-library dump (`-s <domain> -l 25 --dump`)
//   - postleaksNg  — Postman public-library URL/secret search (`-k <domain> ...`)
//
// Postman public workspaces routinely embed LIVE API tokens, auth headers, and
// credentials in saved requests/environments. Every surfaced value is treated as
// a live secret. XCUT-07 three-layer redaction (mirrors github_leaks.go /
// mantra.go:162-193) is the #1 correctness requirement:
//
//	L2 (runtime registry): for every surfaced secret VALUE, registerSecret feeds
//	    app.Log's Redactor (RegisterHandlerSecret) BEFORE any log line, scrubbing
//	    the substring from ALL subsequent slog output (redactor.go:35-58).
//	L3 (field-level): the OSINTFindingRecord carries ONLY the non-secret locator
//	    (the workspace/request URL); ValueRedacted="***". The raw secret is NEVER
//	    written to a record, log, or artefact.
//
// Logs report ONLY counts, never raw matches (T-07-04-01 mitigate).
//
// SEEDING (D-O1): company/root-domain-seeded — no DependsOn edges.
// CAPS (D-O8): porch-pirate -l 25; postleaksNg uses the conservative
// cfg.OSINT.Postman.Threads default.
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

// postmanDefaultThreads is the conservative v1 postleaksNg thread default
// (POSTLEAKS_THREADS=10, reconftw.cfg:124) used when config carries no override.
const postmanDefaultThreads = 10

// PostmanTask runs porch-pirate + postleaksNg for OSINT-08 (secret-emitting).
type PostmanTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *PostmanTask) Name() string { return "osint.postman" }

// Module returns the owning module group.
func (t *PostmanTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *PostmanTask) Description() string {
	return "Postman public-workspace leak scan (porch-pirate + postleaksNg, OSINT-08) — XCUT-07 redacted"
}

// Enabled reports whether Postman leak scanning is configured.
func (t *PostmanTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Postman.Enabled
}

// DependsOn returns nil — Postman scanning is company/root-domain-seeded (D-O1).
func (t *PostmanTask) DependsOn() []string { return nil }

// postmanThreads resolves the conservative postleaksNg thread count.
func postmanThreads(cfg *config.Config) int {
	if cfg != nil && cfg.OSINT.Postman.Threads > 0 {
		return cfg.OSINT.Postman.Threads
	}
	return postmanDefaultThreads
}

// Run executes porch-pirate + postleaksNg with full XCUT-07 redaction.
//
// Steps:
//  1. Derive + validate the root domain (T-07-04-04).
//  2. Run porch-pirate (-s <domain> -l 25 --dump); parse stdout → redacted records.
//  3. Run postleaksNg (-k <domain> --output <dir> -t <threads>); parse JSON → records.
//  4. Write inputs/findings.postman.jsonl (multi-writer staging) — all redacted.
func (t *PostmanTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.postman: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.postman: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	var logger *slog.Logger
	if app.Log != nil {
		logger = app.Log
	}
	var records []OSINTFindingRecord

	// --- Engine 1: porch-pirate (Postman public-library dump) -----------------
	// v1 arg vector (osint.sh:443): -s <domain> -l 25 --dump. Output may embed
	// raw secrets — it is parsed for non-secret locators with L2 registration,
	// NEVER logged.
	ppArgs := []string{"-s", root, "-l", "25", "--dump"}
	if res, err := app.Tools.Run(ctx, "porch-pirate", ppArgs); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.postman: porch-pirate run failed (best_effort)", "err", err)
		}
	} else {
		records = append(records, parsePorchPirateOutput(res.Stdout, logger)...)
	}

	// --- Engine 2: postleaksNg (Postman public-library URL/secret search) ------
	// v1 arg vector (osint.sh:480): -k <domain> --output <dir> -t <threads>.
	// postleaksNg writes per-result JSON files under --output.
	postleaksOut := filepath.Join(osintDir, "postman_leaks_postleaksng")
	_ = os.MkdirAll(postleaksOut, 0o755) //nolint:errcheck // best_effort
	plArgs := []string{
		"-k", root,
		"--output", postleaksOut,
		"-t", fmt.Sprintf("%d", postmanThreads(app.Cfg)),
	}
	if _, err := app.Tools.Run(ctx, "postleaksNg", plArgs); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.postman: postleaksNg run failed (best_effort)", "err", err)
		}
	}
	// Parse postleaksNg per-result JSON files (best_effort — dir may be empty).
	records = append(records, parsePostleaksDir(postleaksOut, logger)...)

	// Step 4: write staging JSONL — every record is already REDACTED.
	writeOSINTStaging(app, inputsDir, "findings.postman.jsonl", records)

	// XCUT-07: log ONLY the count, never the raw matches.
	if app.Log != nil {
		app.Log.Info("osint.postman: completed", "leaks_found", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"leaks_found": len(records)},
	}, nil
}

// parsePorchPirateOutput parses porch-pirate stdout into REDACTED records. Each
// non-empty line may carry a Postman workspace/request URL alongside an embedded
// secret. We register the WHOLE line as a potential secret (L2) then emit a
// record carrying ONLY the extracted URL locator with ValueRedacted="***" (L3).
func parsePorchPirateOutput(data []byte, logger *slog.Logger) []OSINTFindingRecord {
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
		// L2: register the raw line AND each non-URL token (which may BE the
		// secret) BEFORE any log/record. registerSecretTokens scrubs the discrete
		// secret substrings so a later log of the value alone is still redacted.
		registerSecret(logger, line)
		registerSecretTokens(logger, line)
		locator := extractURLToken(line)
		if locator == "" {
			// No URL on this line — still a potential leak line; register-only,
			// do not emit a record without a non-secret locator (avoid leaking).
			continue
		}
		records = append(records, OSINTFindingRecord{
			Severity:      "high",
			Confidence:    "medium",
			Class:         "osint",
			Source:        "postman",
			Category:      "postman-leak",
			ValueRedacted: "***", // L3: raw secret NEVER propagated
			PoCRedacted:   locator,
		})
	}
	return records
}

// postleaksEntry is the subset of a postleaksNg result JSON we read. The raw
// secret fields (Secret/Token/Value) are registered (L2) then DROPPED; only the
// non-secret URL locator survives (L3).
type postleaksEntry struct {
	URL    string `json:"url"`
	Secret string `json:"secret"`
	Token  string `json:"token"`
	Value  string `json:"value"`
}

// parsePostleaksDir reads postleaksNg per-result JSON files under dir and returns
// REDACTED records. Raw secrets are registered (L2) then dropped (L3).
func parsePostleaksDir(dir string, logger *slog.Logger) []OSINTFindingRecord {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var records []OSINTFindingRecord
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		data, rErr := os.ReadFile(filepath.Join(dir, ent.Name())) //nolint:gosec // within WorkDir
		if rErr != nil {
			continue
		}
		records = append(records, parsePostleaksJSON(data, logger)...)
	}
	return records
}

// parsePostleaksJSON parses a postleaksNg result file (a JSON array, a single
// object, or a JSONL stream) into REDACTED records.
func parsePostleaksJSON(data []byte, logger *slog.Logger) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var entries []postleaksEntry
	// Try a JSON array first.
	if err := json.Unmarshal(data, &entries); err != nil {
		entries = entries[:0]
		// Try a single object.
		var single postleaksEntry
		if sErr := json.Unmarshal(data, &single); sErr == nil && hasPostleaksContent(single) {
			entries = append(entries, single)
		} else {
			// Fall back to JSONL (one object per line).
			sc := bufio.NewScanner(bytes.NewReader(data))
			sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
			for sc.Scan() {
				line := bytes.TrimSpace(sc.Bytes())
				if len(line) == 0 || line[0] != '{' {
					continue
				}
				var e postleaksEntry
				if uErr := json.Unmarshal(line, &e); uErr == nil {
					entries = append(entries, e)
				}
			}
		}
	}

	var records []OSINTFindingRecord
	for _, e := range entries {
		// L2: register every raw secret value BEFORE building/logging anything.
		registerSecret(logger, e.Secret)
		registerSecret(logger, e.Token)
		registerSecret(logger, e.Value)
		locator := strings.TrimSpace(e.URL)
		if locator == "" && !hasPostleaksContent(e) {
			continue
		}
		records = append(records, OSINTFindingRecord{
			Severity:      "high",
			Confidence:    "medium",
			Class:         "osint",
			Source:        "postman",
			Category:      "postman-leak",
			ValueRedacted: "***", // L3: raw secret NEVER propagated
			PoCRedacted:   locator,
		})
	}
	return records
}

// hasPostleaksContent reports whether a postleaksNg entry carries any field worth
// recording (URL or a secret).
func hasPostleaksContent(e postleaksEntry) bool {
	return e.URL != "" || e.Secret != "" || e.Token != "" || e.Value != ""
}

// registerSecretTokens registers each non-URL token of a free-text leak line
// with the slog Redactor (L2). porch-pirate/SwaggerSpy emit lines like
// "<url> token=<secret>" — registering the WHOLE line does not scrub a later log
// of the bare secret value (the Redactor does exact-substring replacement), so we
// register the discrete secret-bearing tokens: any non-URL word, plus the value
// half of a key=value / key:value pair. URL tokens are deliberately NOT
// registered (they are the non-secret locator we keep).
func registerSecretTokens(logger *slog.Logger, line string) {
	for _, tok := range strings.Fields(line) {
		tok = strings.Trim(tok, `"',`)
		if tok == "" || strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
			continue
		}
		// Register the whole token (e.g. "token=SECRET") and, for key=value /
		// key:value pairs, the value half on its own.
		registerSecret(logger, tok)
		for _, sep := range []string{"=", ":"} {
			if idx := strings.Index(tok, sep); idx >= 0 && idx+1 < len(tok) {
				registerSecret(logger, tok[idx+1:])
			}
		}
	}
}

// extractURLToken returns the first http(s) URL token found in a line, or "".
// This is the NON-secret locator extracted from a leak line — the surrounding
// secret material is deliberately discarded.
func extractURLToken(line string) string {
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
			return strings.Trim(tok, `"',`)
		}
	}
	return ""
}

// init self-registers PostmanTask with the Default task registry.
func init() { task.Register(&PostmanTask{}) }
