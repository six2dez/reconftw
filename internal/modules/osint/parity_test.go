// parity_test.go — Frozen-replay parity harness for the OSINT pipeline (D-O6, OSINT-16).
//
// Purpose: detect porting bugs by replaying recorded (or synthetic) tool output
// through v2 osint parse/classify/REDACT logic and asserting per-source behaviour
// matches v1. This is the D-O6 HARD CI gate (~0% tolerance for the deterministic
// parse/redact logic; the soft real-target category-presence gate lives in the
// DoD-2 E2E run, NOT here). Finding COUNTS are explicitly NOT gated (D-O6) —
// external-API results are non-deterministic — but the deterministic parse path
// is pinned exactly.
//
// FIXTURE NOTES:
//   - Stub fixtures (domain_info/whois, ip_info/asnmap): header starts
//     "# TODO: capture from: ..." → osintParitySkip() t.Skip()s cleanly.
//     Populate via an osint E2E lab run (D-O7).
//   - Synthetic FAKE-secret fixtures (github_leaks, github_actions, postman,
//     swagger): committed right now. Tests backed by these MUST PASS (no t.Skip).
//   - Every secret-emitting fixture uses the clearly-FAKE marker
//     "FAKE_SECRET_MARKER_AAAA" to verify XCUT-07 redaction WITHOUT committing
//     real credentials (T-07-06-01). Each parity test asserts the marker is
//     ABSENT from every parsed record AND ValueRedacted=="***" (L3 redaction).
//
// NOTE ON PACKAGE: this file uses package osint (not osint_test) to reach the
// unexported parse functions (parseTrufflehogOutput, parseGhleaksReport,
// parseGatoOutput, parsePorchPirateOutput, parseSwaggerOutput, parsePostleaksJSON).
// The package-external DAG test is in dag_test.go (package osint_test).
//
// Source: .planning/phases/07-osint-e2e/07-06-PLAN.md Task 1.
package osint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// forbiddenRaw is the synthetic secret marker embedded in every secret-emitting
// fixture. It must NEVER appear in any parsed OSINTFindingRecord (XCUT-07 / L3).
const forbiddenRaw = "FAKE_SECRET_MARKER_AAAA"

// osintParitySkip checks the first non-empty line of fixtureBytes:
//   - Empty file or "# TODO:" header → t.Skip (fixture not captured yet).
//   - Other "# "-prefixed line → return without skip (synthetic/captured).
//   - No # prefix on a non-empty line → return without skip (data file).
func osintParitySkip(t *testing.T, fixtureBytes []byte, fixturePath string) {
	t.Helper()
	if len(fixtureBytes) == 0 {
		t.Skipf("fixture not captured yet (empty file): %s", fixturePath)
	}
	scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "# TODO:") {
			t.Skipf("fixture not captured yet (stub header): %s — populate via osint E2E lab run", fixturePath)
		}
		return
	}
	t.Skipf("fixture not captured yet (all-whitespace): %s", fixturePath)
}

// osintFixturesBase returns the testdata/fixtures dir relative to this package.
func osintFixturesBase() string { return filepath.Join("testdata", "fixtures") }

// readOSINTTestFixture reads a fixture file and fatals if missing.
func readOSINTTestFixture(t *testing.T, relPath string) []byte {
	t.Helper()
	data, err := os.ReadFile(relPath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", relPath, err)
	}
	return data
}

// assertRedacted is the shared XCUT-07 redaction-proof assertion: every record
// must carry ValueRedacted=="***" and NO record's JSON may contain the raw FAKE
// secret marker. Source/Category sanity-checked against the expectation.
func assertRedacted(t *testing.T, testName string, records []OSINTFindingRecord, wantSource, wantCategory string) {
	t.Helper()
	if len(records) == 0 {
		t.Fatalf("%s: parsed 0 records from a non-empty synthetic fixture", testName)
	}
	for i, rec := range records {
		if rec.ValueRedacted != "***" {
			t.Errorf("%s: record[%d].ValueRedacted = %q; want \"***\" (XCUT-07 L3)", testName, i, rec.ValueRedacted)
		}
		if rec.Source != wantSource {
			t.Errorf("%s: record[%d].Source = %q; want %q", testName, i, rec.Source, wantSource)
		}
		if rec.Category != wantCategory {
			t.Errorf("%s: record[%d].Category = %q; want %q", testName, i, rec.Category, wantCategory)
		}
		// Belt-and-suspenders: marshal and search for the raw FAKE secret.
		recJSON, merr := json.Marshal(rec)
		if merr != nil {
			t.Errorf("%s: marshal record[%d]: %v", testName, i, merr)
			continue
		}
		if strings.Contains(string(recJSON), forbiddenRaw) {
			t.Errorf("%s: record[%d] JSON contains forbidden raw secret %q: %s",
				testName, i, forbiddenRaw, recJSON)
		}
	}
}

// -------------------------------------------------------------------------
// TestOSINTConfigDefaults — asserts REAL field names from config.go (D-O8/D-O9).
// Uses config.Defaults() — NOT a zero-value Config{} which has no defaults.
// Wrong field names here are COMPILE ERRORS (these are real struct fields).
// -------------------------------------------------------------------------

// TestOSINTConfigDefaults asserts the D-O9 default-ON master gate (the DELIBERATE
// inversion of vulns' default-OFF) plus the D-O8 conservative per-source defaults.
func TestOSINTConfigDefaults(t *testing.T) {
	cfg := config.Defaults()

	// D-O9: master gate default ON — OSINT is passive recon (map attack surface),
	// so composite `recon`/`all` (Phase 9) INCLUDES it. Matches v1 OSINT=true.
	// This is the deliberate inversion of vulns D-V7 (default off).
	if cfg.OSINT.Enabled != true {
		t.Errorf("OSINT.Enabled: got %v, want true (D-O9 master gate default ON — inverts vulns default off)", cfg.OSINT.Enabled)
	}

	// D-O8: secret-emitting GitHub leak scan on by default (key-gated at runtime).
	if cfg.OSINT.GitHub.LeaksEnabled != true {
		t.Errorf("OSINT.GitHub.LeaksEnabled: got %v, want true (D-O8 default-on, key-gated)", cfg.OSINT.GitHub.LeaksEnabled)
	}

	// D-O8: GitHub threads conservative cap (v1 GITHUB_REPOS thread default).
	if cfg.OSINT.GitHub.Threads != 5 {
		t.Errorf("OSINT.GitHub.Threads: got %v, want 5 (D-O8 conservative cap)", cfg.OSINT.GitHub.Threads)
	}

	// D-O8: Postman conservative thread cap (v1 POSTLEAKS_THREADS=10).
	if cfg.OSINT.Postman.Threads != 10 {
		t.Errorf("OSINT.Postman.Threads: got %v, want 10 (D-O8 conservative cap, v1 POSTLEAKS_THREADS=10)", cfg.OSINT.Postman.Threads)
	}

	// D-O8: secret-emitting sources default-on (key/best-effort gated).
	if cfg.OSINT.Swagger.Enabled != true {
		t.Errorf("OSINT.Swagger.Enabled: got %v, want true (D-O8 default-on)", cfg.OSINT.Swagger.Enabled)
	}
	if cfg.OSINT.Cloud.Enabled != true {
		t.Errorf("OSINT.Cloud.Enabled: got %v, want true (D-O8 default-on)", cfg.OSINT.Cloud.Enabled)
	}
	if cfg.OSINT.GitHub.ActionsAudit.Enabled != true {
		t.Errorf("OSINT.GitHub.ActionsAudit.Enabled: got %v, want true (D-O8 default-on)", cfg.OSINT.GitHub.ActionsAudit.Enabled)
	}

	// D-O8: MSFT tenant recon OFF by default (opt-in; noisier/less universal).
	if cfg.OSINT.MSFT.Enabled != false {
		t.Errorf("OSINT.MSFT.Enabled: got %v, want false (D-O8 opt-in default off)", cfg.OSINT.MSFT.Enabled)
	}

	// Failure policy: the whole osint module group is best_effort (ARCH-09).
	if cfg.Scheduler.Overrides.OSINT != "best_effort" {
		t.Errorf("Scheduler.Overrides.OSINT: got %q, want \"best_effort\" (ARCH-09 binding)", cfg.Scheduler.Overrides.OSINT)
	}

	t.Logf("TestOSINTConfigDefaults: PASS — D-O9 default-ON + D-O8 conservative caps verified")
}

// -------------------------------------------------------------------------
// TestOSINTParityTrufflehogRedact — SYNTHETIC FAKE-secret: MUST PASS (no Skip).
// Highest-secret-leak-risk source (OSINT-05). Proves XCUT-07 L3 redaction.
// -------------------------------------------------------------------------

func TestOSINTParityTrufflehogRedact(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "github_leaks", "trufflehog_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath)

	records := parseTrufflehogOutput(data, nil)
	if len(records) != 2 {
		t.Errorf("TestOSINTParityTrufflehogRedact: expected 2 records, got %d", len(records))
	}
	assertRedacted(t, "TestOSINTParityTrufflehogRedact", records, "github_leaks", "leaked-secret")

	// The verified=true entry must classify critical; verified=false → high.
	if len(records) == 2 {
		if records[0].Severity != "critical" {
			t.Errorf("TestOSINTParityTrufflehogRedact: record[0].Severity = %q; want \"critical\" (Verified=true)", records[0].Severity)
		}
		if records[1].Severity != "high" {
			t.Errorf("TestOSINTParityTrufflehogRedact: record[1].Severity = %q; want \"high\" (Verified=false)", records[1].Severity)
		}
	}

	// Empty input → nil, no panic.
	if got := parseTrufflehogOutput(nil, nil); len(got) != 0 {
		t.Errorf("TestOSINTParityTrufflehogRedact: parseTrufflehogOutput(nil) = %d, want 0", len(got))
	}
	t.Logf("TestOSINTParityTrufflehogRedact: PASS — %d records, all redacted, FAKE marker absent", len(records))
}

// -------------------------------------------------------------------------
// TestOSINTParityGhleaksRedact — SYNTHETIC FAKE-secret: MUST PASS (no Skip).
// -------------------------------------------------------------------------

func TestOSINTParityGhleaksRedact(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "github_leaks", "ghleaks_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath)

	records := parseGhleaksReport(data, nil)
	if len(records) != 2 {
		t.Errorf("TestOSINTParityGhleaksRedact: expected 2 records, got %d", len(records))
	}
	assertRedacted(t, "TestOSINTParityGhleaksRedact", records, "github_leaks", "leaked-secret")

	if got := parseGhleaksReport(nil, nil); len(got) != 0 {
		t.Errorf("TestOSINTParityGhleaksRedact: parseGhleaksReport(nil) = %d, want 0", len(got))
	}
	t.Logf("TestOSINTParityGhleaksRedact: PASS — %d records, all redacted, FAKE marker absent", len(records))
}

// -------------------------------------------------------------------------
// TestOSINTParityGatoRedact — SYNTHETIC FAKE-secret: MUST PASS (no Skip).
// OSINT-06 workflow-secret exposure. Proves XCUT-07 redaction on JSON walk.
// -------------------------------------------------------------------------

func TestOSINTParityGatoRedact(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "github_actions", "gato_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath)

	records := parseGatoOutput(data)
	if len(records) == 0 {
		t.Fatal("TestOSINTParityGatoRedact: parsed 0 records — the fixture embeds secret/runner/artifact keys that MUST classify")
	}
	assertRedacted(t, "TestOSINTParityGatoRedact", records, "github_actions", "workflow-secret-exposure")

	if got := parseGatoOutput(nil); len(got) != 0 {
		t.Errorf("TestOSINTParityGatoRedact: parseGatoOutput(nil) = %d, want 0", len(got))
	}
	t.Logf("TestOSINTParityGatoRedact: PASS — %d records, all redacted, FAKE marker absent", len(records))
}

// -------------------------------------------------------------------------
// TestOSINTParityPostmanRedact — SYNTHETIC FAKE-secret: MUST PASS (no Skip).
// OSINT-08 Postman leak. Proves the URL-locator-only / secret-dropped contract.
// -------------------------------------------------------------------------

func TestOSINTParityPostmanRedact(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "postman", "porchpirate_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath)

	records := parsePorchPirateOutput(data, nil)
	if len(records) != 2 {
		t.Errorf("TestOSINTParityPostmanRedact: expected 2 records, got %d", len(records))
	}
	assertRedacted(t, "TestOSINTParityPostmanRedact", records, "postman", "postman-leak")

	// The locator MUST be the URL only — never the secret token.
	for i, rec := range records {
		if !strings.HasPrefix(rec.PoCRedacted, "https://www.postman.com/") {
			t.Errorf("TestOSINTParityPostmanRedact: record[%d].PoCRedacted = %q; want a postman.com URL locator", i, rec.PoCRedacted)
		}
	}
	t.Logf("TestOSINTParityPostmanRedact: PASS — %d records, URL-only locators, FAKE marker absent", len(records))
}

// -------------------------------------------------------------------------
// TestOSINTParitySwaggerRedact — SYNTHETIC FAKE-secret: MUST PASS (no Skip).
// OSINT-09 Swagger/OpenAPI leak. Proves the URL-locator-only contract.
// -------------------------------------------------------------------------

func TestOSINTParitySwaggerRedact(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "swagger", "swagger_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath)

	records := parseSwaggerOutput(data, "swaggerspy", nil)
	if len(records) != 2 {
		t.Errorf("TestOSINTParitySwaggerRedact: expected 2 records, got %d", len(records))
	}
	assertRedacted(t, "TestOSINTParitySwaggerRedact", records, "swagger", "swagger-leak")

	// The locator carries "<engine> <url>" — never the secret token.
	for i, rec := range records {
		if !strings.Contains(rec.PoCRedacted, "https://api.example.com/") {
			t.Errorf("TestOSINTParitySwaggerRedact: record[%d].PoCRedacted = %q; want a spec URL locator", i, rec.PoCRedacted)
		}
	}
	t.Logf("TestOSINTParitySwaggerRedact: PASS — %d records, URL-only locators, FAKE marker absent", len(records))
}

// -------------------------------------------------------------------------
// TestOSINTParityWhois — stub-backed: skips until lab fixture captured (D-O7).
// Demonstrates the logged-clean-skip path for a non-secret source.
// -------------------------------------------------------------------------

func TestOSINTParityWhois(t *testing.T) {
	fixturePath := filepath.Join(osintFixturesBase(), "domain_info", "whois_fixture.txt")
	data := readOSINTTestFixture(t, fixturePath)
	osintParitySkip(t, data, fixturePath) // stub → t.Skip cleanly
	t.Logf("TestOSINTParityWhois: fixture present (%d bytes) — parse assertions would run here", len(data))
}
