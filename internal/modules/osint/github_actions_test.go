// github_actions_test.go — XCUT-07 redaction + parse assertions for the gato
// GitHub Actions audit (OSINT-06).
//
// CRITICAL (T-07-03-01): gato output may embed live workflow secrets. These
// tests prove the raw secret VALUE is NEVER propagated to a record — every
// secret-exposure record carries ValueRedacted="***" and only a non-secret
// locator survives.
package osint

import (
	"encoding/json"
	"strings"
	"testing"
)

// FAKE_WORKFLOW_SECRET_AAAA is a clearly-synthetic secret marker (mirrors the
// vulns dalfox FAKE_XSS_MARKER convention) so we can assert redaction without
// committing a real secret value.
const fakeWorkflowSecret = "FAKE_WORKFLOW_SECRET_AAAA_ghp_deadbeefcafebabe"

func TestParseGatoOutput_RedactsSurfacedSecret(t *testing.T) {
	// Synthetic gato-shaped JSON with a secret-bearing artifact entry.
	gatoJSON := `{
		"organization": "acme",
		"repositories": [
			{
				"name": "acme/ci",
				"workflow_secrets": ["` + fakeWorkflowSecret + `"],
				"artifact_token": "` + fakeWorkflowSecret + `"
			}
		]
	}`

	records := parseGatoOutput([]byte(gatoJSON))
	if len(records) == 0 {
		t.Fatal("parseGatoOutput returned no records for secret-bearing gato JSON")
	}

	for _, rec := range records {
		// Marshal the full record and assert the raw secret never appears.
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), fakeWorkflowSecret) {
			t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into record: %s", string(b))
		}
		if rec.Category == "workflow-secret-exposure" && rec.ValueRedacted != "***" {
			t.Fatalf("expected ValueRedacted=*** for secret-exposure record, got %q", rec.ValueRedacted)
		}
	}
}

func TestParseGatoOutput_Empty(t *testing.T) {
	if recs := parseGatoOutput(nil); recs != nil {
		t.Fatalf("expected nil for empty input, got %v", recs)
	}
	if recs := parseGatoOutput([]byte("   ")); recs != nil {
		t.Fatalf("expected nil for whitespace input, got %v", recs)
	}
	if recs := parseGatoOutput([]byte("not json")); recs != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", recs)
	}
}

func TestCompanyName(t *testing.T) {
	cases := map[string]string{
		"example.com":     "example",
		"example.co.uk":   "example",
		"sub.example.com": "example",
		"acme.org":        "acme",
		"acme.com.au":     "acme",
		"single":          "single",
	}
	for in, want := range cases {
		if got := companyName(in); got != want {
			t.Errorf("companyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDorkRecords_Dedup(t *testing.T) {
	hits := []string{"https://x/1", "https://x/1", "https://x/2"}
	recs := dorkRecords(hits, "github_dorks", "github-dork")
	if len(recs) != 2 {
		t.Fatalf("expected 2 deduped records, got %d", len(recs))
	}
	for _, r := range recs {
		if r.Severity != "informational" || r.Source != "github_dorks" {
			t.Errorf("unexpected record shape: %+v", r)
		}
	}
}
