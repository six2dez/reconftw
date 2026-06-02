package js

import (
	"testing"
)

func TestExtractSecrets(t *testing.T) {
	t.Run("empty input returns empty non-nil slice", func(t *testing.T) {
		got, err := ExtractSecrets(nil, "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil slice, got nil")
		}
		if len(got) != 0 {
			t.Fatalf("expected 0 records, got %d", len(got))
		}
	})

	t.Run("empty byte slice returns empty non-nil slice", func(t *testing.T) {
		got, err := ExtractSecrets([]byte{}, "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected 0 records, got %d", len(got))
		}
	})

	t.Run("well-formed jsluice secret JSONL returns redacted record", func(t *testing.T) {
		// This is the exact format produced by jsluice secrets -j
		// CRITICAL: uses "filename" not "url" for the source path.
		input := `{"kind":"AWS_ACCESS_KEY","value":"AKIAIOSFODNN7EXAMPLE","filename":"/tmp/sourcemaps/app.js","severity":"high"}`
		got, err := ExtractSecrets([]byte(input), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 record, got %d", len(got))
		}

		rec := got[0]

		// XCUT-07: Redacted MUST be "***", NEVER the raw value.
		if rec.Redacted != "***" {
			t.Errorf("Redacted = %q, want \"***\" (XCUT-07 violation)", rec.Redacted)
		}

		// Verify raw value is NOT present in ANY field.
		rawValue := "AKIAIOSFODNN7EXAMPLE"
		if rec.URL == rawValue || rec.Type == rawValue || rec.Severity == rawValue || rec.Redacted == rawValue {
			t.Errorf("raw secret value %q found in SecretRecord fields (XCUT-07 violation)", rawValue)
		}

		// Verify filename field is mapped to URL.
		if rec.URL != "/tmp/sourcemaps/app.js" {
			t.Errorf("URL = %q, want %q (CRITICAL: must use 'filename' field, not 'url')", rec.URL, "/tmp/sourcemaps/app.js")
		}

		// Verify type is mapped from "kind".
		if rec.Type != "AWS_ACCESS_KEY" {
			t.Errorf("Type = %q, want %q", rec.Type, "AWS_ACCESS_KEY")
		}

		// Verify severity.
		if rec.Severity != "high" {
			t.Errorf("Severity = %q, want %q", rec.Severity, "high")
		}
	})

	t.Run("jsluice secret with url field (not filename) — url field is ignored", func(t *testing.T) {
		// Confirms that "url" field is NOT used (CRITICAL assumption A6).
		// If jsluice uses "url" instead of "filename", URL field will be empty —
		// that is expected behavior per the RESEARCH §A6 assumption.
		input := `{"kind":"API_KEY","value":"secret123","url":"https://example.com/app.js","severity":"medium"}`
		got, err := ExtractSecrets([]byte(input), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 record, got %d", len(got))
		}
		// The "url" field is NOT mapped; URL will be empty (only "filename" is mapped).
		if got[0].URL != "" {
			t.Errorf("URL = %q, want empty string (only 'filename' field is mapped, not 'url')", got[0].URL)
		}
		// Redacted must still be "***".
		if got[0].Redacted != "***" {
			t.Errorf("Redacted = %q, want \"***\"", got[0].Redacted)
		}
	})

	t.Run("multiple JSONL lines all return Redacted='***'", func(t *testing.T) {
		input := `{"kind":"AWS_ACCESS_KEY","value":"AKIAIOSFODNN7EXAMPLE","filename":"/app.js","severity":"high"}
{"kind":"PRIVATE_KEY","value":"-----BEGIN RSA PRIVATE KEY-----","filename":"/vendor.js","severity":"critical"}
{"kind":"GITHUB_TOKEN","value":"ghp_xxxxxxxxxxxxxxxxxxxx","filename":"/bundle.js","severity":"medium"}`
		got, err := ExtractSecrets([]byte(input), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 records, got %d", len(got))
		}
		rawValues := []string{"AKIAIOSFODNN7EXAMPLE", "-----BEGIN RSA PRIVATE KEY-----", "ghp_xxxxxxxxxxxxxxxxxxxx"}
		for i, rec := range got {
			if rec.Redacted != "***" {
				t.Errorf("record[%d].Redacted = %q, want \"***\" (XCUT-07 violation)", i, rec.Redacted)
			}
			// Ensure raw value is not present in any field.
			for _, rv := range rawValues {
				if rec.URL == rv || rec.Type == rv || rec.Severity == rv || rec.Redacted == rv {
					t.Errorf("record[%d]: raw value %q leaked into SecretRecord (XCUT-07 violation)", i, rv)
				}
			}
		}
	})

	t.Run("malformed JSON lines are skipped", func(t *testing.T) {
		input := `{"kind":"AWS_ACCESS_KEY","value":"AKIA123","filename":"/app.js","severity":"high"}
not-valid-json
{"kind":"API_KEY","value":"token456","filename":"/vendor.js","severity":"low"}`
		got, err := ExtractSecrets([]byte(input), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 records (1 malformed skipped), got %d", len(got))
		}
	})

	t.Run("blank lines between JSONL records are skipped", func(t *testing.T) {
		input := `{"kind":"AWS_ACCESS_KEY","value":"AKIA123","filename":"/app.js","severity":"high"}

{"kind":"API_KEY","value":"token456","filename":"/vendor.js","severity":"low"}
`
		got, err := ExtractSecrets([]byte(input), "example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 records, got %d", len(got))
		}
	})

	t.Run("existing Extract function is unaffected", func(t *testing.T) {
		// D-W3: ensure secrets.go addition does not break existing js.Extract.
		jsluiceURLOutput := `{"url":"https://api.example.com/v1","kind":"URL"}
{"url":"https://other.example.com/js","kind":"URL"}`
		results, err := Extract([]byte(jsluiceURLOutput), "example.com")
		if err != nil {
			t.Fatalf("Extract: unexpected error: %v", err)
		}
		if len(results) == 0 {
			t.Fatal("Extract: expected results, got empty (D-W3 regression)")
		}
	})
}
