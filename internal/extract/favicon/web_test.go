package favicon_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/favicon"
)

func TestExtractWeb(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		domain string
		want   []favicon.WebResult
	}{
		{
			name:   "empty input",
			input:  "",
			domain: "example.com",
			want:   []favicon.WebResult{},
		},
		{
			name:   "json array with Title-case fields",
			input:  `[{"URL":"https://example.com","Name":"Apache","Hash":"-12345"}]`,
			domain: "example.com",
			want: []favicon.WebResult{
				{URL: "https://example.com", Tech: "Apache", Hash: "-12345", Domain: "example.com"},
			},
		},
		{
			name:   "json array with lower-case fields",
			input:  `[{"url":"https://sub.example.com","name":"Nginx","hash":"67890"}]`,
			domain: "example.com",
			want: []favicon.WebResult{
				{URL: "https://sub.example.com", Tech: "Nginx", Hash: "67890", Domain: "sub.example.com"},
			},
		},
		{
			name:   "ndjson format",
			input:  `{"URL":"https://example.com","Name":"Apache","Hash":"111"}` + "\n" + `{"url":"https://api.example.com","name":"Nginx","hash":"222"}`,
			domain: "example.com",
			want: []favicon.WebResult{
				{URL: "https://example.com", Tech: "Apache", Hash: "111", Domain: "example.com"},
				{URL: "https://api.example.com", Tech: "Nginx", Hash: "222", Domain: "api.example.com"},
			},
		},
		{
			name:   "out-of-scope urls filtered",
			input:  `[{"URL":"https://evil.com","Name":"Apache","Hash":"111"},{"URL":"https://example.com","Name":"Nginx","Hash":"222"}]`,
			domain: "example.com",
			want: []favicon.WebResult{
				{URL: "https://example.com", Tech: "Nginx", Hash: "222", Domain: "example.com"},
			},
		},
		{
			name:   "records with no URL skipped",
			input:  `[{"Name":"Apache","Hash":"111"},{"URL":"https://example.com","Name":"Nginx","Hash":"222"}]`,
			domain: "example.com",
			want: []favicon.WebResult{
				{URL: "https://example.com", Tech: "Nginx", Hash: "222", Domain: "example.com"},
			},
		},
		{
			name:   "all out of scope",
			input:  `[{"URL":"https://evil.com","Name":"Apache","Hash":"111"}]`,
			domain: "example.com",
			want:   []favicon.WebResult{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := favicon.ExtractWeb([]byte(tc.input), tc.domain)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d, want %d\ngot=%+v\nwant=%+v", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i].URL != tc.want[i].URL {
					t.Errorf("[%d] URL: got %q, want %q", i, got[i].URL, tc.want[i].URL)
				}
				if got[i].Tech != tc.want[i].Tech {
					t.Errorf("[%d] Tech: got %q, want %q", i, got[i].Tech, tc.want[i].Tech)
				}
				if got[i].Hash != tc.want[i].Hash {
					t.Errorf("[%d] Hash: got %q, want %q", i, got[i].Hash, tc.want[i].Hash)
				}
				if got[i].Domain != tc.want[i].Domain {
					t.Errorf("[%d] Domain: got %q, want %q", i, got[i].Domain, tc.want[i].Domain)
				}
			}
		})
	}
}

// TestExtractUnmodified verifies the original Extract function is unchanged
// (D-W3: do not break Phase-4 callers).
func TestExtractUnmodified(t *testing.T) {
	input := "-12345 sub.example.com\n67890 other.example.com\n"
	results, err := favicon.Extract([]byte(input), "example.com")
	if err != nil {
		t.Fatalf("unexpected error from original Extract: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("original Extract returned %d results, want 2", len(results))
	}
	if results[0].Subdomain != "sub.example.com" {
		t.Errorf("Extract[0].Subdomain = %q, want %q", results[0].Subdomain, "sub.example.com")
	}
}
