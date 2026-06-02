package waf_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/waf"
)

func TestExtractWafw00f(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		domain string
		want   []waf.WAFResult
	}{
		{
			name:   "empty input",
			input:  "",
			domain: "example.com",
			want:   []waf.WAFResult{},
		},
		{
			name:   "no WAF detected (None lines only)",
			input:  "https://example.com : (None)\nhttps://sub.example.com : (None)\n",
			domain: "example.com",
			want:   []waf.WAFResult{},
		},
		{
			name:   "single WAF detected",
			input:  "https://example.com : Cloudflare\n",
			domain: "example.com",
			want: []waf.WAFResult{
				{Host: "https://example.com", WAF: "Cloudflare", DetectedBy: "wafw00f"},
			},
		},
		{
			name:   "multiple hosts mixed results",
			input:  "https://sub.example.com : Cloudflare\nhttps://api.example.com : (None)\nhttps://other.example.com : Akamai\n",
			domain: "example.com",
			want: []waf.WAFResult{
				{Host: "https://sub.example.com", WAF: "Cloudflare", DetectedBy: "wafw00f"},
				{Host: "https://other.example.com", WAF: "Akamai", DetectedBy: "wafw00f"},
			},
		},
		{
			name:   "out-of-scope hosts filtered",
			input:  "https://evil.com : Cloudflare\nhttps://example.com : Akamai\n",
			domain: "example.com",
			want: []waf.WAFResult{
				{Host: "https://example.com", WAF: "Akamai", DetectedBy: "wafw00f"},
			},
		},
		{
			name:   "apex domain in scope",
			input:  "https://example.com : F5 BIG-IP\n",
			domain: "example.com",
			want: []waf.WAFResult{
				{Host: "https://example.com", WAF: "F5 BIG-IP", DetectedBy: "wafw00f"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := waf.ExtractWafw00f([]byte(tc.input), tc.domain)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d, want %d; got=%+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Host != tc.want[i].Host {
					t.Errorf("[%d] Host: got %q, want %q", i, got[i].Host, tc.want[i].Host)
				}
				if got[i].WAF != tc.want[i].WAF {
					t.Errorf("[%d] WAF: got %q, want %q", i, got[i].WAF, tc.want[i].WAF)
				}
				if got[i].DetectedBy != "wafw00f" {
					t.Errorf("[%d] DetectedBy: got %q, want %q", i, got[i].DetectedBy, "wafw00f")
				}
			}
		})
	}
}

func TestExtractCDNCheck(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []waf.CDNResult
	}{
		{
			name:  "empty input",
			input: "",
			want:  []waf.CDNResult{},
		},
		{
			name:  "no CDN lines",
			input: "1.2.3.4\n5.6.7.8\n",
			want:  []waf.CDNResult{},
		},
		{
			name:  "single CDN detected",
			input: "104.16.1.1 [Cloudflare]\n",
			want: []waf.CDNResult{
				{Host: "104.16.1.1", CDN: "Cloudflare", DetectedBy: "cdncheck"},
			},
		},
		{
			name:  "multiple CDN entries",
			input: "104.16.1.1 [Cloudflare]\n23.45.67.89 [Akamai]\n1.2.3.4\n",
			want: []waf.CDNResult{
				{Host: "104.16.1.1", CDN: "Cloudflare", DetectedBy: "cdncheck"},
				{Host: "23.45.67.89", CDN: "Akamai", DetectedBy: "cdncheck"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := waf.ExtractCDNCheck([]byte(tc.input), "example.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d, want %d; got=%+v", len(got), len(tc.want), got)
			}
			for i := range got {
				if got[i].Host != tc.want[i].Host {
					t.Errorf("[%d] Host: got %q, want %q", i, got[i].Host, tc.want[i].Host)
				}
				if got[i].CDN != tc.want[i].CDN {
					t.Errorf("[%d] CDN: got %q, want %q", i, got[i].CDN, tc.want[i].CDN)
				}
				if got[i].DetectedBy != "cdncheck" {
					t.Errorf("[%d] DetectedBy: got %q, want %q", i, got[i].DetectedBy, "cdncheck")
				}
			}
		})
	}
}
