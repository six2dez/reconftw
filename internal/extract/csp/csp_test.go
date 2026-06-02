package csp_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/extract/csp"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		domain string
		want   []csp.HostnameResult
	}{
		{
			name:   "empty input",
			input:  "",
			domain: "example.com",
			want:   []csp.HostnameResult{},
		},
		{
			name:   "single in-scope hostname",
			input:  "sub.example.com\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "sub.example.com", Source: "csp"},
			},
		},
		{
			name:   "apex domain in scope",
			input:  "example.com\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "example.com", Source: "csp"},
			},
		},
		{
			name:   "mixed in-scope and out-of-scope",
			input:  "api.example.com\nevil.com\ncdn.example.com\nother.org\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "api.example.com", Source: "csp"},
				{Subdomain: "cdn.example.com", Source: "csp"},
			},
		},
		{
			name:   "duplicate hostnames deduplicated",
			input:  "sub.example.com\nsub.example.com\nsub.example.com\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "sub.example.com", Source: "csp"},
			},
		},
		{
			name:   "case-insensitive normalisation",
			input:  "SUB.EXAMPLE.COM\nAPI.example.com\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "sub.example.com", Source: "csp"},
				{Subdomain: "api.example.com", Source: "csp"},
			},
		},
		{
			name:   "all out-of-scope",
			input:  "evil.com\nother.org\nattacker.net\n",
			domain: "example.com",
			want:   []csp.HostnameResult{},
		},
		{
			name:   "source field always csp",
			input:  "sub.example.com\n",
			domain: "example.com",
			want: []csp.HostnameResult{
				{Subdomain: "sub.example.com", Source: "csp"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := csp.Extract([]byte(tc.input), tc.domain)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("len(got)=%d, want %d\ngot=%+v\nwant=%+v", len(got), len(tc.want), got, tc.want)
			}
			for i := range got {
				if got[i].Subdomain != tc.want[i].Subdomain {
					t.Errorf("[%d] Subdomain: got %q, want %q", i, got[i].Subdomain, tc.want[i].Subdomain)
				}
				if got[i].Source != "csp" {
					t.Errorf("[%d] Source: got %q, want %q", i, got[i].Source, "csp")
				}
			}
		})
	}
}
