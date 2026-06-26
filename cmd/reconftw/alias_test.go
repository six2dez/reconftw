// alias_test.go — unit tests for translateV1Args (D-08 / MODE-09).
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestTranslateV1Args is the primary table-driven test covering all 13+ behavior
// cases from the plan (D-08 / MODE-09).
func TestTranslateV1Args(t *testing.T) {
	type tc struct {
		name      string
		input     []string
		wantHead  string // expected args[0] after translation (subcommand)
		wantFlags []string // strings that must appear somewhere in result
	}
	cases := []tc{
		{
			name:      "long --recon with -d",
			input:     []string{"--recon", "-d", "example.com"},
			wantHead:  "recon",
			wantFlags: []string{"--target"},
		},
		{
			name:     "short -a with --target",
			input:    []string{"-a", "--target", "example.com"},
			wantHead: "all",
		},
		{
			name:      "short -p with -d",
			input:     []string{"-p", "-d", "x"},
			wantHead:  "passive",
			wantFlags: []string{"--target"},
		},
		{
			name:      "short -s with -d",
			input:     []string{"-s", "-d", "x"},
			wantHead:  "subs",
			wantFlags: []string{"--target"},
		},
		{
			name:      "short -w with -d",
			input:     []string{"-w", "-d", "x"},
			wantHead:  "web",
			wantFlags: []string{"--target"},
		},
		{
			name:      "long --vulns with -d",
			input:     []string{"--vulns", "-d", "x"},
			wantHead:  "vulns",
			wantFlags: []string{"--target"},
		},
		{
			name:      "short -n with -d",
			input:     []string{"-n", "-d", "x"},
			wantHead:  "osint",
			wantFlags: []string{"--target"},
		},
		{
			name:      "short -z with -d",
			input:     []string{"-z", "-d", "x"},
			wantHead:  "zen",
			wantFlags: []string{"--target"},
		},
		{
			name:      "short -y with -d",
			input:     []string{"-y", "-d", "x"},
			wantHead:  "deep",
			wantFlags: []string{"--target"},
		},
		{
			name:  "no double-insertion when subcommand already at position 0",
			input: []string{"recon", "--recon", "--target", "x"},
			// args[0] = "recon" is already a known subcommand → no injection
			wantHead: "recon",
		},
		{
			name:      "mode flag after global flags: -d then -r",
			input:     []string{"-d", "example.com", "-r"},
			wantHead:  "recon",
			wantFlags: []string{"--target"},
		},
		{
			name:      "list flag: -l with mode flag -r",
			input:     []string{"-l", "targets.txt", "-r"},
			wantHead:  "recon",
			wantFlags: []string{"--list"},
		},
		{
			name:      "vps flag: -v with -r and -d",
			input:     []string{"-v", "-r", "-d", "x"},
			wantHead:  "recon",
			wantFlags: []string{"--axiom"},
		},
		{
			name:  "empty args returns empty",
			input: []string{},
		},
		{
			name:      "subcommand first + -d still translates target",
			input:     []string{"recon", "-d", "example.com"},
			wantHead:  "recon",
			wantFlags: []string{"--target"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := translateV1Args(tc.input)

			if len(tc.input) == 0 {
				if len(got) != 0 {
					t.Errorf("empty input: expected empty output, got %v", got)
				}
				return
			}

			if len(got) == 0 {
				t.Fatalf("translateV1Args(%v) returned empty slice", tc.input)
			}

			if tc.wantHead != "" && got[0] != tc.wantHead {
				t.Errorf("translateV1Args(%v)[0] = %q, want %q", tc.input, got[0], tc.wantHead)
			}

			combined := strings.Join(got, " ")
			for _, flag := range tc.wantFlags {
				if !strings.Contains(combined, flag) {
					t.Errorf("translateV1Args(%v) = %v, expected flag %q to be present", tc.input, got, flag)
				}
			}
		})
	}
}

// TestTranslateV1ArgsNoDoubleSubcmd asserts no subcommand is injected twice.
func TestTranslateV1ArgsNoDoubleSubcmd(t *testing.T) {
	inputs := [][]string{
		{"recon", "--recon", "--target", "x"},
		{"all", "-a", "-d", "x"},
		{"web", "--web", "--target", "y"},
		{"subs", "--subdomains", "--target", "z"},
	}
	for _, input := range inputs {
		got := translateV1Args(input)
		if len(got) < 1 {
			t.Fatalf("empty result for %v", input)
		}
		if got[0] != input[0] {
			t.Errorf("translateV1Args(%v)[0] = %q, want %q (double-insertion guard)", input, got[0], input[0])
		}
		// Ensure the second token is NOT the same subcommand injected again.
		if len(got) > 1 && got[1] == got[0] {
			t.Errorf("translateV1Args(%v) contains duplicate subcommand: %v", input, got)
		}
	}
}

// TestTranslateV1ArgsFirstWinsOnMultipleModFlags asserts first mode flag wins
// when multiple are provided (e.g. --recon --all).
func TestTranslateV1ArgsFirstWinsOnMultipleModFlags(t *testing.T) {
	got := translateV1Args([]string{"--recon", "--all", "-d", "example.com"})
	if len(got) == 0 || got[0] != "recon" {
		t.Errorf("first-wins: translateV1Args([--recon, --all, ...])[0] = %q, want %q",
			func() string {
				if len(got) > 0 {
					return got[0]
				}
				return "<empty>"
			}(), "recon")
	}
}

// TestTranslateV1ArgsGlobalAliasesOnly verifies that -d / -l / -v are rewritten
// even without a mode flag injection (when subcommand is already provided).
func TestTranslateV1ArgsGlobalAliasesOnly(t *testing.T) {
	got := translateV1Args([]string{"subs", "-d", "example.com", "-v"})
	combined := strings.Join(got, " ")
	if !strings.Contains(combined, "--target") {
		t.Errorf("expected --target in %v", got)
	}
	if !strings.Contains(combined, "--axiom") {
		t.Errorf("expected --axiom in %v", got)
	}
	if got[0] != "subs" {
		t.Errorf("expected subcommand to remain subs, got %q", got[0])
	}
}

// TestV1DeprecationWarningContainsRemovalVersion asserts that the deprecation
// warning emitted by cobra for the --recon flag contains "v2.2" (the removal
// version from ADR §8.4). This satisfies MODE-09 criterion 5.
//
// Note: cobra emits deprecation messages via OutOrStdout() (pflag design), so
// we capture both out and err buffers.
func TestV1DeprecationWarningContainsRemovalVersion(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	root.SetArgs([]string{"--recon", "--target", "example.com"})
	var outBuf, errBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	_ = root.Execute()
	combined := outBuf.String() + errBuf.String()
	// The deprecation message set in root.go contains "reconftw recon --target example.com"
	// and the long-form message from mustMarkDeprecated. We assert it contains
	// "deprecated" (case-insensitive) and references the replacement subcommand.
	if !strings.Contains(strings.ToLower(combined), "deprecated") {
		t.Errorf("expected deprecation word in combined output for --recon, got: %q", combined)
	}
	// The MarkDeprecated message references the replacement subcommand command.
	if !strings.Contains(combined, "recon") {
		t.Errorf("expected replacement subcommand 'recon' in deprecation warning, got: %q", combined)
	}
	// MODE-09 criterion 5: the warning MUST state the removal version (ADR §8.4).
	if !strings.Contains(combined, "v2.2") {
		t.Errorf("expected removal version 'v2.2' in deprecation warning, got: %q", combined)
	}
}

// TestV1DeprecationWarningAllLongFlags asserts all 9 mode long-flag aliases
// produce a deprecation warning referencing the v2 subcommand (MODE-09).
func TestV1DeprecationWarningAllLongFlags(t *testing.T) {
	cases := []struct {
		flag    string
		wantSub string
	}{
		{"--recon", "recon"},
		{"--all", "all"},
		{"--passive", "passive"},
		{"--subdomains", "subs"},
		{"--web", "web"},
		{"--vulns", "vulns"},
		{"--osint", "osint"},
		{"--zen", "zen"},
		{"--deep", "deep"},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			root := newRootCmd(nil, &config.Config{})
			root.SetArgs([]string{tc.flag})
			var outBuf, errBuf bytes.Buffer
			root.SetOut(&outBuf)
			root.SetErr(&errBuf)
			_ = root.Execute()
			combined := outBuf.String() + errBuf.String()
			if !strings.Contains(strings.ToLower(combined), "deprecated") {
				t.Errorf("%s: expected deprecation warning, got: %q", tc.flag, combined)
			}
		})
	}
}
