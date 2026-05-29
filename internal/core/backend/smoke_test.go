//go:build realtools

// Package backend_test — real-tool ARG-VECTOR smoke test.
//
// TestRealToolArgVectors runs each subdomain tool with the EXACT argument
// vector its Task passes (against benign/throwaway inputs) and fails only when
// the tool reports a flag-parse / usage error. This catches the class of bug
// the live Phase-4 run exposed — crt's table output, analyticsrelationships'
// missing -u, s3scanner's bogus `scan` subcommand, favirecon's nonexistent -d —
// which the previous `--help`-only probe could never see (help short-circuits
// before flag parsing of the real args).
//
// WHY help-only was insufficient: `tool --help` exits 0 even when the tool's
// real invocation args are wrong, so it validates that the binary's help works,
// not that the args the Task passes are accepted. This test substitutes a safe
// target/input into each Task's real arg vector and asserts the tool does not
// reject the flags.
//
// CLASSIFICATION: a non-zero exit alone is NOT a failure (many tools exit
// non-zero on no-input / no-findings / network errors). The test fails ONLY
// when stderr/stdout contains a flag-parse/usage sentinel. Tools not on PATH
// are skipped (not failed) so the suite stays usable without the full toolchain.
//
// BUILD TAG: //go:build realtools keeps plain `go test ./...` hermetic. Run with:
//
//	go test -tags realtools ./internal/core/backend/...
//
// Source: live-run remediation (supersedes the 04-08 --help probe).
package backend_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// usageSentinels are substrings that indicate the tool REJECTED the arg vector
// (flag-parse / unknown-subcommand / required-flag errors). These — not the
// exit code — are the failure condition.
var usageSentinels = []string{
	"flag provided but not defined",
	"unknown flag",
	"unknown shorthand flag",
	"unknown command",
	"unexpected argument",
	"flag needs an argument",
	"no such flag",
	"exactly one of", // s3scanner: signals --bucket-file wasn't parsed
}

// toolProbe pairs a tool name with the representative real arg vector its Task
// uses. {F}=hosts file, {R}=resolvers file, {W}=wordlist file, {J}=JS file,
// {O}=output file path — substituted with throwaway temp paths at runtime.
type toolProbe struct {
	name string
	args []string
	// stdin, when true, feeds empty stdin (for stdin-reading tools).
	stdin bool
}

func TestRealToolArgVectors(t *testing.T) {
	dir := t.TempDir()
	hosts := filepath.Join(dir, "hosts.txt")
	resolvers := filepath.Join(dir, "resolvers.txt")
	wordlist := filepath.Join(dir, "words.txt")
	jsFile := filepath.Join(dir, "in.js")
	outFile := filepath.Join(dir, "out.json")
	mustWrite(t, hosts, "a.example.com\nb.example.com\n")
	mustWrite(t, resolvers, "8.8.8.8\n1.1.1.1\n")
	mustWrite(t, wordlist, "dev\napi\n")
	mustWrite(t, jsFile, "var u = \"https://api.example.com/v1\";\n")

	sub := func(args []string) []string {
		out := make([]string, len(args))
		rep := strings.NewReplacer("{F}", hosts, "{R}", resolvers, "{W}", wordlist, "{J}", jsFile, "{O}", outFile)
		for i, a := range args {
			out[i] = rep.Replace(a)
		}
		return out
	}

	// Each probe mirrors the real Task invocation (internal/modules/subdomains/*.go).
	probes := []toolProbe{
		{name: "subfinder", args: []string{"-all", "-d", "example.com", "-max-time", "1", "-silent"}},
		{name: "crt", args: []string{"-s", "-json", "example.com"}},
		{name: "urlfinder", args: []string{"-d", "example.com", "-silent"}},
		{name: "github-subdomains", args: []string{"-d", "example.com", "-t", "dummytoken"}},
		{name: "gitlab-subdomains", args: []string{"-d", "example.com", "-t", "dummytoken"}},
		{name: "httpx", args: []string{"-silent", "-u", "https://example.com"}},
		{name: "puredns", args: []string{"resolve", "{F}", "-r", "{R}", "--wildcard-tests", "1", "--wildcard-batch", "1", "--rate-limit", "1", "--rate-limit-trusted", "1", "-rt", "{R}", "--quiet"}},
		{name: "puredns", args: []string{"bruteforce", "{W}", "example.com", "-r", "{R}", "--quiet"}},
		{name: "tlsx", args: []string{"-l", "{F}", "-silent", "-san", "-cn", "-re", "example.com"}},
		{name: "dnsx", args: []string{"-l", "{F}", "-ns", "-resp", "-silent"}},
		{name: "gotator", args: []string{"-sub", "{F}", "-depth", "1", "-numbers", "3", "-md"}},
		{name: "regulator", args: []string{"{F}", "example.com"}},
		{name: "dnscewl", args: []string{"-f", "{F}"}},
		{name: "subwiz", args: []string{"-i", "{F}", "--no-resolve"}},
		{name: "subzy", args: []string{"run", "--targets", "{F}", "--verify-ssl", "--output", "{O}"}},
		{name: "dnstake", args: []string{"-f", "{F}", "-silent"}},
		{name: "s3scanner", args: []string{"--bucket-file", "{F}"}},
		{name: "asnmap", args: []string{"-d", "example.com", "-json", "-silent"}},
		{name: "favirecon", args: []string{"-u", "example.com", "-timeout", "5"}},
		{name: "analyticsrelationships", args: []string{"-u", "https://example.com", "--chain-mode"}},
		{name: "jsluice", args: []string{"urls", "-i", "{J}"}},
		{name: "subjs", args: []string{"-i", "-"}, stdin: true},
	}

	for _, p := range probes {
		p := p
		label := p.name + " " + strings.Join(p.args, " ")
		t.Run(label, func(t *testing.T) {
			binPath, err := exec.LookPath(p.name)
			if err != nil {
				t.Skipf("binary %q not on PATH — skipping (not a CI failure)", p.name)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binPath, sub(p.args)...)
			if p.stdin {
				cmd.Stdin = strings.NewReader("")
			}
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			_ = cmd.Run() // exit code is NOT the failure condition — sentinels are.

			combined := strings.ToLower(out.String())
			for _, sentinel := range usageSentinels {
				if strings.Contains(combined, sentinel) {
					t.Errorf("%s rejected its real arg vector (sentinel %q):\n  args: %v\n  output:\n%s",
						p.name, sentinel, sub(p.args), out.String())
					break
				}
			}
		})
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
