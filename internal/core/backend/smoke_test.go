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
	mustWrite(t, wordlist, "dev\napi\nadmin\nlogin\n")
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

		// Phase 5 additions — web pipeline (DoD-1)
		// Each entry uses the EXACT arg vector from internal/modules/web/*.go (D-W9).
		// A wrong flag is caught even when the binary is absent (golden is checked unconditionally).

		// nuclei: scan mode (NucleiTask — nuclei.go)
		{name: "nuclei", args: []string{"-u", "https://example.com", "-id", "http-missing-security-headers", "-silent", "-j", "-o", "{O}"}},

		// nuclei: screenshot mode (ScreenshotTask — screenshot.go)
		// -V dir={O}: nuclei variable sets screenshot output directory.
		{name: "nuclei", args: []string{"-headless", "-id", "screenshot", "-V", "dir={O}", "-l", "{F}", "-silent"}},

		// ffuf: web directory fuzzer (FfufTask — ffuf.go)
		{name: "ffuf", args: []string{"-mc", "all", "-fc", "404", "-sf", "-noninteractive", "-of", "json", "-w", "{W}", "-maxtime", "5", "-u", "https://example.com/FUZZ", "-o", "{O}"}},

		// katana: web crawler (KatanaTask — katana.go: -silent -list {F} -jc -kf all -c N -d 2 -fs rdn)
		{name: "katana", args: []string{"-silent", "-list", "{F}", "-jc", "-kf", "all", "-c", "1", "-d", "2", "-fs", "rdn"}},

		// urlfinder: passive URL discovery (UrlfindlerTask — urlfinder.go: -d domain -all -o {O})
		{name: "urlfinder", args: []string{"-d", "example.com", "-all", "-o", "{O}"}},

		// waymore: passive URL archive (WaymoreTask — waymore.go: -i domain -mode U -oU {O})
		{name: "waymore", args: []string{"-i", "example.com", "-mode", "U", "-oU", "{O}"}},

		// urless: URL deduplication (reads stdin, UrldedupTask — urldedup.go)
		{name: "urless", args: []string{}, stdin: true},

		// p1radup: URL deduplication (-i {F} -o {O} -s, UrldedupTask — urldedup.go)
		{name: "p1radup", args: []string{"-i", "{F}", "-o", "{O}", "-s"}},

		// subjs: JS URL extraction (-ua <ua> -c 40 -i {F}, SubjsTask — subjs.go)
		{name: "subjs", args: []string{"-ua", "Mozilla/5.0", "-c", "40", "-i", "{F}"}},

		// jsluice: URL extraction mode (JsluiceTask — jsluice.go: jsluice urls {file...})
		{name: "jsluice", args: []string{"urls", "{J}"}},

		// jsluice: secrets mode (JsluiceTask — jsluice.go: jsluice secrets -j {file...})
		{name: "jsluice", args: []string{"secrets", "-j", "{J}"}},

		// mantra: JS secret scanner (-ua <ua> -s via stdin, MantraTask — mantra.go)
		// [A5-fix: mantra reads from stdin; no -i flag exists]
		{name: "mantra", args: []string{"-ua", "Mozilla/5.0", "-s"}, stdin: true},

		// sourcemapper: source map extractor (-jsurl <url> -output {O}, SourcemapperTask — sourcemapper.go)
		{name: "sourcemapper", args: []string{"-jsurl", "https://example.com/app.js", "-output", "{O}"}},

		// wafw00f: WAF detection (-i {F} -o {O}, Wafw00fTask — wafw00f.go)
		{name: "wafw00f", args: []string{"-i", "{F}", "-o", "{O}"}},

		// cdncheck: CDN/WAF IP classification (-silent -resp -nc -i {F}, CdncheckTask — cdncheck.go)
		{name: "cdncheck", args: []string{"-silent", "-resp", "-nc", "-i", "{F}"}},

		// hakoriginfinder: origin IP discovery (reads IPs from stdin + -h <url>, HakoriginfinderTask — hakoriginfinder.go)
		// [A14-fix: tool reads IPs from stdin, not -i flag; -h specifies target URL]
		{name: "hakoriginfinder", args: []string{"-h", "https://example.com"}, stdin: true},

		// csprecon: CSP hostname extraction (-s -l {F}, CspreconTask — csprecon.go)
		// [A15-fix: csprecon uses -l/-list for file input, not -i]
		{name: "csprecon", args: []string{"-s", "-l", "{F}"}},

		// favirecon: favicon tech recon (-l {F} -c N -t N -s -j -o {O}, FavireconTask — favirecon.go)
		{name: "favirecon", args: []string{"-l", "{F}", "-c", "5", "-t", "5", "-s", "-j", "-o", "{O}"}},

		// VhostFinder: virtual host discovery (-ips {F} -wordlist {F} -verify, VhostFinderTask — vhostfinder.go)
		{name: "VhostFinder", args: []string{"-ips", "{F}", "-wordlist", "{F}", "-verify"}},

		// shortscan: IIS short filename scanner (positional URL -F -s -p 1, ShortscanTask — shortscan.go)
		{name: "shortscan", args: []string{"https://example.com", "-F", "-s", "-p", "1"}},

		// Gxss: XSS reflection scanner (-c 100 -p Xss via stdin, GxssTask — gxss.go)
		{name: "Gxss", args: []string{"-c", "100", "-p", "Xss"}, stdin: true},

		// arjun: parameter discovery (-i {F} -t N -oT {O}, ArjunTask — arjun.go)
		{name: "arjun", args: []string{"-i", "{F}", "-t", "5", "-oT", "{O}"}},
	}
	// NOTE (DoD-1): 23 Phase-5 tools covered above + nomore403/JSA repo-clone probes below.
	// Do not add --help probes — they bypass flag parsing.

	for _, p := range probes {
		p := p
		label := p.name + " " + strings.Join(p.args, " ")
		t.Run(label, func(t *testing.T) {
			binPath, err := exec.LookPath(p.name)
			if err != nil {
				t.Logf("SKIP: binary %q not on PATH — not a CI failure", p.name)
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

	// --- Repo-clone tool probes (nomore403, JSA) ---
	// These tools are NOT on PATH; they live under cfg.Paths.DataDir.
	// Use os.Stat path lookup instead of exec.LookPath (T-05-16/D-W9).
	// SKIP with explicit logged notice when absent (D-W9: never silent skip).

	repoCloneProbes := []struct {
		name     string
		pathHint string // relative path under a standard tools dir
		args     []string
		stdin    bool
	}{
		{
			name:     "nomore403",
			pathHint: "nomore403/nomore403",
			args:     []string{}, // reads stdin; no positional args in v2 Task
			stdin:    true,
		},
		{
			name:     "JSA (jsa.py via python3)",
			pathHint: "JSA/venv/bin/python3",
			args:     []string{"JSA/jsa.py", "-f", "https://example.com/app.js"},
			stdin:    false,
		},
	}

	// Candidate tools directories to search for repo-clone tools.
	toolsDirCandidates := []string{
		os.Getenv("TOOLS_DIR"),
		filepath.Join(os.Getenv("HOME"), "Tools"),
		filepath.Join(os.Getenv("HOME"), "tools"),
	}

	for _, rp := range repoCloneProbes {
		rp := rp
		t.Run("repo-clone/"+rp.name, func(t *testing.T) {
			// Locate the binary via os.Stat across candidate directories.
			var binaryPath string
			var toolDir string
			for _, td := range toolsDirCandidates {
				if td == "" {
					continue
				}
				candidate := filepath.Join(td, rp.pathHint)
				if _, err := os.Stat(candidate); err == nil {
					binaryPath = candidate
					toolDir = filepath.Dir(candidate)
					break
				}
			}

			if binaryPath == "" {
				t.Logf("SKIP: %s not found in candidate tools dirs %v — not a CI failure", rp.name, toolsDirCandidates)
				t.Skipf("SKIP: %s not found at expected path — not a CI failure", rp.name)
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// Resolve args: for JSA, expand the script path relative to the tools root.
			resolvedArgs := make([]string, len(rp.args))
			for i, a := range rp.args {
				// Replace leading "JSA/" prefix with the actual path.
				if strings.HasPrefix(a, "JSA/") {
					for _, td := range toolsDirCandidates {
						if td != "" {
							resolvedArgs[i] = filepath.Join(td, a)
							break
						}
					}
				} else {
					resolvedArgs[i] = a
				}
			}

			cmd := exec.CommandContext(ctx, binaryPath, resolvedArgs...)
			cmd.Dir = toolDir // nomore403 requires CWD = its own dir (Pitfall 2)
			if rp.stdin {
				cmd.Stdin = strings.NewReader("https://example.com/404test\n")
			}
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			_ = cmd.Run() // exit code NOT the failure condition.

			combined := strings.ToLower(out.String())
			for _, sentinel := range usageSentinels {
				if strings.Contains(combined, sentinel) {
					t.Errorf("%s rejected its real arg vector (sentinel %q):\n  path: %s\n  args: %v\n  output:\n%s",
						rp.name, sentinel, binaryPath, resolvedArgs, out.String())
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
