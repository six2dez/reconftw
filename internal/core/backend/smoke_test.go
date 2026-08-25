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

	// NOTE: this list is EXIT-CODE-INDEPENDENT and is shared with
	// backend_realtools_test.go, which probes some tools with `--help`. Only add a
	// phrase here if a tool printing its own documentation could never contain it.
	// Phrases a help text can legitimately contain belong in
	// semanticRejectionSentinels, which additionally requires a non-zero exit.
}

// semanticRejectionSentinels are rejections the PARSER ACCEPTED — the option
// validation that runs after parsing. They count as failures ONLY when the tool
// also exited non-zero.
//
// This class is what the sentinel list above was blind to, and it is the class
// that actually shipped — twice, in one live run:
//
//	puredns  "-rt <path>"      → pflag binds the REAL shorthand "-r" to the value
//	                             "t", parses cleanly, dies opening a file "t".
//	tlsx     "-san -cn -re D"  → "-re" is -revoked, a boolean probe, not a regex
//	                             filter, so tlsx refuses the COMBINATION with
//	                             cause="san or cn flag cannot be used with other
//	                             probes".
//
// The exit-code condition is load-bearing, not caution. "cannot be used with"
// first shipped unconditional and immediately produced a false positive:
// misconfig-mapper's own --help documents "This flag cannot be used with
// -permutations", so probing it with --help "failed" while the tool was fine.
// A tool printing documentation exits 0; a tool refusing to start does not.
var semanticRejectionSentinels = []string{
	"unable to load public resolvers",
	"unable to load trusted resolvers",
	"unable to load resolvers",
	"cannot be used with",
	"could not validate options",
	"invalid value",
	"requires at least",
	"mutually exclusive",
	"is not a valid",
}

func TestRealToolArgVectors(t *testing.T) {
	// Skip accounting: every probe reports its outcome so the run can say what it
	// did NOT verify. See realtools_census_test.go.
	census := newProbeCensus()
	defer reportRealtoolsCensus(t, "TestRealToolArgVectors", census, smokeKnownAbsent)

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
	// The probe table lives in argvector_probes_test.go, WITHOUT a build tag, so
	// the hermetic drift detector can read the same entries this probe executes.
	// While it lived here, behind //go:build realtools, nothing untagged could
	// compare it against the Tasks it claims to mirror.
	probes := subdomainWebProbes
	// NOTE (DoD-1): 23 Phase-5 tools covered above + nomore403/JSA repo-clone probes below.
	// Do not add --help probes — they bypass flag parsing.

	for _, p := range probes {
		p := p
		label := p.name + " " + strings.Join(p.args, " ")
		t.Run(label, func(t *testing.T) {
			binPath, err := exec.LookPath(p.name)
			if err != nil {
				census.recordAbsent(p.name)
				t.Logf("SKIP: binary %q not on PATH — NOT a pass: this arg vector was not verified", p.name)
				t.Skipf("binary %q not on PATH — skipping (counted in REALTOOLS_CENSUS)", p.name)
				return
			}
			census.recordPresent(p.name)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binPath, sub(p.args)...)
			if p.stdin {
				cmd.Stdin = strings.NewReader("")
			}
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			runErr := cmd.Run() // exit code alone is NOT the failure condition — see below.

			combined := strings.ToLower(out.String())
			for _, sentinel := range usageSentinels {
				if strings.Contains(combined, sentinel) {
					t.Errorf("%s rejected its real arg vector (sentinel %q):\n  args: %v\n  output:\n%s",
						p.name, sentinel, sub(p.args), out.String())
					return
				}
			}

			// Semantic rejections: parser accepted, option validation refused.
			// Gated on a non-zero exit so a tool's own help text cannot trip them.
			if runErr != nil {
				for _, sentinel := range semanticRejectionSentinels {
					if strings.Contains(combined, sentinel) {
						t.Errorf("%s was ACCEPTED by the parser then refused to start (%q):\n"+
							"  args: %v\n  output:\n%s", p.name, sentinel, sub(p.args), out.String())
						return
					}
				}
			}

			// FATAL-LEVEL REJECTION, whatever the wording.
			//
			// The sentinel list can only ever name rejections someone already knew
			// to look for, and both bugs this test missed were phrased in ways
			// nobody had anticipated. projectdiscovery's goflags prints option
			// validation failures at [FTL] and exits non-zero; that pairing —
			// fatal-level diagnostic AND non-zero exit — means the tool refused to
			// start, which is exactly what this probe exists to detect. A tool that
			// merely finds nothing exits non-zero WITHOUT an [FTL] line, so the
			// benign case this test was careful to tolerate stays tolerated.
			if runErr != nil && (strings.Contains(combined, "[ftl]") || strings.Contains(combined, "fatal")) {
				t.Errorf("%s exited non-zero with a FATAL diagnostic — it refused to start:\n"+
					"  args: %v\n  output:\n%s", p.name, sub(p.args), out.String())
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
				t.Logf("SKIP: %s not found in candidate tools dirs %v — NOT a pass", rp.name, toolsDirCandidates)
				census.recordAbsent(rp.name)
				t.Skipf("SKIP: %s not found at expected path — NOT a pass (counted in REALTOOLS_CENSUS)", rp.name)
				return
			}
			census.recordPresent(rp.name)

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
