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
			// 18-06: resolution through ToolRegistry.Discover, which is what
			// production uses. A PATH-only check reports a declared clone absent
			// and the tool then goes unprobed while the Runner runs it happily.
			r := realtoolsResolve(t, p.name)
			if r.Availability != toolResolved {
				census.recordUnavailable(p.name, r)
				t.Logf("SKIP: %s %s — NOT a pass: this arg vector was not verified", p.name, r.describe())
				t.Skipf("%s unavailable — skipping (counted in REALTOOLS_CENSUS)", p.name)
				return
			}
			census.recordPresent(p.name)
			logResolution(t, r)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			probeArgs := r.argv(sub(p.args))
			cmd := exec.CommandContext(ctx, r.Path, probeArgs...)
			cmd.Dir = r.WorkDir
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
						p.name, sentinel, probeArgs, out.String())
					return
				}
			}

			// Semantic rejections: parser accepted, option validation refused.
			// Gated on a non-zero exit so a tool's own help text cannot trip them.
			if runErr != nil {
				for _, sentinel := range semanticRejectionSentinels {
					if strings.Contains(combined, sentinel) {
						t.Errorf("%s was ACCEPTED by the parser then refused to start (%q):\n"+
							"  args: %v\n  output:\n%s", p.name, sentinel, probeArgs, out.String())
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
					"  args: %v\n  output:\n%s", p.name, probeArgs, out.String())
			}
		})
	}

	// --- Repo-clone tool probes (nomore403, JSA) ---
	//
	// 18-06 DELETED THIS BLOCK'S HAND-ROLLED TOOLS-ROOT RESOLVER.
	//
	// It used to search a candidate list — $TOOLS_DIR, $HOME/Tools, $HOME/tools —
	// with os.Stat, which was a FOURTH opinion about where the tools live
	// (18-05 deleted the three production ones and this test-side one outlived
	// them by a plan). It carried a live bug of the shape this repo keeps
	// producing: the binary was located by scanning ALL candidates, but the JSA
	// script path was then rebuilt from the FIRST non-empty candidate, so a box
	// whose clone lived in the second or third would run the right interpreter
	// against a script path that does not exist. It worked only because
	// $HOME/Tools happens to be first when $TOOLS_DIR is unset.
	//
	// Both tools are declared clone rows in tools.lock as of 18-02, so the
	// registry answers all of it — root, interpreter, script prefix and working
	// directory — from the same declaration production reads. The probes now go
	// through the SAME loop as every other tool, which is why there is no
	// separate block below.
	for _, name := range []string{"nomore403", "JSA"} {
		name := name
		t.Run("repo-clone/"+name, func(t *testing.T) {
			r := realtoolsResolve(t, name)
			if r.Availability != toolResolved {
				census.recordUnavailable(name, r)
				t.Logf("SKIP: %s %s — NOT a pass", name, r.describe())
				t.Skipf("%s unavailable (counted in REALTOOLS_CENSUS)", name)
				return
			}
			census.recordPresent(name)
			logResolution(t, r)

			// The safe arg vector per tool. nomore403 reads its 4xx candidates
			// from standard input and takes no positional args (18-05 asserts the
			// same shape through the Runner); JSA takes -f <js url>.
			var args []string
			stdin := false
			switch name {
			case "nomore403":
				stdin = true
			case "JSA":
				args = []string{"-f", "https://example.com/app.js"}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			full := r.argv(args)
			cmd := exec.CommandContext(ctx, r.Path, full...)
			cmd.Dir = r.WorkDir // nomore403 declares clone_workdir (Pitfall 2)
			if stdin {
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
						name, sentinel, r.Path, full, out.String())
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
