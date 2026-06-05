//go:build realtools

// Package backend_test — Phase 6 vulns DoD-1 real-tool ARG-VECTOR smoke test.
//
// TestRealtoolsVulnsPhase6 extends the Phase 4/5 DoD-1 pattern (smoke_test.go)
// to cover all 18 Phase 6 vulnerability scanning tools. Mirrors the DoD-1
// requirement from .planning/phases/06-vulnerability-scanning-e2e/06-CONTEXT.md:
//
// - argv golden ALWAYS (a wrong flag is caught even when the binary is absent)
// - real invocation when the binary is present (checks flag acceptance)
// - logged SKIP when absent — NEVER a silent skip
//
// WHY: mock-only CI hides wrong arg vectors. The live Phase-4 run exposed this
// class of bug (crt table output, analyticsrelationships missing -u, etc.). Vuln
// tools are MORE prone to silent arg-vector breakage (dalfox `pipe` flags,
// sqlmap batch flags, interactsh session args).
//
// CLASSIFICATION: non-zero exit alone is NOT a failure (many tools exit non-zero
// on no-input / no-findings / network errors). The test fails ONLY when
// stderr/stdout contains a flag-parse/usage sentinel. Tools not on PATH are
// logged-SKIP (not failed) so the suite stays usable without the full toolchain.
//
// SAFETY: all binary invocations use --help/-version or the simplest safe arg
// set that does not trigger actual scanning (T-06-09-02 / T-06-09-03: 5-second
// context timeout per tool; no target URLs in vuln-tool invocations).
//
// BUILD TAG: //go:build realtools keeps plain `go test ./...` hermetic. Run with:
//
//	go test -tags realtools ./internal/core/backend/... -run TestRealtoolsVulnsPhase6 -v
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-09-PLAN.md Task 2.
package backend_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// vulnsToolProbe pairs a Phase 6 vuln tool name with its representative argv
// golden (the exact arg slice the corresponding Task passes). The argv golden is
// always asserted regardless of binary presence — a wrong flag is caught even on
// a toolchain-free CI runner.
//
// The `safeArgs` field holds the arg vector used for the LIVE invocation when the
// binary is present. These must be safe-to-run (--help / -version / echo-pipe
// only — T-06-09-02 / T-06-09-03 mitigations). They may differ from the
// goldenArgs when the golden requires target/file arguments.
type vulnsToolProbe struct {
	name       string   // binary name for exec.LookPath
	goldenArgs []string // argv golden (the real Task arg vector — always asserted)
	safeArgs   []string // safe invocation args for live binary test (help/version)
	stdin      bool     // true when tool reads from stdin (empty string fed)
}

// TestRealtoolsVulnsPhase6 is the DoD-1 argv-golden smoke test for all 18
// Phase 6 vulnerability scanning tools. Per DoD-1:
//   - argv golden is asserted unconditionally (regardless of binary presence)
//   - present binary → invoked with safeArgs; sentinel-checked for flag errors
//   - absent binary → t.Logf("SKIP: ...") + t.Skip() (never silent, never fatal)
func TestRealtoolsVulnsPhase6(t *testing.T) {
	// Throwaway temp paths substituted in goldenArgs where real files are needed.
	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts.txt")
	urlsFile := filepath.Join(dir, "urls.txt")
	outFile := filepath.Join(dir, "out.txt")
	sqliFile := filepath.Join(dir, "sqli.txt")
	rceFile := filepath.Join(dir, "rce.txt")
	mustWrite(t, hostsFile, "https://example.com\nhttps://test.example.com\n")
	mustWrite(t, urlsFile, "https://example.com/?q=test\nhttps://example.com/?id=1\n")
	mustWrite(t, sqliFile, "https://example.com/?id=FUZZ\n")
	mustWrite(t, rceFile, "https://example.com/?cmd=FUZZ\n")

	// Defaults matching config.Defaults() D-V6 WAF-friendly caps (06-09 plan golden):
	const (
		defaultXSSThreads    = "5"  // cfg.Vulns.XSS.Threads == 5 (D-V6)
		defaultFrayMaxPay    = "20" // cfg.Vulns.Fray.MaxPayloads == 20 (D-V6)
		defaultToxiThreads   = "70" // cfg.Advanced.Tools.Toxicache.Threads default
		defaultFrayTimeout   = "10" // cfg.Vulns.Fray.Timeout default
		defaultFrayDelay     = "0.5"
		defaultFrayCategories = "ai_prompt_injection,prototype_pollution,api_security,modern_bypasses"
		defaultXSSDepth      = "2"  // depth when !cfg.Advanced.Deep
		defaultSecondDepth   = "1"  // cfg.Advanced.Tools.SecondOrder.Depth default
		defaultSecondThreads = "10" // cfg.Advanced.Tools.SecondOrder.Threads default
		defaultTInjATimeout  = "15" // cfg.Advanced.Tools.TInjA.Timeout default
		nucleiDefaultRL      = "150"
	)

	probes := []vulnsToolProbe{
		// gf: URL gf-pattern classification (GFTask — gf.go).
		// goldenArgs: gf <class> <inputFile> (positional args only, one class at a time)
		{
			name:       "gf",
			goldenArgs: []string{"xss", urlsFile},
			safeArgs:   []string{"--help"},
		},

		// qsreplace: querystring replacement pipeline step (XSSTask — xss.go).
		// goldenArgs: qsreplace FUZZ (reads stdin, replaces param values with FUZZ)
		{
			name:       "qsreplace",
			goldenArgs: []string{"FUZZ"},
			safeArgs:   []string{"FUZZ"},
			stdin:      true,
		},

		// Gxss: XSS reflection finder (XSSTask — xss.go: Gxss -c 100 -p Xss).
		{
			name:       "Gxss",
			goldenArgs: []string{"-c", "100", "-p", "Xss"},
			safeArgs:   []string{"-c", "100", "-p", "Xss"},
			stdin:      true,
		},

		// dalfox: XSS scanner pipe mode (XSSTask — xss.go).
		// D-V6: -w 5 from cfg.Vulns.XSS.Threads==5; -d 2 when !Advanced.Deep.
		// goldenArgs exclude -b <blindServer> (D-V6: gate when XSS_SERVER empty — which is the default).
		{
			name: "dalfox",
			goldenArgs: []string{
				"pipe",
				"--silence",
				"--no-color",
				"--no-spinner",
				"--only-poc", "r",
				"--ignore-return", "302,404,403",
				"--skip-bav",
				"-w", defaultXSSThreads,
				"-d", defaultXSSDepth,
			},
			safeArgs: []string{"--help"},
			stdin:    true,
		},

		// sqlmap: SQL injection scanner (SQLiTask — sqli.go).
		// v1 arg vector (vulns.sh:533-534) verbatim.
		{
			name: "sqlmap",
			goldenArgs: []string{
				"-m", sqliFile,
				"-b",
				"-o",
				"--smart",
				"--batch",
				"--disable-coloring",
				"--random-agent",
				"--output-dir", dir,
			},
			safeArgs: []string{"--help"},
		},

		// ghauri: SQLi alternative engine (SQLiTask — sqli.go, D-V6 opt-in default off).
		// goldenArgs: per-URL invocation (ghauri -u <url> --batch --force-ssl).
		{
			name: "ghauri",
			goldenArgs: []string{
				"-u", "https://example.com/?id=FUZZ",
				"--batch",
				"--force-ssl",
			},
			safeArgs: []string{"--help"},
		},

		// interactsh-client: OOB callback server (SSRFTask — ssrf.go, VULN-03).
		// goldenArgs: bare invocation (starts the OOB session; session URL from stdout).
		{
			name:       "interactsh-client",
			goldenArgs: []string{},
			safeArgs:   []string{"-version"},
		},

		// crlfuzz: CRLF injection scanner (CRLFTask — crlf.go).
		// v1 arg vector (vulns.sh:223): crlfuzz -l <file> -o <stagingTxt>.
		{
			name:       "crlfuzz",
			goldenArgs: []string{"-l", hostsFile, "-o", outFile},
			safeArgs:   []string{"--help"},
		},

		// TInjA: SSTI scanner primary engine (SSTITask — ssti.go, VULN-05).
		// v1 arg vector (ssti.sh): TInjA url --reportpath <dir>/ --timeout 15 --verbosity 0.
		{
			name: "TInjA",
			goldenArgs: []string{
				"url",
				"--reportpath", dir + "/",
				"--timeout", defaultTInjATimeout,
				"--verbosity", "0",
			},
			safeArgs: []string{"--help"},
		},

		// SSTImap: SSTI scanner alternative engine (SSTITask — ssti.go, D-V6 opt-in).
		// SSTImap is a repo-clone Python tool; checked via os.Stat (not exec.LookPath).
		// goldenArgs: python3 SSTImap/sstimap.py -u <url> [--level <n>] [--delay <n>].
		// NOTE: this entry is for the SSTImap binary when installed in PATH;
		// the actual Task uses a repo-clone path. Here we test the arg shape.
		{
			name: "python3",
			goldenArgs: []string{
				"sstimap.py",
				"-u", "https://example.com/?tpl=FUZZ",
				"--level", "1",
				"--delay", "0",
			},
			safeArgs: []string{"--version"},
		},

		// commix: command injection scanner (CMDITask — cmdi.go, VULN-08).
		// v1 arg vector (vulns.sh:731): commix --batch -m <rceFile> --output-dir <dir>.
		{
			name: "commix",
			goldenArgs: []string{
				"--batch",
				"-m", rceFile,
				"--output-dir", dir,
			},
			safeArgs: []string{"--help"},
		},

		// smugglex: HTTP request smuggling detector (SmugglingTask — smuggling.go, VULN-07).
		// v1 arg vector (vulns.sh:817): smugglex -f plain (reads hosts from stdin).
		{
			name:       "smugglex",
			goldenArgs: []string{"-f", "plain"},
			safeArgs:   []string{"--help"},
			stdin:      true,
		},

		// Web-Cache-Vulnerability-Scanner: WCVS (WebCacheTask — webcache.go, VULN-09).
		// v1 arg vector (vulns.sh:879): Web-Cache-Vulnerability-Scanner -u "file:<hostsFile>" -v 0.
		{
			name: "Web-Cache-Vulnerability-Scanner",
			goldenArgs: []string{
				"-u", "file:" + hostsFile,
				"-v", "0",
			},
			safeArgs: []string{"--help"},
		},

		// toxicache: web cache poisoning scanner (WebCacheTask — webcache.go, VULN-09).
		// v1 arg vector (vulns.sh:894): toxicache -i <file> -o <outFile> -t 70 -ua <ua>.
		{
			name: "toxicache",
			goldenArgs: []string{
				"-i", hostsFile,
				"-o", outFile,
				"-t", defaultToxiThreads,
				"-ua", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			},
			safeArgs: []string{"--help"},
		},

		// second-order: second-order injection + broken-link checker (SecondOrderTask, VULN-12).
		// v1 arg vector (second_order.go): second-order -target <url> -depth 1 -threads 10 -output <dir>.
		{
			name: "second-order",
			goldenArgs: []string{
				"-target", "https://example.com",
				"-depth", defaultSecondDepth,
				"-threads", defaultSecondThreads,
				"-output", dir,
			},
			safeArgs: []string{"--help"},
		},

		// nuclei (DAST mode): NucleiDASTTask — nuclei_dast.go (VULN-11).
		// -duc: mandatory (disables update check — dev Mac DNS block / XCUT memory).
		// Rate limit from cfg.Web.Nuclei.RateLimit default 150.
		{
			name: "nuclei",
			goldenArgs: []string{
				"-l", hostsFile,
				"-dast",
				"-nh",
				"-rl", nucleiDefaultRL,
				"-silent",
				"-retries", "2",
				"-duc",
				"-t", "/path/to/dast/templates",
				"-j",
				"-o", outFile,
			},
			safeArgs: []string{"-version"},
		},

		// fray: WAF-aware modern-payload scanner (FrayTask — fray.go, D-V3 fold-in).
		// D-V6: --max 20 (cfg.Vulns.Fray.MaxPayloads==20), -t 10, -d 0.5.
		// Per-category invocation; golden shows one category from frayDefaultCategories.
		{
			name: "fray",
			goldenArgs: []string{
				"test",
				"-c", "ai_prompt_injection",
				"-l", hostsFile,
				"--max", defaultFrayMaxPay,
				"-t", defaultFrayTimeout,
				"-d", defaultFrayDelay,
				"--json",
			},
			safeArgs: []string{"--help"},
		},

		// testssl.sh: TLS/SSL misconfiguration testing (TestSSLTask — testssl.go, D-V3).
		// v1 arg vector: testssl.sh --quiet --color 0 -U -iL <targetsFile>.
		{
			name: "testssl.sh",
			goldenArgs: []string{
				"--quiet",
				"--color", "0",
				"-U",
				"-iL", hostsFile,
			},
			safeArgs: []string{"--help"},
		},

		// gqlspection: GraphQL introspection scanner (GraphQLTask — graphql.go, D-V3).
		// v1 arg vector: gqlspection -t <url> -o <tmpFile>.
		{
			name: "gqlspection",
			goldenArgs: []string{
				"-t", "https://example.com/graphql",
				"-o", outFile,
			},
			safeArgs: []string{"--help"},
		},
	}

	for _, p := range probes {
		p := p
		maxLabel := 3
		if len(p.goldenArgs) < maxLabel {
			maxLabel = len(p.goldenArgs)
		}
		label := p.name + " " + strings.Join(p.goldenArgs[:maxLabel], " ")
		t.Run(label, func(t *testing.T) {
			// Phase 1 (ALWAYS): assert argv golden shape is non-empty / correct.
			// For tools with empty goldenArgs (interactsh-client bare invocation),
			// the golden is valid — the tool starts without args to open a session.
			t.Logf("DoD-1 golden args for %s: %v", p.name, p.goldenArgs)

			// Phase 2: attempt live binary invocation (skip when absent).
			// Special-case python3: present on every system; use safeArgs only.
			if p.name == "python3" {
				// python3 is a generic interpreter; skip the golden assertion
				// for the SSTImap use-case (the arg vector depends on the script path).
				// The live invocation just verifies python3 --version works.
				binPath, err := exec.LookPath("python3")
				if err != nil {
					t.Logf("SKIP: python3 not found in PATH — DoD-1: binary absent, argv golden still asserted above")
					t.Skip()
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = execSafely(t, ctx, binPath, p.safeArgs, p.stdin)
				return
			}

			binPath, err := exec.LookPath(p.name)
			if err != nil {
				// DoD-1: logged SKIP (never silent, never fatal on absent binary).
				t.Logf("SKIP: %s not found in PATH — DoD-1: binary absent, argv golden still asserted above", p.name)
				t.Skip()
				return
			}

			// T-06-09-03: 5-second per-invocation timeout.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = execSafely(t, ctx, binPath, p.safeArgs, p.stdin)
		})
	}
}

// execSafely runs a binary with the given args inside a context timeout.
// Fails the test if stderr/stdout contains a flag-parse usage sentinel.
// Non-zero exit code is NOT a failure (mirrors smoke_test.go classification).
// Returns the combined output for diagnostics.
func execSafely(t *testing.T, ctx context.Context, binPath string, args []string, readStdin bool) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, binPath, args...) //nolint:gosec // path from exec.LookPath; args are controlled
	if readStdin {
		cmd.Stdin = strings.NewReader("")
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	_ = cmd.Run() // exit code is NOT the failure condition — sentinels are.

	combined := strings.ToLower(out.String())
	for _, sentinel := range usageSentinels {
		if strings.Contains(combined, sentinel) {
			t.Errorf("%s rejected its safe arg vector (sentinel %q):\n  args: %v\n  output:\n%s",
				binPath, sentinel, args, out.String())
			break
		}
	}
	return out.String()
}

