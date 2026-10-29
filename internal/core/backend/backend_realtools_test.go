//go:build realtools

// Package backend_test — Phase 6 vulns and Phase 7 OSINT real-tool ARG-VECTOR
// probes (Gate 13).
//
// # WHAT 21-04 CHANGED, AND WHY
//
// Until 21-04 both probes below LOGGED a goldenArgs vector and EXECUTED a
// separate safeArgs one — and 31 of the 44 safeArgs were `--help`, seven more
// `-version`. A help probe exits before flag parsing, so the only thing those
// runs proved was that the binary starts. smoke_test.go's header says exactly
// why that is not enough ("help short-circuits before flag parsing of the real
// args"), and the Phase-4 live run is the evidence: crt's table output,
// analyticsrelationships' missing -u, favirecon's nonexistent -d all sat behind
// green --help probes. The census line then counted every one of those tools as
// "present", which Gate 13 read as verified.
//
// Now each probe executes the GOLDEN vector — the shape the Task dispatches —
// with SAFE inputs:
//
//   - targets are the loopback closed port 127.0.0.1:9 (asserted closed at the
//     start of each test), as a URL where the Task passes a URL;
//   - input files are throwaway files under t.TempDir() holding loopback lines;
//   - output goes under t.TempDir(); the working directory is t.TempDir() for
//     PATH tools (WCVS and friends write reports to cwd) and the clone's own
//     directory for clone tools, exactly as the Runner does;
//   - every run gets HTTP_PROXY/HTTPS_PROXY/ALL_PROXY pointed at the same closed
//     port and the GitHub / PDCP credentials scrubbed from its environment;
//   - a short per-probe timeout.
//
// Where the golden alone would still reach the network, a HERMETICITY PIN is
// added (a resolver, proxy or disable flag the tool documents, or a global proxy
// the tool was OBSERVED to honour) and, where the pin is not itself the barrier,
// an `expect` marker must appear in the output to prove the run died at the
// barrier rather than somewhere past it. Where no such pin exists the probe is
// `presence-only`: it runs --help or nothing, is recorded separately, and the
// census line reports `argvector_verified=N presence_only=M` so a reader cannot
// mistake a help probe for a verified vector.
//
// # WHAT COUNTS AS REJECTION
//
// ANY exit status is accepted EXCEPT a usage error. Tools exit non-zero on
// refused connections, missing credentials and empty results, and all of those
// are fine. A usage error is detected per the tool's flag-parsing FAMILY (Go
// flag/goflags, pflag/cobra, argparse, optparse, clap, shell, perl, BSD whois):
// its stderr signature, and for families that use one, exit code 2 (or 64 for
// whois) together with a usage dump. The shared usageSentinels from
// smoke_test.go apply to every family.
//
// BUILD TAG: //go:build realtools keeps plain `go test ./...` hermetic. Run with:
//
//	go test -tags realtools ./internal/core/backend/... -run 'TestRealtoolsVulnsPhase6|TestRealtoolsOSINTPhase7' -v
package backend_test

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loopbackClosed is the target every golden vector is pointed at. TCP port 9
// (discard) is not bound on any default install; mustBeClosed asserts it.
const (
	loopbackClosed = "127.0.0.1:9"
	loopbackURL    = "http://" + loopbackClosed
	loopbackProxy  = loopbackURL
)

// probeKind partitions what a probe PROVES.
type probeKind string

const (
	// probeArgVector executes the golden arg vector (safe inputs, pins) and
	// fails on a usage error. This is verification.
	probeArgVector probeKind = "argvector"
	// probePresenceOnly resolves the tool and at most runs its help/version.
	// This is NOT verification and is counted separately in the census.
	probePresenceOnly probeKind = "presence-only"
)

// usageFamily names how a tool parses its command line, which decides what a
// rejection looks like.
type usageFamily string

const (
	familyGoFlag   usageFamily = "goflag"   // stdlib flag + projectdiscovery goflags
	familyPflag    usageFamily = "pflag"    // cobra / spf13-pflag
	familyArgparse usageFamily = "argparse" // python argparse
	familyOptparse usageFamily = "optparse" // sqlmap / commix (optparse-derived)
	familyClap     usageFamily = "clap"     // rust clap
	familyShell    usageFamily = "shell"    // testssl.sh
	familyPerl     usageFamily = "perl"     // exiftool
	familyWhois    usageFamily = "whois"    // BSD / GNU whois
	familyGeneric  usageFamily = "generic"  // unknown parser: sentinels only
)

// usageSignature is one family's rejection shape.
type usageSignature struct {
	// patterns are exit-code-independent rejection substrings (lower-case).
	patterns []string
	// usageExit is the exit code at which a bare usage dump ("usage") counts as
	// a rejection. 0 disables that leg (cobra prints usage on EVERY error and
	// exits 1, so for pflag only the patterns are trusted).
	usageExit int
}

// usageErrorSignatures is the per-family table. Add a family rather than
// loosening an existing one.
var usageErrorSignatures = map[usageFamily]usageSignature{
	familyGoFlag: {
		patterns:  []string{"flag provided but not defined", "flag needs an argument", "invalid value \"", "unknown flag"},
		usageExit: 2,
	},
	familyPflag: {
		patterns: []string{"unknown flag", "unknown shorthand flag", "unknown command", "invalid argument \"", "requires at least", "accepts "},
	},
	familyArgparse: {
		patterns:  []string{"unrecognized arguments", "the following arguments are required", "error: argument", "invalid choice", "expected one argument", "expected at least one argument"},
		usageExit: 2,
	},
	familyOptparse: {
		patterns:  []string{"no such option", "error: option", "ambiguous option"},
		usageExit: 2,
	},
	familyClap: {
		patterns:  []string{"error: unexpected argument", "error: unexpected value", "error: invalid value", "unrecognized subcommand", "the following required arguments were not provided"},
		usageExit: 2,
	},
	familyShell: {
		patterns: []string{"unrecognized option", "unknown option", "invalid option"},
	},
	familyPerl: {
		patterns: []string{"unknown option"},
	},
	familyWhois: {
		patterns:  []string{"illegal option", "invalid option"},
		usageExit: 64, // EX_USAGE
	},
	familyGeneric: {
		patterns:  []string{"unknown long flag", "unknown short flag", "unrecognized option", "unknown option", "no such option", "unrecognized arguments"},
		usageExit: 2,
	},
}

// goldenProbe is one tool's probe: the Task's arg vector with safe inputs, plus
// whatever makes running it hermetic.
type goldenProbe struct {
	name    string // logical name (census key); also the registry/exec name unless cmdName is set
	cmdName string
	kind    probeKind
	family  usageFamily
	// golden is the Task's vector with safe inputs substituted. For a
	// presence-only probe it is the help/version vector, or nil to resolve the
	// tool WITHOUT executing anything (SwaggerSpy searches SwaggerHub for the
	// literal string "--help").
	golden []string
	// prePins / pins are hermeticity pins placed before / after the golden.
	// Documented on each probe. They never replace a golden token.
	prePins []string
	pins    []string
	// stdin, when non-nil, is fed to the process (empty string = EOF at once).
	stdin *string
	// unsetEnv names variables scrubbed from the process environment in
	// addition to the credentials every probe loses.
	unsetEnv []string
	// expect, when set, lists output markers of which at least one MUST appear:
	// proof the run reached the hermetic barrier (a refused proxy connect, a
	// missing-credential abort) rather than going somewhere else.
	expect []string
	// why explains a presence-only probe, in the words a census reader needs.
	why     string
	timeout time.Duration
	// knownBad records a PRODUCTION arg-vector defect this probe surfaced and
	// that is deliberately not fixed here (the module is a non-test file and the
	// fix is its own change with its own verification — the 16-04 Task 1 rule).
	// The probe then EXPECTS the rejection: it passes while the defect stands,
	// logs REALTOOLS_KNOWN_BAD so the census names it, and fails STALE the moment
	// the tool accepts the vector, so the entry cannot outlive the fix.
	knownBad string
	// wrongBinary maps an output marker to an explanation: the name on PATH
	// resolved to a DIFFERENT program than the one the Task was written for.
	// That is a box/installer defect, reported as a failure in its own words
	// rather than as "the vector was rejected".
	wrongBinary map[string]string
}

func str(s string) *string { return &s }

// mustBeClosed fails the test if the loopback target accepts connections — a
// listener there would turn every "refused" barrier into a live service.
func mustBeClosed(t *testing.T) {
	t.Helper()
	c, err := net.DialTimeout("tcp", loopbackClosed, 500*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Fatalf("%s accepts connections on this box; the probes assume it is CLOSED and every "+
			"hermeticity barrier below depends on that", loopbackClosed)
	}
}

// probeEnv is the process environment every probe runs with: the caller's,
// minus credentials, plus the loopback proxy and NO_COLOR.
func probeEnv(extraUnset []string) []string {
	drop := map[string]bool{
		"GH_TOKEN": true, "GITHUB_TOKEN": true, "PDCP_API_KEY": true,
		"HTTP_PROXY": true, "HTTPS_PROXY": true, "ALL_PROXY": true, "NO_PROXY": true,
		"http_proxy": true, "https_proxy": true, "all_proxy": true, "no_proxy": true,
		"NO_COLOR": true,
	}
	for _, k := range extraUnset {
		drop[k] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			env = append(env, kv)
		}
	}
	return append(env,
		"HTTP_PROXY="+loopbackProxy, "HTTPS_PROXY="+loopbackProxy, "ALL_PROXY="+loopbackProxy,
		"http_proxy="+loopbackProxy, "https_proxy="+loopbackProxy, "all_proxy="+loopbackProxy,
		"NO_PROXY=", "no_proxy=", "NO_COLOR=1",
	)
}

// runGoldenProbe is the single executor for both tables.
func runGoldenProbe(t *testing.T, census *probeCensus, p goldenProbe) {
	t.Helper()
	cmdName := p.cmdName
	if cmdName == "" {
		cmdName = p.name
	}
	r := realtoolsResolve(t, cmdName)
	if r.Availability != toolResolved {
		census.recordUnavailable(p.name, r)
		t.Logf("SKIP: %s (%s) %s — arg vector NOT verified (counted in REALTOOLS_CENSUS)",
			p.name, cmdName, r.describe())
		t.Skip()
		return
	}
	census.recordPresent(p.name)
	logResolution(t, r)

	timeout := p.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}

	switch p.kind {
	case probePresenceOnly:
		census.recordPresenceOnly(p.name)
		t.Logf("REALTOOLS_PRESENCE_ONLY tool=%s why=%s — the golden vector was NOT executed; this is not verification",
			p.name, p.why)
		if p.golden == nil {
			t.Logf("%s: resolved only; no invocation is safe for this tool", p.name)
			return
		}
		res := execProbe(t, r, p, p.golden, timeout)
		rejected, sig := usageRejected(p.family, res)
		if rejected {
			t.Errorf("%s rejected even its help/version vector (%s):\n  args: %v\n  output:\n%s",
				p.name, sig, res.argv, res.output)
		}
		return

	case probeArgVector:
		full := make([]string, 0, len(p.prePins)+len(p.golden)+len(p.pins))
		full = append(full, p.prePins...)
		full = append(full, p.golden...)
		full = append(full, p.pins...)
		if len(p.prePins)+len(p.pins) > 0 {
			t.Logf("REALTOOLS_PINS tool=%s pre=%v post=%v", p.name, p.prePins, p.pins)
		}
		res := execProbe(t, r, p, full, timeout)
		if res.timedOut {
			t.Logf("WARN: %s did not finish within %s and was killed. Accepted (not a usage error), but a "+
				"hang against a closed loopback port usually means the tool is waiting on something else.",
				p.name, timeout)
		}
		rejected, sig := usageRejected(p.family, res)
		if rejected {
			census.recordRejected(p.name)
			lower := strings.ToLower(res.output)
			for marker, explanation := range p.wrongBinary {
				if strings.Contains(lower, strings.ToLower(marker)) {
					t.Errorf("%s: WRONG BINARY on this box — %s\n  (the usage text contains %q)\n  argv: %v\n  output:\n%s",
						p.name, explanation, marker, res.argv, res.output)
					return
				}
			}
			if p.knownBad != "" {
				t.Logf("REALTOOLS_KNOWN_BAD tool=%s sig=%q why=%s\n  argv: %v\n  output:\n%s",
					p.name, sig, p.knownBad, res.argv, strings.TrimSpace(res.output))
				return
			}
			t.Errorf("%s REJECTED its golden arg vector (%s).\n  argv: %v\n  exit: %d\n  output:\n%s",
				p.name, sig, res.argv, res.exit, res.output)
			return
		}
		if p.knownBad != "" {
			census.recordRejected(p.name)
			t.Errorf("%s: STALE knownBad entry — the tool ACCEPTED the vector this entry says it rejects.\n"+
				"  Either the module was fixed (delete the entry in the same change) or this box carries a\n"+
				"  tool version that still takes the old flag (say which, and pin the version).\n"+
				"  entry: %s\n  argv: %v\n  output:\n%s", p.name, p.knownBad, res.argv, res.output)
			return
		}
		if len(p.expect) > 0 {
			lower := strings.ToLower(res.output)
			hit := false
			for _, m := range p.expect {
				if strings.Contains(lower, strings.ToLower(m)) {
					hit = true
					break
				}
			}
			if !hit {
				census.recordRejected(p.name)
				t.Errorf("%s: hermeticity UNPROVEN — none of %q appears in the output, so the run cannot be "+
					"shown to have stopped at its loopback barrier.\n  argv: %v\n  exit: %d\n  output:\n%s",
					p.name, p.expect, res.argv, res.exit, res.output)
				return
			}
		}
		census.recordVerified(p.name)
		t.Logf("REALTOOLS_ARGVECTOR_OK tool=%s exit=%d argv=%v", p.name, res.exit, res.argv)
	default:
		t.Fatalf("probe %s has no kind", p.name)
	}
}

type probeResult struct {
	argv     []string
	output   string
	exit     int
	timedOut bool
}

// execProbe runs the resolved tool the way the Runner would (interpreter
// prefix, clone workdir) inside a temp cwd for PATH tools.
func execProbe(t *testing.T, r resolvedTool, p goldenProbe, args []string, timeout time.Duration) probeResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	full := r.argv(args)
	cmd := exec.CommandContext(ctx, r.Path, full...) //nolint:gosec // path from the tool registry; args are controlled
	cmd.Dir = r.WorkDir
	if cmd.Dir == "" {
		cmd.Dir = t.TempDir() // never the package directory: some tools write reports to cwd
	}
	cmd.Env = probeEnv(p.unsetEnv)
	if p.stdin != nil {
		cmd.Stdin = strings.NewReader(*p.stdin)
	} else {
		cmd.Stdin = strings.NewReader("") // EOF, never the test's own stdin (gato prompts)
	}
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	res := probeResult{argv: full, output: out.String(), exit: -1}
	var ee *exec.ExitError
	switch {
	case err == nil:
		res.exit = 0
	case errors.As(err, &ee):
		res.exit = ee.ExitCode()
	}
	if ctx.Err() != nil {
		res.timedOut = true
	}
	return res
}

// usageRejected classifies a run as a usage error per family. Returns the
// signature that matched.
func usageRejected(fam usageFamily, res probeResult) (bool, string) {
	lower := strings.ToLower(res.output)
	for _, s := range usageSentinels {
		if strings.Contains(lower, s) {
			return true, "shared sentinel " + s
		}
	}
	sig, ok := usageErrorSignatures[fam]
	if !ok {
		sig = usageErrorSignatures[familyGeneric]
	}
	for _, pat := range sig.patterns {
		if strings.Contains(lower, pat) {
			return true, string(fam) + " pattern " + pat
		}
	}
	if sig.usageExit != 0 && res.exit == sig.usageExit && strings.Contains(lower, "usage") {
		return true, string(fam) + " usage dump at exit " + itoa(res.exit)
	}
	return false, ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// ---------------------------------------------------------------------------
// Phase 6 — vulnerability scanning tools
// ---------------------------------------------------------------------------

// TestRealtoolsVulnsPhase6 executes every Phase 6 vuln tool's golden arg vector
// against loopback. Per DoD-1 an absent tool is a logged SKIP counted in the
// census, never a silent one.
func TestRealtoolsVulnsPhase6(t *testing.T) {
	census := newProbeCensus()
	defer reportRealtoolsCensus(t, "TestRealtoolsVulnsPhase6", census, vulnsKnownAbsent)
	mustBeClosed(t)

	dir := t.TempDir()
	hostsFile := filepath.Join(dir, "hosts.txt")
	tlsHostsFile := filepath.Join(dir, "tls_hosts.txt")
	urlsFile := filepath.Join(dir, "urls.txt")
	outFile := filepath.Join(dir, "out.txt")
	sqliFile := filepath.Join(dir, "sqli.txt")
	rceFile := filepath.Join(dir, "rce.txt")
	sstiFile := filepath.Join(dir, "ssti.txt")
	templatesDir := filepath.Join(dir, "dast-templates")
	mustWrite(t, hostsFile, loopbackURL+"\n")
	mustWrite(t, tlsHostsFile, loopbackClosed+"\n")
	mustWrite(t, urlsFile, loopbackURL+"/?q=test\n"+loopbackURL+"/?id=1\n")
	mustWrite(t, sqliFile, loopbackURL+"/?id=FUZZ\n")
	mustWrite(t, rceFile, loopbackURL+"/?cmd=FUZZ\n")
	mustWrite(t, sstiFile, loopbackURL+"/?tpl=FUZZ\n")
	if err := os.MkdirAll(templatesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Defaults matching config.Defaults() D-V6 WAF-friendly caps (06-09 plan golden):
	const (
		defaultXSSThreads    = "5"  // cfg.Vulns.XSS.Threads == 5 (D-V6)
		defaultFrayMaxPay    = "20" // cfg.Vulns.Fray.MaxPayloads == 20 (D-V6)
		defaultToxiThreads   = "70" // cfg.Advanced.Tools.Toxicache.Threads default
		defaultFrayTimeout   = "10" // cfg.Vulns.Fray.Timeout default
		defaultFrayDelay     = "0.5"
		defaultXSSDepth      = "2"  // depth when !cfg.Advanced.Deep
		defaultSecondDepth   = "1"  // cfg.Advanced.Tools.SecondOrder.Depth default
		defaultSecondThreads = "10" // cfg.Advanced.Tools.SecondOrder.Threads default
		defaultTInjATimeout  = "15" // cfg.Advanced.Tools.TInjA.Timeout default
		nucleiDefaultRL      = "150"
		defaultSSTImapLevel  = "1" // cfg.Advanced.Tools.SSTImap.Level default
		defaultInteractshWhy = "the Task dispatches it with NO arguments (ssrf.go: StreamOpts(ctx, \"interactsh-client\", nil, …)); a bare run opens a live OOB session against the public oast servers and there is no golden token to verify"
		stdinLoopURL         = loopbackURL + "/?q=1\n"
	)

	probes := []goldenProbe{
		// gf: URL gf-pattern classification (GFTask — gf.go): gf <class> <inputFile>.
		{name: "gf", kind: probeArgVector, family: familyGeneric, golden: []string{"xss", urlsFile}},

		// qsreplace: querystring replacement (XSSTask — xss.go), reads stdin.
		{name: "qsreplace", kind: probeArgVector, family: familyGoFlag, golden: []string{"FUZZ"}, stdin: str(stdinLoopURL)},

		// Gxss: reflection finder (XSSTask — xss.go: Gxss -c 100 -p Xss), reads stdin.
		{name: "Gxss", kind: probeArgVector, family: familyGoFlag, golden: []string{"-c", "100", "-p", "Xss"}, stdin: str(stdinLoopURL)},

		// dalfox pipe (XSSTask — xss.go): no -b because XSS_SERVER is empty by
		// default. 21-07a narrowed the vector to the flags dalfox v2.9 (Go) and
		// v3.2 (Rust/clap) BOTH accept: --no-spinner, --skip-bav and -w were
		// v2-only, and -d was never a depth flag (it is --data in both majors).
		{
			name: "dalfox", kind: probeArgVector, family: familyClap,
			golden: []string{
				"pipe", "--silence", "--no-color",
				"--only-poc", "r", "--ignore-return", "302,404,403",
			},
			stdin: str(stdinLoopURL),
		},

		// sqlmap (SQLiTask — sqli.go): v1 vulns.sh:533-534 verbatim. Resolves
		// through the clone row (.venv/bin/python3 sqlmap.py), as production does.
		{
			name: "sqlmap", kind: probeArgVector, family: familyOptparse,
			golden: []string{
				"-m", sqliFile, "-b", "-o", "--smart", "--batch",
				"--disable-coloring", "--random-agent", "--output-dir", dir,
			},
			timeout: 45 * time.Second,
		},

		// ghauri (SQLiTask — sqli.go, D-V6 opt-in): per-URL invocation.
		{
			name: "ghauri", kind: probeArgVector, family: familyArgparse,
			golden:  []string{"-u", loopbackURL + "/?id=FUZZ", "--batch", "--force-ssl"},
			timeout: 30 * time.Second,
		},

		// interactsh-client (SSRFTask — ssrf.go): PRESENCE ONLY, see why.
		{name: "interactsh-client", kind: probePresenceOnly, family: familyGoFlag, golden: []string{"-version"}, why: defaultInteractshWhy},

		// crlfuzz (CRLFTask — crlf.go): v1 vulns.sh:223.
		{name: "crlfuzz", kind: probeArgVector, family: familyPflag, golden: []string{"-l", hostsFile, "-o", outFile}},

		// TInjA (SSTITask — ssti.go:229): url subcommand, then --url per target.
		{
			name: "TInjA", kind: probeArgVector, family: familyPflag,
			golden: []string{
				"url", "--reportpath", dir + "/", "--timeout", defaultTInjATimeout, "--verbosity", "0",
				"--url", loopbackURL + "/?q=1",
			},
		},

		// SSTImap (SSTITask — ssti.go runSSTImap): the clone row supplies
		// `venv/bin/python3 sstimap.py`; the Task appends --level, --no-color and
		// --load-urls. Until 21-04 this probe ran `python3 --version` under the
		// name "python3" and verified nothing about SSTImap.
		{
			name: "SSTImap", kind: probeArgVector, family: familyArgparse,
			golden:  []string{"--level", defaultSSTImapLevel, "--no-color", "--load-urls", sstiFile},
			timeout: 30 * time.Second,
		},

		// commix (CMDITask — cmdi.go): v1 vulns.sh:731.
		{
			name: "commix", kind: probeArgVector, family: familyOptparse,
			golden:  []string{"--batch", "-m", rceFile, "--output-dir", dir},
			timeout: 45 * time.Second,
		},

		// smugglex (SmugglingTask — smuggling.go): v1 vulns.sh:817, hosts on stdin.
		{name: "smugglex", kind: probeArgVector, family: familyClap, golden: []string{"-f", "plain"}, stdin: str(loopbackURL + "\n")},

		// Web-Cache-Vulnerability-Scanner (WebCacheTask — webcache.go): v1 vulns.sh:879.
		// Writes its report files to cwd, which execProbe makes a temp dir.
		{name: "Web-Cache-Vulnerability-Scanner", kind: probeArgVector, family: familyGoFlag, golden: []string{"-u", "file:" + hostsFile, "-v", "0"}},

		// toxicache (WebCacheTask — webcache.go): v1 vulns.sh:894.
		{
			name: "toxicache", kind: probeArgVector, family: familyGoFlag,
			golden: []string{
				"-i", hostsFile, "-o", outFile, "-t", defaultToxiThreads,
				"-ua", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			},
		},

		// second-order (SecondOrderTask — second_order.go).
		{
			name: "second-order", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-target", loopbackURL, "-depth", defaultSecondDepth, "-threads", defaultSecondThreads, "-output", dir},
		},

		// nuclei DAST (NucleiDASTTask — nuclei_dast.go). -duc is mandatory (PD
		// update check hangs on the dev-Mac DNS block). The template path is an
		// empty temp dir: "no templates" is not a usage error.
		{
			name: "nuclei", kind: probeArgVector, family: familyGoFlag,
			golden: []string{
				"-l", hostsFile, "-dast", "-nh", "-rl", nucleiDefaultRL, "-silent", "-retries", "2", "-duc",
				"-t", templatesDir, "-j", "-o", outFile,
			},
			timeout: 30 * time.Second,
		},

		// fray (FrayTask — fray.go): D-V6 --max 20, -t 10, -d 0.5; one category.
		// Targets on STDIN (21-07a): `fray test` takes one positional target and
		// has no list flag, so the v1 `cat targets | fray test ...` shape is the
		// only multi-target form; fray.go hands the file over as StdinPath.
		{
			name: "fray", kind: probeArgVector, family: familyArgparse,
			golden: []string{
				"test", "-c", "ai_prompt_injection",
				"--max", defaultFrayMaxPay, "-t", defaultFrayTimeout, "-d", defaultFrayDelay, "--json",
			},
			stdin:   str(stdinLoopURL),
			timeout: 30 * time.Second,
		},

		// testssl.sh (TestSSLTask — testssl.go): host:port lines, not URLs.
		{
			name: "testssl.sh", kind: probeArgVector, family: familyShell,
			golden:  []string{"--quiet", "--color", "0", "-U", "-iL", tlsHostsFile},
			timeout: 45 * time.Second,
		},

		// gqlspection (GraphQLTask — graphql.go).
		{name: "gqlspection", kind: probeArgVector, family: familyArgparse, golden: []string{"-t", loopbackURL + "/graphql", "-o", outFile}},
	}

	for _, p := range probes {
		p := p
		t.Run(p.name, func(t *testing.T) {
			t.Logf("DoD-1 golden args for %s (%s): %v", p.name, p.kind, p.golden)
			runGoldenProbe(t, census, p)
		})
	}
}

// ---------------------------------------------------------------------------
// Phase 7 — OSINT tools
// ---------------------------------------------------------------------------

// TestRealtoolsOSINTPhase7 executes every Phase 7 OSINT tool's golden arg
// vector. The goldens come from internal/modules/osint/*.go; an OSINT tool is
// by nature a network tool, so this table carries most of the pins and all of
// the presence-only entries. Each presence-only `why` is specific: the reader
// must be able to tell "nobody tried" from "there is no safe way".
func TestRealtoolsOSINTPhase7(t *testing.T) {
	census := newProbeCensus()
	defer reportRealtoolsCensus(t, "TestRealtoolsOSINTPhase7", census, osintKnownAbsent)
	mustBeClosed(t)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "github_tokens.txt")
	usernamesFile := filepath.Join(dir, "usernames.txt")
	orgsFile := filepath.Join(dir, "orgs.txt")
	oneDomainFile := filepath.Join(dir, "one.txt")
	enumOut := filepath.Join(dir, "enum.json")
	ghReport := filepath.Join(dir, "github_leaks.json")
	favOut := filepath.Join(dir, "favicon.json")
	gatoJSON := filepath.Join(dir, "gato.json")
	postleaksOut := filepath.Join(dir, "postleaks")
	gqlOut := filepath.Join(dir, "gql.json")
	hostsFile := filepath.Join(dir, "hosts.txt")
	doc := filepath.Join(dir, "report.pdf")
	// No trailing newline: enumerepo puts the file's bytes straight into an
	// Authorization header and net/http refuses a header value with a newline
	// BEFORE dialing, which would make this probe "hermetic" by accident.
	mustWrite(t, tokenFile, "ghp_FAKETOKEN0000000000000000000000000000")
	mustWrite(t, usernamesFile, "example\n")
	mustWrite(t, orgsFile, "example\n")
	mustWrite(t, oneDomainFile, "example.com\n")
	mustWrite(t, hostsFile, loopbackURL+"\n")
	mustWrite(t, doc, "%PDF-1.4 fake\n")
	dorksFile := filepath.Join(dir, "dorks.txt")
	mustWrite(t, dorksFile, "filename:.env\n")

	const (
		domain  = "example.com"
		company = "example"
		// D-O8 conservative caps (config.Defaults() OSINT block).
		cloudThreads   = "20" // cloudEnumDefaultThreads
		postmanThreads = "10" // cfg.OSINT.Postman.Threads default
		gitDorksNWS    = "20" // gitdorks -nws default
		faviConcurr    = "50" // faviReconDefaultConcurrency
		faviTimeout    = "10" // faviReconDefaultTimeout
		cewlerDepth    = "1"  // cewlerDepth
		cewlerMinLen   = "5"  // cewlerMinLength
	)
	proxyRefused := []string{"proxyconnect", "127.0.0.1:9", "proxy"}

	probes := []goldenProbe{
		// whois (DomainInfoTask — domain_info.go:104): `whois <domain>`. BSD getopt
		// stops at the first operand, so the server pin must come FIRST:
		// -h 127.0.0.1 -p 9 sends the query to the closed loopback port.
		{
			name: "whois", kind: probeArgVector, family: familyWhois,
			prePins: []string{"-h", "127.0.0.1", "-p", "9"},
			golden:  []string{domain},
			expect:  []string{"connect"},
		},

		// dnsx (IPInfoTask — ip_info.go:272; DomainInfoTask — domain_info.go:158):
		// the LIST form, which 17-04 fixed. Pin: -r 127.0.0.1:9 so the lookup is
		// answered by a closed loopback port, never a real resolver.
		{
			name: "dnsx", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-duc", "-silent", "-a", "-resp-only", "-l", oneDomainFile},
			pins:   []string{"-r", loopbackClosed},
		},

		// mapcidr (IPInfoTask — ip_info.go:119): pure CIDR arithmetic. Pin: -duc,
		// which the Task does NOT pass and which is the only way to keep a PD
		// tool from phoning home on start.
		{
			name: "mapcidr", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-silent", "-aggregate", "-cidr", "127.0.0.0/24"},
			pins:   []string{"-duc"},
		},

		// asnmap (IPInfoTask — ip_info.go:180). It IGNORES the proxy environment
		// (observed answering with real CIDRs under HTTPS_PROXY), so the pin is
		// its own -proxy flag, which it validates by connecting BEFORE any API
		// call and aborts on: "could not set proxy" is the barrier and must appear.
		{
			name: "asnmap", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-duc", "-silent", "-i", "127.0.0.1"},
			pins:   []string{"-proxy", loopbackProxy},
			expect: []string{"could not set proxy"},
		},

		// EmailHarvester (EmailsTask — emails.go:82). Pin: its own -x proxy flag.
		{
			name: "EmailHarvester", kind: probeArgVector, family: familyArgparse,
			golden: []string{"-d", domain, "-e", "all", "-l", "20"},
			pins:   []string{"-x", loopbackProxy},
			expect: []string{"proxy"},
		},

		// dorks_hunter (GitHubDorksTask — github_dorks.go:96, golden `-d <domain>
		// -o <file>`): PRESENCE ONLY. It shells out to xnldorker per dork
		// (Google/Bing/DDG) and neither tool offers a proxy or offline option.
		{
			name: "dorks_hunter", kind: probePresenceOnly, family: familyArgparse, golden: []string{"--help"},
			why: "shells out to xnldorker (Google/Bing/DuckDuckGo) per dork; neither tool has a proxy or offline flag",
		},

		// gitdorks_go (GitDorksTask — gitdorks.go). The Task's vector, with a
		// one-dork file standing in for <tools>/gitdorks_go/Dorks/smalldorks.txt.
		// 21-07a added `-gd` (the v1 flag the port dropped); until then the tool
		// answered "require keyword or dorkfile" and searched nothing. With a
		// dorks file it reaches the GitHub API through the Go default transport,
		// which honours HTTPS_PROXY — the loopback refusal is the barrier.
		{
			name: "gitdorks_go", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-gd", dorksFile, "-nws", gitDorksNWS, "-target", domain, "-tf", tokenFile, "-ew", "3"},
			expect: proxyRefused,
			pins:   []string{"-nw=false"},
		},

		// enumerepo (GitHubReposTask — github_repos.go:114). Go default transport:
		// honours HTTPS_PROXY, observed as "proxyconnect tcp: dial tcp 127.0.0.1:9".
		{
			name: "enumerepo", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-token-file", tokenFile, "-usernames", usernamesFile, "-o", enumOut},
			expect: proxyRefused,
		},

		// ghleaks (GitHubLeaksTask — github_leaks.go:112). Same transport, same proof.
		{
			name: "ghleaks", kind: probeArgVector, family: familyPflag,
			golden: []string{"-q", domain, "--token", "REDACTED_TOKEN", "--report", ghReport, "--no-banner"},
			expect: proxyRefused,
		},

		// trufflehog (GitHubLeaksTask — github_leaks.go:136): `git <url> -j`. The
		// URL is a file:// repository built below, so the clone is local. Pin:
		// --no-update (trufflehog checks for updates on start otherwise).
		{
			name: "trufflehog", kind: probeArgVector, family: familyGeneric,
			golden:  []string{"git", "file://" + buildLocalGitRepo(t, dir), "-j"},
			pins:    []string{"--no-update"},
			timeout: 30 * time.Second,
			// The name `trufflehog` is ALSO the abandoned Python v2 package on PyPI
			// (`trufflehog [--json] git_url`), which `uv tool install trufflehog`
			// happily puts on PATH. Its usage names the positional `git_url`; the
			// Go v3 the Task targets has subcommands. Observed on the box this was
			// written on (2026-10-07): ~/.local/bin/trufflehog is the Python one.
			wrongBinary: map[string]string{
				"git_url": "PATH resolves `trufflehog` to the Python trufflehog v2 (PyPI), not trufflesecurity/trufflehog v3 that github_leaks.go:150 was written for (`git <url> -j`); install v3 via go install and remove the uv one",
			},
		},

		// gato (GitHubActionsTask — github_actions.go:109). With GH_TOKEN unset it
		// prompts on stdin, reads EOF and aborts before any request; that prompt
		// is the barrier and must appear.
		{
			name: "gato", kind: probeArgVector, family: familyArgparse,
			golden: []string{
				"e", "--enum_wf_artifacts", "--skip_sh_runner_enum",
				"-O", orgsFile, "-oJ", gatoJSON, "--include_all_artifact_secrets",
			},
			expect: []string{"GH_TOKEN"},
		},

		// cloud_enum (CloudEnumTask — cloud_enum.go:106). Pins: the three
		// --disable-* flags, so no provider is enumerated.
		{
			name: "cloud_enum", kind: probeArgVector, family: familyArgparse,
			golden: []string{"-k", company, "-k", domain, "-k", company, "-t", cloudThreads, "-qs"},
			pins:   []string{"--disable-aws", "--disable-azure", "--disable-gcp"},
		},

		// porch-pirate (PostmanTask — postman.go:117). Pin: its own --proxy.
		{
			name: "porch-pirate", kind: probeArgVector, family: familyArgparse,
			golden: []string{"-s", domain, "-l", "25", "--dump"},
			pins:   []string{"--proxy", loopbackProxy},
		},

		// postleaksNg (PostmanTask — postman.go:131). requests honours HTTPS_PROXY
		// (observed: urllib3 _prepare_proxy → ConnectionRefusedError).
		{
			name: "postleaksNg", kind: probeArgVector, family: familyArgparse,
			golden: []string{"-k", domain, "--output", postleaksOut, "-t", postmanThreads},
			expect: proxyRefused,
		},

		// sj (SwaggerTask — swagger.go:135): loopback URL.
		{name: "sj", kind: probeArgVector, family: familyPflag, golden: []string{"automate", "-u", loopbackURL + "/swagger.json"}},

		// SwaggerSpy (SwaggerTask — swagger.go:111): a single positional. requests
		// honours HTTPS_PROXY (observed). NOTE: `swaggerspy.py --help` is NOT safe —
		// it searches SwaggerHub for the string "--help".
		{
			name: "SwaggerSpy", kind: probeArgVector, family: familyGeneric,
			golden: []string{domain},
			expect: proxyRefused,
		},

		// Spoofy (SpoofyTask — spoofy.go:91): PRESENCE ONLY. SPF/DMARC lookups go
		// through dns.resolver and the system resolvers; no resolver flag, no
		// proxy, and it hung for the full timeout when tried.
		{
			name: "Spoofy", kind: probePresenceOnly, family: familyArgparse, golden: []string{"--help"},
			why: "DNS lookups via the system resolver; no resolver/proxy flag (observed hanging 15 s under a loopback proxy)",
		},

		// msftrecon (MSFTReconTask — msftrecon.go:99): PRESENCE ONLY. urllib
		// without a ProxyHandler: observed connecting directly under HTTPS_PROXY.
		{
			name: "msftrecon", kind: probePresenceOnly, family: familyArgparse, golden: []string{"--help"},
			why: "urllib opener without ProxyHandler — ignores HTTPS_PROXY (observed); no proxy flag; targets login.microsoftonline.com",
		},

		// cmseek (CMSeeKTask — cmseek.go:102): loopback URL.
		{name: "cmseek", kind: probeArgVector, family: familyArgparse, golden: []string{"-u", loopbackURL, "--batch", "-r"}, timeout: 30 * time.Second},

		// favirecon (FaviReconTask — favirecon.go:112): loopback hosts file.
		{
			name: "favirecon", kind: probeArgVector, family: familyGoFlag,
			golden: []string{"-l", hostsFile, "-c", faviConcurr, "-t", faviTimeout, "-s", "-j", "-o", favOut},
		},

		// gqlspection (GQLSpectionTask — gqlspection.go:101): loopback URL.
		{name: "gqlspection", kind: probeArgVector, family: familyArgparse, golden: []string{"-t", loopbackURL + "/graphql", "-o", gqlOut}},

		// cewler (CewlerTask — cewler.go:110): loopback URL.
		{
			name: "cewler", kind: probeArgVector, family: familyArgparse,
			golden: []string{"-d", cewlerDepth, "-m", cewlerMinLen, "-l", "-o", filepath.Join(dir, "cewl.part"), loopbackURL},
		},

		// xnldorker (XnldorkerTask — xnldorker.go:102, golden `-q <company> -o <file>`): PRESENCE ONLY.
		{
			name: "xnldorker", kind: probePresenceOnly, family: familyArgparse, golden: []string{"--help"},
			why: "queries Google/Bing/DuckDuckGo; no proxy or offline flag",
		},

		// misconfig-mapper (MisconfigTask — misconfig.go:85). Its first act is to
		// pull services.json from GitHub through the Go default transport, which
		// honours HTTPS_PROXY (observed "proxyconnect tcp: dial tcp 127.0.0.1:9").
		{
			name: "misconfig-mapper", kind: probeArgVector, family: familyGoFlag,
			golden: []string{
				"-target", domain, "-as-domain", "true", "-permutations", "false",
				"-skip-ssl", "-service", "*", "-verbose", "0",
			},
			expect: proxyRefused,
		},

		// metafinder/exiftool (MetadataTask — metadata.go:117): local file.
		{
			name: "metafinder/exiftool", cmdName: "exiftool", kind: probeArgVector, family: familyPerl,
			golden: []string{"-S", "-Author", "-Creator", "-Producer", "-Software", "-Company", doc},
		},
	}

	for _, p := range probes {
		p := p
		t.Run(p.name, func(t *testing.T) {
			if p.kind == probeArgVector && len(p.golden) == 0 {
				t.Fatalf("DoD-1: %s has an empty argv golden — a Task with no arg vector is a porting bug", p.name)
			}
			t.Logf("DoD-1 golden args for %s (%s): %v", p.name, p.kind, p.golden)
			runGoldenProbe(t, census, p)
		})
	}
}

// buildLocalGitRepo creates a one-commit repository under dir for the
// trufflehog probe and returns its absolute path. Fatal when git is missing:
// the probe is then not runnable and must not pass by accident.
func buildLocalGitRepo(t *testing.T, dir string) string {
	t.Helper()
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(repo, "README.md"), "nothing secret here\n")
	for _, argv := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=probe@example.invalid", "-c", "user.name=probe", "add", "README.md"},
		{"-c", "user.email=probe@example.invalid", "-c", "user.name=probe", "commit", "-q", "-m", "probe"},
	} {
		cmd := exec.Command("git", argv...)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", argv, err, out)
		}
	}
	return repo
}

// ---------------------------------------------------------------------------
// The six fixed arg vectors, against the real binaries (17-04)
// ---------------------------------------------------------------------------

// fixedVectorProbe is one of the vectors 17-04 fixed, with the argv to run
// against the installed binary and the rejection the OLD vector produced.
type fixedVectorProbe struct {
	name string
	// tool is the binary name for exec.LookPath.
	tool string
	// args is the FIXED vector, in the shape the module now dispatches.
	args []string
	// wasRejectedBy is the substring the OLD vector produced. Asserting its
	// ABSENCE is what makes this a fix rather than a claim: the check fails if
	// the tool still reports the very error the fix was supposed to remove.
	wasRejectedBy string
	// stdin feeds empty stdin.
	stdin bool
}

// TestRealtoolsFixedArgVectors runs each fixed vector against its installed
// binary and asserts the tool ACCEPTS the invocation.
//
// # WHAT THIS PROVES, AND WHAT IT DOES NOT
//
// Every one of these six bugs manifested as the tool REFUSING the invocation —
// before a packet was sent, before a file was read. Acceptance is therefore the
// exact property the fixes restore, and it is fully checkable on any box that
// has the binary.
//
// It does NOT prove the tool returns RESULTS. The developer box this was written
// on blocks outbound UDP/53, so puredns and dnsx cannot resolve anything here.
// A run that resolves nothing and a run that was rejected look identical in a
// results count and completely different in the tool's own output, which is why
// this test reads the OUTPUT and not the exit code.
//
// EXIT CODE IS NOT THE ORACLE. subzy exits 0 while printing
// `Error: unknown flag: --verify-ssl`, and sj exits 1 on a refused connection to
// a closed local port, which is correct acceptance. The oracle is the absence of
// the specific rejection string the old vector produced.
//
// SAFETY (T-17-04-03): every target is example.com (RFC 2606) or a closed port
// on 127.0.0.1. No live third-party host is contacted.
func TestRealtoolsFixedArgVectors(t *testing.T) {
	census := newProbeCensus()
	defer reportRealtoolsCensus(t, "TestRealtoolsFixedArgVectors", census, fixedVectorKnownAbsent)

	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	wordlist := write("wl.txt", "www\napi\n")
	resolvers := write("res.txt", "1.1.1.1\n8.8.8.8\n")
	oneName := write("one.txt", "example.com\n")
	targets := write("targets.txt", "api.example.com\n")
	urls := write("urls.txt", "http://127.0.0.1:1/\n")
	outJSON := filepath.Join(dir, "out.json")

	probes := []fixedVectorProbe{
		{
			name: "puredns bruteforce, POSITIONAL domain (subdomains.brute / subdomains.recursive.brute)",
			tool: "puredns",
			args: []string{"bruteforce", wordlist, "example.com", "-r", resolvers, "--quiet"},
			// OLD: puredns bruteforce wl.txt -d example.com …
			wasRejectedBy: "no such file or directory",
		},
		{
			name:          "dnsx record lookup via the LIST input (osint.ip_info / osint.domain_info)",
			tool:          "dnsx",
			args:          []string{"-duc", "-silent", "-a", "-resp-only", "-l", oneName},
			wasRejectedBy: "missing wordlist(w) flag required with domain(d) input",
		},
		{
			name:          "subzy with the UNDERSCORE long flag (subdomains.takeover.subzy)",
			tool:          "subzy",
			args:          []string{"run", "--targets", targets, "--verify_ssl", "--output", outJSON},
			wasRejectedBy: "unknown flag",
		},
		{
			name:          "sj with a SCHEME-BEARING url (osint.swagger)",
			tool:          "sj",
			args:          []string{"automate", "-q", "-u", "http://127.0.0.1:1/swagger.json"},
			wasRejectedBy: "unsupported protocol scheme",
		},
		{
			name:          "subjs with a REAL FILE (subdomains.scraping)",
			tool:          "subjs",
			args:          []string{"-i", urls},
			wasRejectedBy: "Could not open input file",
		},
	}

	for _, p := range probes {
		p := p
		t.Run(p.tool+": "+p.name, func(t *testing.T) {
			r := realtoolsResolve(t, p.tool)
			if r.Availability != toolResolved {
				census.recordUnavailable(p.tool, r)
				t.Logf("SKIP: %s %s — this vector's ACCEPTANCE was NOT verified on this box",
					p.tool, r.describe())
				t.Skipf("%s unavailable", p.tool)
			}
			census.recordPresent(p.tool)
			census.recordVerified(p.tool)
			logResolution(t, r)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			fullArgs := r.argv(p.args)
			cmd := exec.CommandContext(ctx, r.Path, fullArgs...) //nolint:gosec // fixture argv, synthetic targets
			cmd.Dir = r.WorkDir
			if p.stdin {
				cmd.Stdin = strings.NewReader("")
			}
			out, _ := cmd.CombinedOutput()
			got := string(out)

			t.Logf("%s %s\n--- tool output ---\n%s", p.tool, strings.Join(fullArgs, " "), strings.TrimSpace(got))

			if strings.Contains(got, p.wasRejectedBy) {
				t.Errorf("%s STILL REJECTS the invocation: output contains %q.\n"+
					"  That is the exact rejection the old vector produced, so the fix did not take.\n"+
					"  argv: %v\n  output:\n%s", p.tool, p.wasRejectedBy, p.args, got)
			}
			// A usage dump is the other shape a refused vector takes.
			for _, sentinel := range []string{"unknown flag", "unknown shorthand", "flag provided but not defined"} {
				if strings.Contains(strings.ToLower(got), sentinel) {
					t.Errorf("%s reports %q — the vector is not accepted.\n  argv: %v\n  output:\n%s",
						p.tool, sentinel, p.args, got)
				}
			}
		})
	}
}

// logResolution prints how a tool was resolved, so a REFERENCE run's log shows
// whether a probe reached a PATH binary or a declared clone — and with which
// interpreter and working directory.
//
// Without this the census could report a tool "present" and nobody could tell
// which of the two routes answered, which is the ambiguity 18-02's three-state
// partition exists to remove.
func logResolution(t *testing.T, r resolvedTool) {
	t.Helper()
	if r.ViaPath {
		t.Logf("REALTOOLS_RESOLVED tool=%s via=PATH path=%s", r.Name, r.Path)
		return
	}
	t.Logf("REALTOOLS_RESOLVED tool=%s via=CLONE path=%s argv_prefix=%v workdir=%s",
		r.Name, r.Path, r.ArgvPrefix, r.WorkDir)
}

// fixedVectorKnownAbsent moved to realtools_census_test.go in 18-06, alongside
// the other three lists, when all four were reclassified into the registry's
// three availability states.
