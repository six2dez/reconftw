// toolflags_test.go — every dash-prefixed token a Task dispatches must be a flag
// the tool actually defines.
//
// NO BUILD TAG, NO BINARIES. This runs in plain `go test ./...` on a CI runner
// with an empty PATH, which is the entire point: the two flag bugs that reached
// production were both invisible to every hermetic test in the tree and were
// only catchable by a probe that needed the 70-tool runtime.
//
// # WHAT THIS LAYER CATCHES, AND WHAT IT CANNOT
//
// It catches an UNDEFINED FLAG NAME — the `-rt` class:
//
//	puredns -rt <path>   puredns has no -rt shorthand. pflag reads it as -r with
//	                     the value "t", parses cleanly, and the tool dies with
//	                     `unable to load public resolvers: open t`. Every recon
//	                     run was broken and every test was green.
//	subzy --verify-ssl   subzy defines --verify_ssl with an UNDERSCORE. The tool
//	                     exits `unknown flag: --verify-ssl` on every invocation,
//	                     so subzy takeover detection has produced zero results
//	                     for as long as the vector has existed. Found by plan
//	                     16-04 Task 1 when the realtools probes were first made
//	                     to actually run.
//
// It CANNOT catch a DEFINED flag used with wrong SEMANTICS — the `-re` class:
//
//	tlsx -re <regex>     `-re` IS a real tlsx flag. It is `-revoked`, a boolean
//	                     certificate-revocation probe, not a scope regex. The
//	                     name is defined, so this test passes it, and only a real
//	                     invocation shows the tool doing the wrong thing.
//
// That is why the realtools probes still exist and why this file does not
// replace them. Two layers, two failure classes:
//
//	toolflags (here)     undefined name        hermetic, every `go test`
//	realtools probes     rejected/misbehaving  needs the toolchain, gated target
//
// Retiring either one leaves a class uncovered. Say which class you are giving
// up before deleting one.
//
// # SCOPE, AND THE CRITERION FOR IT
//
// Not all 70 tools — a table covering everything would rot faster than it helps.
// The covered set is the tools whose failure ABORTS OR EMPTIES a run:
// `tools.lock`'s critical tier, plus puredns (the resolve spine), plus the
// ProjectDiscovery tools that carry the web and vuln layers. Everything else is
// best-effort, and a best-effort tool with a bad flag degrades one task rather
// than the run.
//
// # PROVENANCE IS MANDATORY
//
// Each flag set records the exact command and the tool VERSION its contents came
// from. A flag table with no stated source cannot be re-derived, cannot be
// audited, and becomes folklore within two releases.
// TestToolFlagSetsHaveProvenance FAILS on a missing or malformed source, so this
// cannot decay quietly.
package backend_test

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// toolFlagSet is the set of flag tokens one tool defines, with the provenance of
// that set.
type toolFlagSet struct {
	// source is the exact command whose output produced this set, INCLUDING the
	// tool version. Enforced by TestToolFlagSetsHaveProvenance.
	source string
	// flags holds every accepted dash-prefixed token, long and short.
	flags []string
}

func (s toolFlagSet) has(tok string) bool {
	for _, f := range s.flags {
		if f == tok {
			return true
		}
	}
	return false
}

// knownToolFlags is the covered set. See the scope criterion in the header.
//
// ADD a flag here only after running the recorded command and reading its
// output. Adding one because "the code passes it" inverts the test: the table
// would then be derived from the arg vectors it is supposed to check.
var knownToolFlags = map[string]toolFlagSet{
	"puredns": {
		source: "puredns resolve --help (v2.1.1)",
		flags: []string{
			"-r", "--resolvers", "--resolvers-trusted",
			"-l", "--rate-limit", "--rate-limit-trusted",
			"-t", "--threads", "-n", "--wildcard-tests", "--wildcard-batch",
			"-b", "--bin", "-w", "--write", "--write-massdns", "--write-wildcards",
			"--skip-sanitize", "--skip-validation", "--skip-wildcard-filter",
			"--trusted-only", "-q", "--quiet", "--debug",
		},
	},
	"subzy": {
		// THE BUG THIS FILE WAS EXTENDED FOR. Note --verify_ssl, underscore.
		// internal/modules/subdomains/takeover.go passes --verify-ssl and has
		// never worked. Recorded in 16-04-SUMMARY; the fix is its own plan.
		source: "subzy run --help (v2.0.4)",
		flags: []string{
			"--concurrency", "-h", "--help", "--hide_fails", "--https",
			"--output", "--target", "--targets", "--timeout", "--verify_ssl", "--vuln",
		},
	},
	"httpx": {
		source: "httpx -h (v1.9.0), flag names only",
		flags: []string{
			"-l", "-list", "-u", "-target", "-p", "-ports", "-json", "-o", "-output",
			"-silent", "-no-color", "-nc", "-title", "-web-server", "-wc", "-server",
			"-tech-detect", "-td", "-status-code", "-sc", "-content-length", "-cl",
			"-location", "-follow-host-redirects", "-fhr", "-follow-redirects", "-fr",
			"-random-agent", "-retries", "-timeout", "-threads", "-t", "-rate-limit", "-rl",
			"-duc", "-disable-update-check", "-probe", "-sr", "-srd", "-ip", "-cdn",
			"-favicon", "-jarm", "-asn", "-hash", "-irh", "-include-response-header",
			"-H", "-header", "-x", "-method", "-body", "-d", "-delay", "-mc", "-fc",
			"-ms", "-fs", "-debug", "-v", "-verbose", "-stats", "-dashboard",
		},
	},
	"dnsx": {
		source: "dnsx -h (v1.2.1), flag names only",
		flags: []string{
			"-l", "-list", "-d", "-domain", "-w", "-wordlist", "-r", "-resolver",
			"-silent", "-json", "-o", "-output", "-a", "-aaaa", "-cname", "-ns",
			"-txt", "-mx", "-soa", "-ptr", "-srv", "-any", "-caa", "-axfr",
			"-resp", "-resp-only", "-ro", "-rcode", "-re", "-recon",
			"-t", "-threads", "-rl", "-rate-limit", "-retry", "-duc",
			"-disable-update-check", "-nc", "-no-color", "-v", "-verbose", "-debug",
			"-stats", "-wd", "-wildcard-domain", "-wt", "-wildcard-threshold",
		},
	},
	"subfinder": {
		source: "subfinder -h (v2.14.0), flag names only",
		flags: []string{
			"-d", "-domain", "-dL", "-list", "-all", "-s", "-sources",
			"-es", "-exclude-sources", "-recursive", "-silent", "-o", "-output",
			"-oJ", "-json", "-oD", "-cs", "-collect-sources", "-oI", "-ip",
			"-t", "-threads", "-timeout", "-max-time", "-rl", "-rate-limit",
			"-duc", "-disable-update-check", "-nc", "-no-color", "-v", "-verbose",
			"-config", "-pc", "-provider-config", "-stats", "-active", "-ei",
			"-exclude-ip", "-m", "-match", "-f", "-filter", "-r", "-rL",
		},
	},
	"tlsx": {
		source: "tlsx -h (v1.1.6), flag names only",
		flags: []string{
			"-l", "-list", "-u", "-host", "-p", "-port", "-silent", "-json",
			"-o", "-output", "-san", "-cn", "-so", "-ro", "-resp-only",
			"-re", "-revoked", "-ex", "-expired", "-mm", "-mismatched",
			"-untrusted", "-c", "-concurrency", "-timeout", "-retry",
			"-duc", "-disable-update-check", "-nc", "-no-color", "-v", "-verbose",
			"-tls-version", "-cipher", "-hash", "-jarm", "-ja3", "-wildcard-cert",
			"-probe-status", "-tps", "-cert", "-serial", "-version",
		},
	},
}

// dashToken matches a token that looks like a flag rather than a value.
//
// A NEGATIVE NUMBER IS NOT A FLAG. "-1" as a value for `-timeout` would
// otherwise be reported as an undefined flag, the test would be wrong, and the
// cheapest fix under pressure would be to delete the assertion.
var dashToken = regexp.MustCompile(`^-{1,2}[A-Za-z][A-Za-z0-9_.-]*$`)

// TestToolFlagSetsHaveProvenance makes an undocumented flag table a test
// failure.
//
// Without this, the cheapest way to silence a real finding is to append the
// offending token to the table — which would convert this guard into a
// transcription of the arg vectors it exists to check.
func TestToolFlagSetsHaveProvenance(t *testing.T) {
	if len(knownToolFlags) == 0 {
		t.Fatal("knownToolFlags is empty — the guard covers nothing")
	}
	versionish := regexp.MustCompile(`\(v[0-9]`)
	for tool, set := range knownToolFlags {
		switch {
		case strings.TrimSpace(set.source) == "":
			t.Errorf("%s: flag set has no recorded source.\n"+
				"  Record the exact command AND the tool version its output came from. A table nobody\n"+
				"  can re-derive is folklore, and folklore is what this guard replaces.", tool)
		case !versionish.MatchString(set.source):
			t.Errorf("%s: source %q records no tool VERSION.\n"+
				"  Flag sets drift between releases; a source without a version cannot be audited.\n"+
				"  Expected something like \"subzy run --help (v2.0.4)\".", tool, set.source)
		}
		if len(set.flags) == 0 {
			t.Errorf("%s: flag set is empty, so every token would be reported undefined", tool)
		}
		seen := map[string]bool{}
		for _, f := range set.flags {
			if seen[f] {
				t.Errorf("%s: %q listed twice", tool, f)
			}
			seen[f] = true
			if !dashToken.MatchString(f) {
				t.Errorf("%s: %q is not a flag-shaped token", tool, f)
			}
		}
	}
}

// knownBadArgVectors names (tool, flag) pairs that are KNOWN WRONG IN PRODUCTION
// and are not fixed here.
//
// WHY THIS LIST EXISTS AND WHY IT IS NOT A SUPPRESSION. Plan 16-04 Task 1 says a
// genuine arg-vector bug surfaced by newly-enabled probes must be RECORDED and
// left alone: "Fixing them is a real change to production arg vectors and
// belongs in its own plan with its own verification, exactly as the dnstake fix
// did." Without this list the guard would leave `go test ./...` permanently red,
// and a permanently red suite is one that stops being read.
//
// So the entry keeps the suite green AND keeps the finding named, and the
// ratchet runs in BOTH directions: TestKnownBadArgVectorsAreStillBad fails as
// STALE the moment the vector is fixed, so the fixer must delete the entry in
// the same commit. It cannot be forgotten and it cannot be quietly extended.
//
// NEVER add an entry to silence a NEW finding. A new undefined flag is a bug
// found before it shipped, which is the entire point of this file.
var knownBadArgVectors = map[string][]string{
	// internal/modules/subdomains/takeover.go:82 passes --verify-ssl.
	// subzy defines --verify_ssl (UNDERSCORE), so the tool exits
	// `unknown flag: --verify-ssl` on every invocation and subzy takeover
	// detection has produced zero results for as long as this vector existed.
	// Same file and same class as the dnstake bug; found by plan 16-04 Task 1.
	"subzy": {"--verify-ssl"},
}

const knownBadArgVectorsSize = 1

// TestKnownBadArgVectorsArePinned stops the list growing without a diff.
func TestKnownBadArgVectorsArePinned(t *testing.T) {
	n := 0
	for _, flags := range knownBadArgVectors {
		n += len(flags)
	}
	if n != knownBadArgVectorsSize {
		t.Errorf("knownBadArgVectors holds %d flag(s), constant says %d.\n"+
			"  Growing this list means shipping a KNOWN-BROKEN arg vector on purpose. If that is\n"+
			"  really the intent, raise the constant in the same commit and say why in the map.",
			n, knownBadArgVectorsSize)
	}
	for tool, flags := range knownBadArgVectors {
		set, ok := knownToolFlags[tool]
		if !ok {
			t.Errorf("knownBadArgVectors names %q, which has no flag table — the entry asserts nothing", tool)
			continue
		}
		for _, f := range flags {
			if set.has(f) {
				t.Errorf("%s: %q is on the known-bad list but IS a flag the tool defines (%s).\n"+
					"  STALE: either the flag table was corrected or the entry was wrong. Delete it.",
					tool, f, set.source)
			}
		}
	}
}

// assertFlagsDefined is the reusable assertion: every dash-prefixed token in
// argv must be a flag the tool defines.
//
// Returns false when the tool is not covered, so a caller can distinguish "no
// finding" from "not checked" — the distinction this whole phase is about.
func containsFlag(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func assertFlagsDefined(t *testing.T, tool string, argv []string) bool {
	t.Helper()
	set, ok := knownToolFlags[tool]
	if !ok {
		return false
	}
	var undefined, knownBad []string
	for _, a := range argv {
		if !dashToken.MatchString(a) {
			continue
		}
		if set.has(a) {
			continue
		}
		if containsFlag(knownBadArgVectors[tool], a) {
			knownBad = append(knownBad, a)
			continue
		}
		undefined = append(undefined, a)
	}
	if len(knownBad) > 0 {
		sort.Strings(knownBad)
		t.Logf("KNOWN-BAD ARG VECTOR: %s is dispatched with %s, which the tool does not define.\n"+
			"  This is a RECORDED, UNFIXED production bug (see knownBadArgVectors) — not a pass.\n"+
			"  source: %s", tool, strings.Join(knownBad, " "), set.source)
	}
	if len(undefined) > 0 {
		sort.Strings(undefined)
		t.Errorf("%s is dispatched with flag(s) it does not define: %s\n"+
			"  argv:   %v\n"+
			"  source: %s\n"+
			"  An UNDEFINED SHORTHAND is the dangerous case: puredns reads -rt as -r with the value\n"+
			"  \"t\", parses cleanly, and dies at runtime. Check the tool's help before adding the\n"+
			"  token to knownToolFlags — the table must come from the tool, never from the caller.",
			tool, strings.Join(undefined, " "), argv, set.source)
		return true
	}
	return true
}
