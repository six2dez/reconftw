// SPDX-License-Identifier: MIT
//
// # Silent-success ratchet (rule B1)
//
// Phase 16 plan 02. Two evidenced failures from the 2026-08-20 live run share
// one shape: a task ran a tool, the tool FAILED, the failure was logged at
// Debug, and the task returned task.StatusDone. On the operator's screen that
// is `[OK] subdomains.takeover.dnstake 0s`, indistinguishable from a clean
// target — and dnstake had been exiting `flag provided but not defined` on
// every run for months while takeover detection produced zero.
//
// This test is the mechanism that names the next one.
//
// # THE RULE
//
// In any function under internal/modules that calls app.Tools.Run / RunEnv /
// Stream / StreamEnv, the `if` branch that handles the error returned by that
// call must not:
//
//	(status rule) return a task.Result whose Status is task.StatusDone; or
//	(log rule)    say nothing about the failure above Debug.
//
// Both halves are required because the dnstake failure needed both: the status
// made it look healthy, and the Debug level made it invisible even to someone
// looking.
//
// THE LOG RULE'S THRESHOLD IS THE DEFAULT HANDLER LEVEL, NOT WARN. The plan's
// wording was "Warn, Error or higher"; the implemented threshold is Info,
// because internal/core/config/defaults.go resolves an unset log level to
// slog.LevelInfo, so an Info line about a tool failure IS on the operator's
// screen. Enforcing Warn would have reported 22 branches that already announce
// their failure at Info ("web.katana: binary absent or failed — skipping"),
// none of which are in Task 2's remainder — a detector that flags correct code
// gets disabled by the first person it inconveniences. The 22 are counted in
// the census (InfoLevel) so the decision stays visible and reversible.
//
// A branch that logs at Debug AND at Info-or-above is NOT reported: the failure
// is announced and the Debug line is detail.
//
// Accepted shapes inside a tool-error branch — anything else is reported:
//
//  1. A task.Result composite literal whose Status is task.StatusSkipped,
//     task.StatusErrored or task.StatusCancelled.
//  2. task.ToolDegraded(...) / task.NothingProduced(...), or a same-package
//     helper whose own body returns one of the above. ONE level of indirection
//     only, matching the stream detector's shape 3.
//  3. No return from that branch at all — it falls through
//     (subdomains/resolve.go dnsxRecon does this deliberately).
//
// task.Produced(...) is Done by construction and is reported like a StatusDone
// literal.
//
// # GRANULARITY: DETECTION IS PER BRANCH, SUPPRESSION IS PER FUNCTION
//
// Chosen deliberately, against the known hole in the older detector.
// deferred-items.md § "From plan 15-17" records that checkStreamContract
// evaluates its verdict ONCE PER FUNCTION, so a function with two Stream calls
// — one consuming the terminal error, one dropping it — passes. That hole was
// found by running its own mutation proof, not by reading it.
//
// checkSilentSuccess classifies each tool-error BRANCH independently, so a
// function with one compliant and one violating branch is reported. What the
// choice still hides: silentSuccessAllowlist is keyed by FUNCTION, so an
// allowlisted function is exempt in every branch it has, including branches
// added after it was listed. With 49 entries seeded that is a live hole, not a
// theoretical one — the honest reading is that those 49 functions are unguarded
// until their entries are deleted.
//
// # WHAT THIS DETECTOR PROVABLY CANNOT SEE
//
// Every item below was MUTATION-PROVEN, not reasoned about: a file containing
// the shape was dropped into internal/modules/web/, TestSilentSuccess was run,
// and it passed. Two of them contradicted what the code looked like it did.
//
//   - RULE B2 — a tool that SUCCEEDED and produced nothing. That needs an input
//     count only the individual task knows (web/httpx.go compares parsed
//     records against inputCount). Deliberately out of scope: for a detection
//     tool zero is the normal healthy answer, and a blanket "zero counter
//     therefore SKIP" rule would be wrong for dnstake on a clean target and for
//     nuclei on a hardened one. Do not "finish the job" by adding it.
//   - TWO levels of helper indirection. A branch returning zzOuter() where
//     zzOuter returns zzInner() and zzInner returns StatusDone passes. One level
//     is resolved, two is not — the same limit the stream detector's shape 3
//     draws.
//   - A DISCARDED error: `res, _ := app.Tools.Run(...)`. No error variable is
//     bound, so there is no branch to inspect and nothing is reported. The tool
//     failure there is not mis-reported, it is unobservable — arguably worse
//     than what the rule catches. The census pins the count at 0 for the tree
//     today so a first instance is visible in a diff.
//   - A logger under an unrecognised name. `slogger := app.Log; slogger.Debug(...)`
//     passes: the log rule matches `<x>.Log`/`<x>.Logger` selectors and bare
//     identifiers named log/logger/lg.
//   - A branch returning a Result VARIABLE (`done := task.Result{Status:
//     task.StatusDone}; ... return done, nil`) passes AND IS NOT EVEN COUNTED.
//     The classifier is syntactic; a returned identifier reads as "not a Result
//     literal at all", so it lands in neither the violation list nor the
//     unclassified counter. This was the one item the first draft of this
//     comment got wrong — it claimed such returns were counted as
//     `unclassified`. They are not. Only a Result literal with a missing or
//     unrecognised Status raises the unclassified counter, and there are zero
//     of those in the tree.
//
// # THE ALLOWLIST IS A SHRINKING MIGRATION LIST, NOT A CLOSED RATCHET
//
// Unlike the stream and staging detectors, this one is seeded NON-EMPTY: 49
// functions, the remainder 16-02 Task 2 deliberately left after fixing the two
// evidenced sites and preserving degradeResolveTool's CONTINUE_ON_TOOL_ERROR
// contract. Task 2 stopped on its own budget-discipline instruction — "an
// accurate partial sweep with a named remainder is worth more than a rushed
// complete one" — and this list is that remainder, now derived structurally
// instead of by grepping log messages.
//
// The ratchet fails in both directions, like the two detectors before it:
//
//   - A violating function absent from the allowlist is a violation: the list
//     cannot be dodged.
//   - An allowlist entry whose function is gone, or which now complies, is
//     stale: the list cannot quietly outlive its migration.
//
// silentSuccessAllowlistSize pins the count. Lower it as sites are fixed; it
// may never be raised.
package modules_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// silentSuccessAllowlist maps a repo-relative file path to the names of
// functions in it whose tool-error branch violates rule B1.
//
// Methods are named "<ReceiverType>.<Method>", matching declName, because a bare
// "Run" is ambiguous across the module task types.
//
// DELETE entries as you fix them. NEVER add one.
var silentSuccessAllowlist = map[string][]string{
	// SEEDED BY 16-02 TASK 3 with exactly the sites 16-02 Task 2 left unswept.
	// 49 functions in 44 files, 64 findings (10 status-rule, 54 log-rule).
	//
	// 16-02-SWEEP-DEBT.md named 28 sites in 22 files. That number was derived by
	// grepping Log.Debug lines whose MESSAGE matched "run failed|not registered",
	// so it counted the osint/subdomains sites and missed every vulns/* site
	// whose Debug line is worded differently ("commix stream error
	// (best_effort)", "gf invocation failed", "httpx error"). The structural
	// census below is the real remainder. The debt file has been corrected.
	//
	// The subdomains/* entries are inside a PolicyFailFast module and need
	// reading before any status change — see 16-02-SWEEP-DEBT.md § "Per-site
	// judgement still required".
	"internal/modules/osint/cewler.go":            {"CewlerTask.Run"},
	"internal/modules/osint/cloud_enum.go":        {"CloudEnumTask.Run"},
	"internal/modules/osint/cmseek.go":            {"CMSeeKTask.Run"},
	"internal/modules/osint/domain_info.go":       {"DomainInfoTask.Run", "DomainInfoTask.runScopify"},
	"internal/modules/osint/emails.go":            {"EmailsTask.Run", "EmailsTask.runLeakSearch"},
	"internal/modules/osint/favirecon.go":         {"FaviReconTask.Run"},
	"internal/modules/osint/gitdorks.go":          {"GitDorksTask.Run"},
	"internal/modules/osint/github_actions.go":    {"GitHubActionsTask.Run"},
	"internal/modules/osint/github_dorks.go":      {"GitHubDorksTask.Run"},
	"internal/modules/osint/github_leaks.go":      {"GitHubLeaksTask.Run"},
	"internal/modules/osint/github_repos.go":      {"GitHubReposTask.Run", "GitHubReposTask.runTitusScan", "GitHubReposTask.runTrufflehogScan"},
	"internal/modules/osint/gqlspection.go":       {"GQLSpectionTask.Run"},
	"internal/modules/osint/ip_info.go":           {"IPInfoTask.Run", "IPInfoTask.resolveIPs"},
	"internal/modules/osint/metadata.go":          {"MetadataTask.Run"},
	"internal/modules/osint/misconfig.go":         {"MisconfigTask.Run"},
	"internal/modules/osint/msftrecon.go":         {"MSFTReconTask.Run"},
	"internal/modules/osint/postman.go":           {"PostmanTask.Run"},
	"internal/modules/osint/spoofy.go":            {"SpoofyTask.Run"},
	"internal/modules/osint/swagger.go":           {"SwaggerTask.Run"},
	"internal/modules/osint/xnldorker.go":         {"XnldorkerTask.Run"},
	"internal/modules/subdomains/asn.go":          {"SubASNTask.Run"},
	"internal/modules/subdomains/buckets.go":      {"SubBucketsTask.Run"},
	"internal/modules/subdomains/csprecon.go":     {"SubCspreconTask.Run"},
	"internal/modules/subdomains/geo.go":          {"SubGeoTask.Run"},
	"internal/modules/subdomains/zonetransfer.go": {"attemptAXFR"},
	"internal/modules/vulns/cmdi.go":              {"CMDITask.Run"},
	"internal/modules/vulns/crlf.go":              {"CRLFTask.Run"},
	"internal/modules/vulns/fray.go":              {"FrayTask.Run"},
	"internal/modules/vulns/fuzzparams.go":        {"FuzzparamsTask.Run"},
	"internal/modules/vulns/gf.go":                {"GFTask.Run"},
	"internal/modules/vulns/graphql.go":           {"GraphQLTask.Run"},
	"internal/modules/vulns/grpc.go":              {"GRPCTask.Run"},
	"internal/modules/vulns/lfi.go":               {"runLFIFFUF"},
	"internal/modules/vulns/llm.go":               {"LLMTask.Run"},
	"internal/modules/vulns/nuclei_dast.go":       {"NucleiDASTTask.Run"},
	"internal/modules/vulns/second_order.go":      {"SecondOrderTask.Run"},
	"internal/modules/vulns/smuggling.go":         {"SmugglingTask.Run"},
	"internal/modules/vulns/spray.go":             {"SprayTask.resolveServiceFingerprintInput"},
	"internal/modules/vulns/sqli.go":              {"runGhauriPerURL"},
	"internal/modules/vulns/ssrf.go":              {"runSSRFFFUF"},
	"internal/modules/vulns/testssl.go":           {"TestSSLTask.Run"},
	"internal/modules/vulns/webcache.go":          {"WebCacheTask.Run"},
	"internal/modules/vulns/websocket.go":         {"WebsocketTask.Run"},
	"internal/modules/web/sourcemapper.go":        {"SourcemapperTask.Run"},
}

// silentSuccessAllowlistSize is the number of flattened allowlist entries.
// TestSilentSuccessAllowlistShrinks pins it against the map so the two cannot
// drift, and fails LOUDER when the map grows than when it shrinks.
//
// 16-02 Task 3 seed: 49 (osint 24, vulns 19, subdomains 5, web 1).
// LOWER IT as sites are fixed. It may never be raised: a new tool-error branch
// reports a non-Done status and logs at Info or above on the day it is written.
const silentSuccessAllowlistSize = 49

// --- rules ------------------------------------------------------------------

type ssRule string

const (
	ssRuleStatus ssRule = "status"
	ssRuleLog    ssRule = "log-level"
)

// ssFinding is one violating tool-error branch. Rule is carried separately from
// the message so the two rules cannot be confused for one another in a failure
// report — diagnosing a Debug-level swallow as a StatusDone return would send
// the reader to the wrong line.
type ssFinding struct {
	File   string
	Func   string
	Rule   ssRule
	Line   int
	Detail string
}

func (f ssFinding) key() string { return f.File + ":" + f.Func }

func (f ssFinding) String() string {
	return fmt.Sprintf("%s:%s [%s] line %d: %s", f.File, f.Func, f.Rule, f.Line, f.Detail)
}

// ssCensus is the size of what rule B1 covers, so a later plan knows what is
// left rather than being told it is "mostly done".
type ssCensus struct {
	Files          int // non-test .go files walked
	ToolFuncs      int // functions calling app.Tools.Run/RunEnv/Stream/StreamEnv
	WithErrBranch  int // of those, ones binding the error and testing it against nil
	Branches       int // tool-error branches found (>= WithErrBranch)
	Compliant      int // functions with an error branch and no finding
	Violating      int // functions with at least one finding, before the allowlist
	Allowlisted    int // of those, suppressed by silentSuccessAllowlist
	Unclassified   int // returns the classifier could not decide (see blind spots)
	InfoLevel      int // branches whose loudest log is exactly Info — accepted, pinned
	NoErrorBranch  int // tool-calling functions that never test the error
	DiscardedError int // tool calls whose error is bound to _
}

// --- the ratchet ------------------------------------------------------------

// TestSilentSuccess is the ratchet itself.
func TestSilentSuccess(t *testing.T) {
	violations, stale := checkSilentSuccess(".", silentSuccessAllowlist)

	for _, v := range violations {
		switch v.Rule {
		case ssRuleStatus:
			t.Errorf("silent-success violation (status rule): %s\n"+
				"  That branch handles the error from app.Tools.Run/Stream, so the tool FAILED — and it\n"+
				"  reports task.StatusDone. On the operator's screen that is [OK], indistinguishable from a\n"+
				"  clean result. Return task.ToolDegraded(tool, err, outputs...) with a NIL error to keep\n"+
				"  CONTINUE_ON_TOOL_ERROR parity while telling the truth. Do NOT add an allowlist entry.", v)
		case ssRuleLog:
			t.Errorf("silent-success violation (log-level rule): %s\n"+
				"  The default handler level is Info (internal/core/config/defaults.go), so a tool failure\n"+
				"  whose loudest line is Debug is invisible on a normal run. dnstake's bad arg vector was\n"+
				"  swallowed as a Debug line for months and takeover detection produced zero the whole time.\n"+
				"  Raise it to app.Log.Warn — Info clears the rule, Warn is what a tool failure deserves.\n"+
				"  Do NOT add an allowlist entry.", v)
		}
	}

	for _, s := range stale {
		t.Errorf("stale allowlist entry: %s\n"+
			"  That function no longer exists, no longer calls a tool, or no longer violates rule B1.\n"+
			"  Delete the entry from silentSuccessAllowlist and decrement silentSuccessAllowlistSize.", s)
	}
}

// TestSilentSuccessAllowlistShrinks pins the allowlist size against the map.
func TestSilentSuccessAllowlistShrinks(t *testing.T) {
	got := 0
	for _, fns := range silentSuccessAllowlist {
		got += len(fns)
	}
	switch {
	case got > silentSuccessAllowlistSize:
		t.Errorf("the silent-success allowlist grew to %d entries (constant says %d) — that is never correct.\n"+
			"  A new tool-error branch reports a non-Done status on the day it is written.", got, silentSuccessAllowlistSize)
	case got < silentSuccessAllowlistSize:
		t.Errorf("silentSuccessAllowlist is down to %d entries but silentSuccessAllowlistSize still says %d.\n"+
			"  Lower the constant in the same commit so the ratchet stays tight.", got, silentSuccessAllowlistSize)
	}
}

// TestSilentSuccessAllowlistIsHonest asserts that every allowlist entry is a
// REAL violation right now.
//
// TestSilentSuccessAllowlistShrinks only pins the map against the constant, so
// raising both together would satisfy it — which is exactly how a migration
// list gets padded with entries that were never violations, making a future
// "we fixed 49 sites" claim unfalsifiable. This test consults the detector with
// NO allowlist and requires the unsuppressed violation set to be exactly the
// allowlist, function for function.
func TestSilentSuccessAllowlistIsHonest(t *testing.T) {
	violations, stale := checkSilentSuccess(".", nil)
	if len(stale) > 0 {
		t.Errorf("no allowlist was passed, so there can be no stale entries; got: %v", stale)
	}

	got := map[string]bool{}
	for _, v := range violations {
		got[v.key()] = true
	}
	want := map[string]bool{}
	for file, fns := range silentSuccessAllowlist {
		for _, fn := range fns {
			want[file+":"+fn] = true
		}
	}

	for k := range want {
		if !got[k] {
			t.Errorf("allowlist entry %s is not a violation — it is dead weight that would mask a\n"+
				"  future regression in that same function. Delete it and lower\n"+
				"  silentSuccessAllowlistSize.", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("%s violates rule B1 but is not on the allowlist.\n"+
				"  Fix the branch — do NOT append here; the list only shrinks.", k)
		}
	}
}

// TestSilentSuccessSkipsTestdata asserts the real-tree walk does not pick up the
// fixtures, whose intentional violations would otherwise make the ratchet
// permanently red.
func TestSilentSuccessSkipsTestdata(t *testing.T) {
	violations, _ := checkSilentSuccess(".", silentSuccessAllowlist)
	for _, v := range violations {
		if strings.Contains(v.File, "/testdata/") {
			t.Errorf("the real-tree walk reported a fixture: %s", v)
		}
	}
}

// TestSilentSuccessCensus records the size of rule B1's coverage. Numbers, not
// adjectives: the next plan that picks this up needs to know what is left.
func TestSilentSuccessCensus(t *testing.T) {
	_, _, c := checkSilentSuccessFull(".", silentSuccessAllowlist)
	t.Logf("silent-success census under internal/modules/:\n"+
		"  files walked ................ %d\n"+
		"  tool-invoking functions ..... %d\n"+
		"  with an error branch ........ %d  (%d branches)\n"+
		"  no error branch at all ...... %d\n"+
		"  error bound to _ ............ %d\n"+
		"  compliant ................... %d\n"+
		"  violating ................... %d\n"+
		"  allowlisted ................. %d\n"+
		"  unclassified returns ........ %d\n"+
		"  branches loudest at Info .... %d",
		c.Files, c.ToolFuncs, c.WithErrBranch, c.Branches, c.NoErrorBranch,
		c.DiscardedError, c.Compliant, c.Violating, c.Allowlisted, c.Unclassified, c.InfoLevel)
}

// TestSilentSuccessDetector proves the detector itself works, in BOTH
// directions, against the fixtures in testdata/silentsuccess/.
//
// Without this, "the detector fires", "it does not over-fire" and "the ratchet
// cannot be dodged" would be claims backed only by a mutation someone has to
// remember to repeat. It is also the assertion that makes the detector
// un-guttable: reduce checkSilentSuccess to `return nil, nil` and the positive
// fixtures fail here even though the ratchet stays green.
func TestSilentSuccessDetector(t *testing.T) {
	root := filepath.Join("testdata", "silentsuccess")
	goodFixture := repoRelPath(filepath.Join(root, "good_shapes.go"))
	badFixture := repoRelPath(filepath.Join(root, "bad_shapes.go"))

	t.Run("the status rule fires on exactly the bad shapes", func(t *testing.T) {
		violations, stale := checkSilentSuccess(root, nil)
		if len(stale) != 0 {
			t.Errorf("stale = %v, want empty (no allowlist was passed)", stale)
		}
		got := ssNamesFor(violations, ssRuleStatus)
		want := []string{
			"bothRulesBad",
			"elseBranchBad",
			"helperDoneBad",
			"producedDoneBad",
			"secondCallBad",
			"statusDoneBad",
		}
		if !equalStrings(got, want) {
			t.Fatalf("status violations = %v, want exactly %v\n"+
				"  Missing names mean a StatusDone shape gets reported as OK on the operator's screen.\n"+
				"  Extra names mean a correct fix is now a red test.\n  full: %v", got, want, ssJoin(violations))
		}
	})

	t.Run("the log rule fires with a DISTINCT message", func(t *testing.T) {
		violations, _ := checkSilentSuccess(root, nil)
		got := ssNamesFor(violations, ssRuleLog)
		want := []string{"bothRulesBad", "debugOnlyBad", "elseBranchBad", "secondCallBad"}
		if !equalStrings(got, want) {
			t.Fatalf("log violations = %v, want exactly %v\n  full: %v", got, want, ssJoin(violations))
		}

		// One rule reporting the other's violation would send the reader to the
		// wrong line, so the two messages must not be interchangeable.
		for _, v := range violations {
			switch v.Rule {
			case ssRuleStatus:
				if !strings.Contains(v.Detail, "returns") {
					t.Errorf("status finding does not describe a return: %s", v)
				}
				if strings.Contains(v.Detail, "logged at") {
					t.Errorf("status finding reads like a log finding: %s", v)
				}
			case ssRuleLog:
				if !strings.Contains(v.Detail, "logged at") {
					t.Errorf("log finding does not name a log level: %s", v)
				}
				if strings.Contains(v.Detail, "returns") {
					t.Errorf("log finding reads like a status finding: %s", v)
				}
			}
		}
	})

	t.Run("bothRulesBad produces one finding per rule", func(t *testing.T) {
		// The 2026-08-20 shape broke both halves. A reader handed only one of
		// them fixes half the defect and the task stays invisible or stays [OK].
		violations, _ := checkSilentSuccess(root, nil)
		rules := map[ssRule]int{}
		for _, v := range violations {
			if v.Func == "bothRulesBad" {
				rules[v.Rule]++
			}
		}
		if rules[ssRuleStatus] != 1 || rules[ssRuleLog] != 1 {
			t.Errorf("bothRulesBad findings = %v, want exactly one of each rule", rules)
		}
	})

	t.Run("no over-firing on the good shapes", func(t *testing.T) {
		// A detector that flags correct code gets disabled by the first person it
		// inconveniences, so this is asserted by name rather than by set diff.
		violations, _ := checkSilentSuccess(root, nil)
		for _, v := range violations {
			if v.File == goodFixture {
				t.Errorf("accepted shape reported as a violation: %s", v)
			}
		}
	})

	t.Run("per-branch granularity: a compliant first call does not excuse the second", func(t *testing.T) {
		// This is the hole in the stream-contract ratchet (deferred-items.md
		// § "From plan 15-17"), closed here by construction.
		violations, _ := checkSilentSuccess(root, nil)
		found := false
		for _, v := range violations {
			if v.Func == "secondCallBad" {
				found = true
			}
		}
		if !found {
			t.Error("secondCallBad was not reported — the detector is deciding once per FUNCTION, " +
				"so a function with one compliant and one violating branch passes")
		}
	})

	t.Run("allowlisting a bad shape suppresses every rule in it", func(t *testing.T) {
		allow := map[string][]string{badFixture: {"bothRulesBad"}}
		violations, stale := checkSilentSuccess(root, allow)
		if len(stale) != 0 {
			t.Errorf("stale = %v, want empty — bothRulesBad genuinely violates, so its entry is live", stale)
		}
		for _, v := range violations {
			if v.Func == "bothRulesBad" {
				t.Errorf("allowlisted function still reported: %s", v)
			}
		}
		if len(violations) == 0 {
			t.Error("allowlisting one function silenced everything — the allowlist is not scoped")
		}
	})

	t.Run("an allowlisted compliant function is stale", func(t *testing.T) {
		// The direction that lets a list quietly outlive its migration.
		allow := map[string][]string{goodFixture: {"literalSkipOK"}}
		_, stale := checkSilentSuccess(root, allow)
		if !equalStrings(stale, []string{goodFixture + ":literalSkipOK"}) {
			t.Fatalf("stale = %v, want [%s:literalSkipOK]", stale, goodFixture)
		}
	})

	t.Run("an allowlisted missing function is stale", func(t *testing.T) {
		allow := map[string][]string{badFixture: {"noSuchFunction"}}
		_, stale := checkSilentSuccess(root, allow)
		if !equalStrings(stale, []string{badFixture + ":noSuchFunction"}) {
			t.Fatalf("stale = %v, want [%s:noSuchFunction]", stale, badFixture)
		}
	})

	t.Run("an allowlisted missing file is stale", func(t *testing.T) {
		allow := map[string][]string{"internal/modules/gone.go": {"vanished"}}
		_, stale := checkSilentSuccess(root, allow)
		if !equalStrings(stale, []string{"internal/modules/gone.go:vanished"}) {
			t.Fatalf("stale = %v, want [internal/modules/gone.go:vanished]", stale)
		}
	})

	t.Run("the fixture census is what the blind spots claim", func(t *testing.T) {
		// noErrorBranchOK binds its error to _, so it must be counted as a
		// discarded error rather than reported. Pinning it keeps the package
		// comment's blind-spot list honest.
		_, _, c := checkSilentSuccessFull(root, nil)
		if c.DiscardedError != 1 {
			t.Errorf("DiscardedError = %d, want 1 (noErrorBranchOK)", c.DiscardedError)
		}
		if c.NoErrorBranch != 1 {
			t.Errorf("NoErrorBranch = %d, want 1 (noErrorBranchOK)", c.NoErrorBranch)
		}
		if c.InfoLevel != 1 {
			t.Errorf("InfoLevel = %d, want 1 (infoOnlyOK)", c.InfoLevel)
		}
		if c.Unclassified != 0 {
			t.Errorf("Unclassified = %d, want 0 — every fixture return is decidable", c.Unclassified)
		}
	})
}

// --- detector ---------------------------------------------------------------

// checkSilentSuccess parses every non-test .go file under root and reports
// violations of rule B1 plus stale allowlist entries.
func checkSilentSuccess(root string, allow map[string][]string) ([]ssFinding, []string) {
	v, s, _ := checkSilentSuccessFull(root, allow)
	return v, s
}

func checkSilentSuccessFull(root string, allow map[string][]string) (violations []ssFinding, stale []string, census ssCensus) {
	fset := token.NewFileSet()

	type parsedFile struct {
		rel  string
		dir  string
		file *ast.File
	}
	var files []parsedFile
	// helpers maps a package directory to the declarations in it, for the single
	// level of indirection accepted by shape 2.
	helpers := map[string]map[string][]*ast.FuncDecl{}

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		dir := filepath.Dir(path)
		files = append(files, parsedFile{rel: repoRelPath(path), dir: dir, file: f})
		if helpers[dir] == nil {
			helpers[dir] = map[string][]*ast.FuncDecl{}
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil && fn.Recv == nil {
				helpers[dir][fn.Name.Name] = append(helpers[dir][fn.Name.Name], fn)
			}
		}
		return nil
	})
	if walkErr != nil {
		// Surface as a violation rather than panicking: a parse failure must not
		// be able to turn the ratchet green.
		return []ssFinding{{File: "<walk error>", Func: "-", Rule: ssRuleStatus, Detail: walkErr.Error()}}, nil, census
	}

	census.Files = len(files)

	// violating tracks "<rel>:<func>" that produced at least one finding, so the
	// stale direction can tell a live entry from a dead one.
	violating := map[string]bool{}

	for _, pf := range files {
		for _, decl := range pf.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !ssHasToolCall(fn.Body) {
				continue
			}
			census.ToolFuncs++

			branches, discarded := ssFindErrBranches(fn, fset)
			census.DiscardedError += discarded
			if len(branches) == 0 {
				census.NoErrorBranch++
				continue
			}
			census.WithErrBranch++
			census.Branches += len(branches)

			name := declName(fn)
			var found []ssFinding
			for _, b := range branches {
				fs2, unclassified, infoOnly := ssAnalyzeBranch(b, helpers[pf.dir], fset)
				census.Unclassified += unclassified
				census.InfoLevel += infoOnly
				for i := range fs2 {
					fs2[i].File = pf.rel
					fs2[i].Func = name
				}
				found = append(found, fs2...)
			}
			if len(found) == 0 {
				census.Compliant++
				continue
			}
			census.Violating++
			violating[pf.rel+":"+name] = true
			if containsString(allow[pf.rel], name) {
				census.Allowlisted++
				continue
			}
			violations = append(violations, found...)
		}
	}

	for file, fns := range allow {
		for _, name := range fns {
			if !violating[file+":"+name] {
				stale = append(stale, file+":"+name)
			}
		}
	}

	sort.Slice(violations, func(i, j int) bool { return violations[i].String() < violations[j].String() })
	sort.Strings(stale)
	return violations, stale, census
}

// --- branch discovery -------------------------------------------------------

// ssBranch is the body of an `if` that handles the error returned by a tool call.
type ssBranch struct {
	body *ast.BlockStmt
	line int // line of the tool call, not the if — that is what the reader greps for
}

// ssFindErrBranches locates every tool-error branch in fn, and counts tool calls
// whose error was bound to _ (a blind spot the census pins).
func ssFindErrBranches(fn *ast.FuncDecl, fset *token.FileSet) (out []ssBranch, discarded int) {
	scanList := func(list []ast.Stmt) {
		for i, st := range list {
			switch s := st.(type) {
			case *ast.IfStmt:
				// `if _, err := app.Tools.Run(...); err != nil { ... }`
				as, ok := s.Init.(*ast.AssignStmt)
				if !ok || !ssAssignHasToolCall(as) {
					continue
				}
				errVar, bound := ssErrVar(as)
				if !bound {
					discarded++
					continue
				}
				if body, ok := ssErrBranchOf(s, errVar); ok {
					out = append(out, ssBranch{body: body, line: fset.Position(as.Pos()).Line})
				}
			case *ast.AssignStmt:
				// `res, err := app.Tools.Run(...)` followed by `if err != nil {`
				if !ssAssignHasToolCall(s) {
					continue
				}
				errVar, bound := ssErrVar(s)
				if !bound {
					discarded++
					continue
				}
				for _, later := range list[i+1:] {
					ifSt, ok := later.(*ast.IfStmt)
					if !ok {
						continue
					}
					body, ok := ssErrBranchOf(ifSt, errVar)
					if !ok {
						continue
					}
					out = append(out, ssBranch{body: body, line: fset.Position(s.Pos()).Line})
					break
				}
			}
		}
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.BlockStmt:
			scanList(t.List)
		case *ast.CaseClause:
			scanList(t.Body)
		case *ast.CommClause:
			scanList(t.Body)
		}
		return true
	})
	return out, discarded
}

// ssErrBranchOf returns the block that runs when errVar is non-nil: the `if`
// body for `err != nil`, the `else` block for `err == nil`.
func ssErrBranchOf(ifSt *ast.IfStmt, errVar string) (*ast.BlockStmt, bool) {
	op, ok := ssComparesToNil(ifSt.Cond, errVar)
	if !ok {
		return nil, false
	}
	if op == token.NEQ {
		return ifSt.Body, true
	}
	if blk, ok := ifSt.Else.(*ast.BlockStmt); ok {
		return blk, true
	}
	return nil, false
}

// ssComparesToNil reports whether cond compares errVar against nil, and with
// which operator.
func ssComparesToNil(cond ast.Expr, errVar string) (token.Token, bool) {
	var op token.Token
	found := false
	ast.Inspect(cond, func(n ast.Node) bool {
		if found {
			return false
		}
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.NEQ && bin.Op != token.EQL) {
			return true
		}
		if (ssIsIdent(bin.X, errVar) && ssIsIdent(bin.Y, "nil")) ||
			(ssIsIdent(bin.Y, errVar) && ssIsIdent(bin.X, "nil")) {
			op, found = bin.Op, true
			return false
		}
		return true
	})
	return op, found
}

func ssIsIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// ssErrVar returns the identifier the tool call's error was bound to. Go's
// convention puts it last; a `_` there means the error was discarded.
func ssErrVar(as *ast.AssignStmt) (string, bool) {
	if len(as.Lhs) == 0 {
		return "", false
	}
	id, ok := as.Lhs[len(as.Lhs)-1].(*ast.Ident)
	if !ok || id.Name == "_" {
		return "", false
	}
	return id.Name, true
}

func ssAssignHasToolCall(as *ast.AssignStmt) bool {
	for _, rhs := range as.Rhs {
		if ssHasToolCall(rhs) {
			return true
		}
	}
	return false
}

// ssHasToolCall reports whether n contains a call to <x>.Tools.Run / RunEnv /
// Stream / StreamEnv.
func ssHasToolCall(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		if found {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch sel.Sel.Name {
		case "Run", "RunEnv", "Stream", "StreamEnv":
		default:
			return true
		}
		if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "Tools" {
			found = true
			return false
		}
		return true
	})
	return found
}

// --- branch analysis --------------------------------------------------------

func ssAnalyzeBranch(b ssBranch, pkgHelpers map[string][]*ast.FuncDecl, fset *token.FileSet) (findings []ssFinding, unclassified, infoOnly int) {
	// Status rule.
	for _, ret := range ssReturnsIn(b.body) {
		class, detail := ssClassifyReturn(ret, pkgHelpers, 0)
		switch class {
		case ssClassDone:
			findings = append(findings, ssFinding{
				Rule:   ssRuleStatus,
				Line:   fset.Position(ret.Pos()).Line,
				Detail: "tool-error branch returns " + detail + " (tool call at line " + fmt.Sprint(b.line) + ")",
			})
		case ssClassUnknown:
			unclassified++
		}
	}

	// Log-level rule: the branch must announce the tool failure at a level the
	// default handler prints. quiet is a below-Info log with no Info-or-above
	// companion; loudest records whether anything reached Info.
	quiet, loudest := ssLogLevelsIn(b.body)
	switch {
	case loudest == "":
		// No log at all. Not reported: web/httpx.go returns StatusErrored with a
		// wrapped error there and the scheduler surfaces it.
	case loudest == "Debug" && len(quiet) > 0:
		sel := quiet[0].Fun.(*ast.SelectorExpr)
		findings = append(findings, ssFinding{
			Rule: ssRuleLog,
			Line: fset.Position(quiet[0].Pos()).Line,
			Detail: "tool failure logged at " + sel.Sel.Name + " and nowhere at Info or above " +
				"(tool call at line " + fmt.Sprint(b.line) + ")",
		})
	case loudest == "Info":
		infoOnly = 1
	}
	return findings, unclassified, infoOnly
}

// ssReturnsIn collects the return statements in body, skipping nested function
// literals — a closure's return is not this branch's return.
func ssReturnsIn(body *ast.BlockStmt) []*ast.ReturnStmt {
	var out []*ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			out = append(out, t)
		}
		return true
	})
	return out
}

// ssLogLevelsIn inspects the logger calls in body, skipping nested function
// literals. quiet holds calls below Info; loudest is the highest level seen
// ("", "Info", "Warn" or "Error").
//
// A branch that logs at Debug AND at Warn is not reported: the failure IS
// announced. Only a branch whose loudest word about the tool failure is below
// the default handler level is invisible, and that is the dnstake shape.
func ssLogLevelsIn(body *ast.BlockStmt) (quiet []*ast.CallExpr, loudest string) {
	rank := map[string]int{"Trace": 0, "Debug": 1, "Debugf": 1, "Info": 2, "Infof": 2, "Warn": 3, "Warnf": 3, "Error": 4, "Errorf": 4}
	best := -1
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.FuncLit); ok {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		r, known := rank[sel.Sel.Name]
		if !known || !ssIsLoggerExpr(sel.X) {
			return true
		}
		if r < rank["Info"] {
			quiet = append(quiet, call)
		}
		if r > best {
			best = r
			switch {
			case r >= rank["Error"]:
				loudest = "Error"
			case r >= rank["Warn"]:
				loudest = "Warn"
			case r >= rank["Info"]:
				loudest = "Info"
			default:
				loudest = "Debug"
			}
		}
		return true
	})
	return quiet, loudest
}

// ssIsLoggerExpr recognises the receivers this tree actually uses: `app.Log`,
// and a local identifier named log/logger/lg. Any other name is a blind spot,
// named in the package comment.
func ssIsLoggerExpr(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name == "Log" || t.Sel.Name == "Logger"
	case *ast.Ident:
		switch strings.ToLower(t.Name) {
		case "log", "logger", "lg":
			return true
		}
	}
	return false
}

// --- return classification --------------------------------------------------

type ssClass int

const (
	ssClassNone    ssClass = iota // not a task.Result at all
	ssClassOK                     // an accepted non-Done status
	ssClassDone                   // StatusDone — the violation
	ssClassUnknown                // a Result the classifier cannot decide
)

// ssClassifyReturn classifies the first result expression that looks like a
// task.Result. `return task.Result{...}, fmt.Errorf(...)` therefore classifies
// on the literal, not on the error.
func ssClassifyReturn(ret *ast.ReturnStmt, pkgHelpers map[string][]*ast.FuncDecl, depth int) (ssClass, string) {
	for _, r := range ret.Results {
		if class, detail := ssClassifyExpr(r, pkgHelpers, depth); class != ssClassNone {
			return class, detail
		}
	}
	return ssClassNone, ""
}

func ssClassifyExpr(e ast.Expr, pkgHelpers map[string][]*ast.FuncDecl, depth int) (ssClass, string) {
	switch t := e.(type) {
	case *ast.CompositeLit:
		if !ssIsResultType(t.Type) {
			return ssClassNone, ""
		}
		for _, elt := range t.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Status" {
				continue
			}
			switch ssStatusName(kv.Value) {
			case "StatusDone":
				return ssClassDone, "task.Result{Status: task.StatusDone}"
			case "StatusSkipped", "StatusErrored", "StatusCancelled":
				return ssClassOK, ""
			default:
				return ssClassUnknown, ""
			}
		}
		// A bare task.Result{} has the zero Status, which is neither Done nor an
		// accepted status. Not decidable syntactically.
		return ssClassUnknown, ""

	case *ast.CallExpr:
		switch fun := t.Fun.(type) {
		case *ast.SelectorExpr:
			pkg, ok := fun.X.(*ast.Ident)
			if !ok || pkg.Name != "task" {
				return ssClassNone, ""
			}
			switch fun.Sel.Name {
			case "Produced":
				return ssClassDone, "task.Produced(...), which is StatusDone"
			case "NothingProduced", "ToolDegraded":
				return ssClassOK, ""
			default:
				return ssClassNone, ""
			}
		case *ast.Ident:
			// Shape 2: one level of same-package indirection.
			if depth > 0 {
				return ssClassUnknown, ""
			}
			decls := pkgHelpers[fun.Name]
			if len(decls) == 0 {
				return ssClassNone, ""
			}
			agg := ssClassNone
			detail := ""
			for _, d := range decls {
				for _, ret := range ssReturnsIn(d.Body) {
					c, det := ssClassifyReturn(ret, pkgHelpers, depth+1)
					switch c {
					case ssClassDone:
						return ssClassDone, "helper " + fun.Name + "(...) returning " + det
					case ssClassUnknown:
						agg = ssClassUnknown
					case ssClassOK:
						if agg == ssClassNone {
							agg = ssClassOK
						}
					}
				}
			}
			return agg, detail
		}
		return ssClassNone, ""
	}
	return ssClassNone, ""
}

func ssIsResultType(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && pkg.Name == "task" && t.Sel.Name == "Result"
	case *ast.Ident:
		return t.Name == "Result"
	}
	return false
}

func ssStatusName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	}
	return ""
}

// --- helpers ----------------------------------------------------------------

func ssJoin(fs []ssFinding) string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}
	return strings.Join(out, "\n  ")
}

func ssKeys(fs []ssFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.key())
	}
	sort.Strings(out)
	return out
}

// ssNamesFor returns the function names reported for one rule, so the two rules
// can be asserted independently.
func ssNamesFor(fs []ssFinding, rule ssRule) []string {
	var out []string
	for _, f := range fs {
		if f.Rule == rule {
			out = append(out, f.Func)
		}
	}
	sort.Strings(out)
	return out
}
