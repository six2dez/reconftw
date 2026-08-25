//go:build realtools

// realtools_census_test.go — skip accounting and the known-absent ratchet for
// the three real-tool arg-vector probes in this package.
//
// # WHY THIS EXISTS
//
// Before this file, an absent binary produced `t.Skip()` and nothing else. The
// package reported "37 PASS / 0 FAIL" and a sign-off reader had no way to see
// that nine tools had never been probed at all. `scripts/release-gates.sh`
// already knows this is wrong — its `require_tool` records SKIPPED precisely so
// the summary can say "a SKIPPED step was NOT executed. It is not a pass." This
// file gives the arg-vector probes the same posture.
//
// Every probe now reports through recordProbe, and each test ends with
// reportRealtoolsCensus, which prints ONE greppable line naming every skipped
// tool and then applies the ratchet.
//
// # THE THREE MODES, AND WHY THERE ARE THREE
//
// The plan asked for a both-directions ratchet against a list of tools known to
// be absent from a reference provisioned box. That list is a property of ONE
// BOX, and running the ratchet unconditionally would fail on every other one —
// which is how a guard gets disabled within a week. The mode is therefore
// detected, and the mode is always printed:
//
//	NOT EXECUTED  fewer than realtoolsMinToolchain distinct tools present. The
//	              run says so and FAILS. This is the developer laptop with no
//	              toolchain: not a pass, and not a wall of per-tool failures.
//	CENSUS ONLY   a partial toolchain (the default). The census line is printed
//	              in full; the ratchet is NOT enforced, and the output says so in
//	              those words. A partial box cannot arbitrate a list that
//	              describes a complete one.
//	REFERENCE     REALTOOLS_REFERENCE=1. Both ratchet directions are enforced.
//	              This is what `scripts/release-gates.sh` runs on the provisioned
//	              box, and it is the only mode in which a green run means the
//	              known-absent list is accurate.
//
// CENSUS ONLY is the honest default, but it is also the mode in which this file
// asserts least — so it never claims otherwise. The gate script reads the mode
// off the census line and records SKIPPED when it is not REFERENCE.
//
// # THE RATCHET, BOTH DIRECTIONS
//
//	forward  a tool that is ABSENT and not on the list FAILS. The list is the
//	         only way to be absent, so a newly-missing tool cannot arrive as a
//	         silent skip.
//	stale    a tool that is PRESENT and still on the list FAILS. The list cannot
//	         outlive its reason. This is the direction that matters: the entries
//	         were added because one box lacked those tools, and without this
//	         direction they would stay listed forever after being installed.
package backend_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

// realtoolsMinToolchain is the floor below which a run is NOT EXECUTED rather
// than mostly-skipped.
//
// Chosen as a fraction rather than a count because the three probes cover very
// different numbers of tools (47, 26 and 20 subtests as of 2026-08-24). A box
// with under a third of a probe's tools cannot say anything useful about that
// probe's coverage, and reporting 30 individual failures would bury the one
// fact that matters: the toolchain is not installed.
const realtoolsMinToolchainRatio = 0.34

// smokeKnownAbsent is the known-absent list for TestRealToolArgVectors.
//
// SEEDED from the 2026-08-20 provisioned-box run recorded in 16-04-PLAN.md,
// which reported 37 PASS / 0 FAIL / 9 SKIPPED. It has NOT been re-verified on a
// provisioned box since — the box that introduced this file is a partial-
// toolchain developer machine and ran in CENSUS ONLY mode, where the ratchet is
// deliberately not enforced.
//
// EXPECT THE FIRST REFERENCE RUN TO FAIL, and read that as the ratchet working
// rather than as a defect in it: this list is nine months of drift away from
// whatever the box carries today. Delete what is present, add what is absent,
// and the second run is meaningful.
//
// DELETE entries as tools are installed. An entry here is a tool NOBODY IS
// PROBING.
var smokeKnownAbsent = map[string]string{
	"arjun":     "python tool, uv-installed; absent on the 2026-08-20 reference box",
	"dnscewl":   "repo-clone tool, not on PATH",
	"p1radup":   "python tool, uv-installed",
	"regulator": "repo-clone python tool, run via its own venv",
	"subwiz":    "python tool, uv-installed",
	"subzy":     "go tool; see 16-04-SUMMARY — its PRODUCTION arg vector is wrong",
	"urless":    "python tool, uv-installed",
	"wafw00f":   "python tool, uv-installed",
	"waymore":   "python tool, uv-installed",
}

// vulnsKnownAbsent is the known-absent list for TestRealtoolsVulnsPhase6.
//
// DERIVED BY RUNNING IT, not assumed — this probe had never executed before
// this plan, so no prior list existed. Observed on the 2026-08-24 developer box.
// It is a partial toolchain, so treat these as a starting point for the first
// reference run, not as the reference set.
var vulnsKnownAbsent = map[string]string{
	"sqlmap":     "system/repo-clone tool; observed absent 2026-08-24",
	"testssl.sh": "repo-clone shell tool; observed absent 2026-08-24",
}

// osintKnownAbsent is the known-absent list for TestRealtoolsOSINTPhase7.
// Same provenance and same caveat as vulnsKnownAbsent.
var osintKnownAbsent = map[string]string{
	"EmailHarvester": "repo-clone python tool; observed absent 2026-08-24",
	"dorks_hunter":   "repo-clone python tool; observed absent 2026-08-24",
	"ghleaks":        "repo-clone go tool; observed absent 2026-08-24",
	"gato":           "repo-clone python tool; observed absent 2026-08-24",
	"SwaggerSpy":     "repo-clone python tool; observed absent 2026-08-24",
	"Spoofy":         "repo-clone python tool; observed absent 2026-08-24",
	"cmseek":         "repo-clone python tool; observed absent 2026-08-24",
}

// probeCensus accumulates one test function's per-tool outcomes.
//
// Guarded by a mutex even though the probes are sequential today: a future
// t.Parallel() in a subtest would otherwise corrupt the census silently, and a
// corrupted census is worse than none.
type probeCensus struct {
	mu      sync.Mutex
	present map[string]bool
	absent  map[string]bool
}

func newProbeCensus() *probeCensus {
	return &probeCensus{present: map[string]bool{}, absent: map[string]bool{}}
}

// recordPresent notes that tool's binary was found and its probe ran.
func (c *probeCensus) recordPresent(tool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.present[tool] = true
	delete(c.absent, tool)
}

// recordAbsent notes that tool's binary was not found, so its arg vector was
// NOT verified.
func (c *probeCensus) recordAbsent(tool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.present[tool] {
		c.absent[tool] = true
	}
}

func (c *probeCensus) sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// realtoolsMode returns the mode this run is in, and why.
func realtoolsMode(c *probeCensus) (mode, reason string) {
	c.mu.Lock()
	nPresent, nAbsent := len(c.present), len(c.absent)
	c.mu.Unlock()
	total := nPresent + nAbsent

	if total == 0 {
		return "NOT_EXECUTED", "no probes recorded an outcome at all"
	}
	ratio := float64(nPresent) / float64(total)
	if ratio < realtoolsMinToolchainRatio {
		return "NOT_EXECUTED", fmt.Sprintf(
			"only %d of %d probed tools are on PATH (%.0f%%, floor %.0f%%) — this is a box without the toolchain, "+
				"not a box with findings", nPresent, total, ratio*100, realtoolsMinToolchainRatio*100)
	}
	if os.Getenv("REALTOOLS_REFERENCE") == "1" {
		return "REFERENCE", "REALTOOLS_REFERENCE=1 — the known-absent ratchet is enforced in both directions"
	}
	return "CENSUS_ONLY", fmt.Sprintf(
		"%d of %d probed tools on PATH; set REALTOOLS_REFERENCE=1 on a provisioned box to enforce the ratchet",
		nPresent, total)
}

// reportRealtoolsCensus prints the machine-readable census line and applies the
// ratchet according to the detected mode.
//
// The census line format is stable and greppable — scripts/release-gates.sh
// parses it — and it prints tool NAMES, because "9 skipped" is not actionable
// and "9 skipped: arjun dnscewl …" is.
func reportRealtoolsCensus(t *testing.T, testName string, c *probeCensus, knownAbsent map[string]string) {
	t.Helper()

	mode, reason := realtoolsMode(c)
	c.mu.Lock()
	present := c.sorted(c.present)
	absent := c.sorted(c.absent)
	c.mu.Unlock()

	t.Logf("REALTOOLS_CENSUS test=%s mode=%s present=%d skipped=%d skipped_tools=%s",
		testName, mode, len(present), len(absent), joinOrNone(absent))
	t.Logf("REALTOOLS_CENSUS_REASON test=%s %s", testName, reason)

	switch mode {
	case "NOT_EXECUTED":
		t.Errorf("%s: NOT EXECUTED — %s.\n"+
			"  This is a FAILURE and not a pass: no arg vector was verified, so the run says nothing\n"+
			"  about whether the tools accept what the Tasks send them. Install the toolchain, or run\n"+
			"  this target only on a provisioned box.\n"+
			"  tools on PATH: %s", testName, reason, joinOrNone(present))
		return

	case "CENSUS_ONLY":
		t.Logf("%s: the known-absent ratchet was NOT ENFORCED in this mode. The skip list above is a\n"+
			"  report, not an assertion. Only a REFERENCE run can tell a correct known-absent list\n"+
			"  from a stale one.", testName)
		// PREVIEW, not an assertion. A mode that asserts nothing and says nothing
		// is inert, and an inert mode is the default mode — so it reports what the
		// ratchet WOULD say. The operator sees the delta before the provisioned-box
		// run rather than discovering it there.
		fwd, stale := ratchetDelta(c, present, absent, knownAbsent)
		if len(fwd) == 0 && len(stale) == 0 {
			t.Logf("%s: RATCHET PREVIEW — the known-absent list matches this box exactly.", testName)
			return
		}
		if len(fwd) > 0 {
			t.Logf("%s: RATCHET PREVIEW — absent and NOT listed (would FAIL in REFERENCE mode): %s",
				testName, strings.Join(fwd, ","))
		}
		if len(stale) > 0 {
			t.Logf("%s: RATCHET PREVIEW — listed but PRESENT here, so stale on this box (would FAIL in\n"+
				"  REFERENCE mode): %s\n"+
				"  If this box is not the reference box, that is expected and is not a defect.",
				testName, strings.Join(stale, ","))
		}
		return
	}

	// REFERENCE mode: both directions.
	for _, tool := range absent {
		if _, listed := knownAbsent[tool]; !listed {
			t.Errorf("%s: %q is ABSENT and not on the known-absent list.\n"+
				"  Its arg vector was not verified by this run, and nothing else in the tree verifies it.\n"+
				"  Either install it, or add it to the list WITH the reason it is missing — a skip that\n"+
				"  nobody wrote down is indistinguishable from coverage.", testName, tool)
		}
	}
	for tool, why := range knownAbsent {
		if c.present[tool] {
			t.Errorf("%s: %q is on the known-absent list (%q) but is PRESENT on this box.\n"+
				"  Delete the entry. A list that outlives its reason quietly excuses the next genuine\n"+
				"  absence, which is the whole failure mode this ratchet exists to stop.", testName, tool, why)
		}
	}
}

// ratchetDelta computes both ratchet directions without asserting either, so
// CENSUS_ONLY can preview what REFERENCE would decide.
func ratchetDelta(c *probeCensus, present, absent []string, knownAbsent map[string]string) (forward, stale []string) {
	for _, tool := range absent {
		if _, listed := knownAbsent[tool]; !listed {
			forward = append(forward, tool)
		}
	}
	presentSet := map[string]bool{}
	for _, p := range present {
		presentSet[p] = true
	}
	for tool := range knownAbsent {
		if presentSet[tool] {
			stale = append(stale, tool)
		}
	}
	sort.Strings(forward)
	sort.Strings(stale)
	return forward, stale
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ",")
}
