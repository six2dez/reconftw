// argvector_coverage_test.go — the completeness census over EVERY registered
// Task, hermetically.
//
// NO BUILD TAG AND NO BINARIES. Like toolflags_test.go and
// argvector_drift_test.go, this runs under a PATH stripped of the tool tree.
//
// # WHY A THIRD LAYER
//
// Plan 16-04 built two hermetic layers and both work. What neither could do is
// say what they DID NOT COVER. `driveCases` held two entries against 97
// registered Tasks and `undrivableTasks` held three, so 92 Tasks were in no
// list at all — and `subdomains.brute` was one of them. That is precisely why
// CR-01 (`puredns bruteforce -d <bare domain>`) survived the guard built to
// catch its class: the guard never looked.
//
// 16-04's own summary states the number honestly — `PROBE_DRIFT_COVERAGE
// checked=1 of 44`. An honest number is not coverage. This file makes the
// number an ASSERTION: every registered Task lands in exactly one accounted
// bucket, the totals are pinned constants, and a Task that lands in none is a
// FAILURE rather than a silent omission.
//
// # THE THREE LAYERS, AND WHAT EACH CATCHES
//
// Say which class you are giving up before deleting one of these.
//
//	toolflags_test.go        an UNDEFINED flag NAME (`puredns -rt`,
//	                         `subzy --verify-ssl`). Hermetic.
//	argvector_drift_test.go  a DEFINED flag used with the WRONG MEANING, by
//	                         comparing the probe table's flag-name set against
//	                         the Task's. Hermetic.
//	this file                a Task NOBODY IS CHECKING AT ALL. Hermetic.
//
// The middle one is not a nicety, and the puredns bug is the proof. `-d` IS a
// real `puredns bruteforce` flag — it names a FILE of domains — so once
// knownToolFlags was re-sourced from `puredns bruteforce --help` the flag-name
// layer could no longer see the bug at all. What caught it was the drift
// detector, because the probe table has always used the POSITIONAL form that
// `puredns bruteforce --help` documents. One real bug, two different layers,
// two different failures, and neither layer alone was sufficient.
//
// # SANDBOX
//
// Driving 97 Tasks means running code that was never written to be run in a
// unit test. Two containment rules, both asserted:
//
//	filesystem  every Task gets a fresh t.TempDir() and nothing else; the
//	            workspace file count is compared before and after.
//	network     a few Tasks (osint.ip_info, subdomains.geo, web.wellknown,
//	            web.portscan) use net/http DIRECTLY, bypassing the
//	            arg-capturing backend entirely. HTTP(S)_PROXY is pointed at a
//	            closed local port for the duration, so any such call fails at
//	            connect instead of reaching a third party from `go test`.
package backend_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	tomlv2 "github.com/pelletier/go-toml/v2"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// censusTaskDeadline bounds one Task's drive. A Task that outruns it is
// REPORTED BY NAME and counted as NOT covered — never dropped.
const censusTaskDeadline = 5 * time.Second

// ---------------------------------------------------------------------------
// The reasoned buckets
// ---------------------------------------------------------------------------

// noDispatchTasks names Tasks that dispatch NO external tool under the generic
// seed, with the reason. Every entry needs a non-empty reason
// (TestCensusBucketsCarryReasons).
//
// A Task in here asserts nothing about an arg vector, and that is the point of
// writing it down: "it dispatched nothing" and "it has no arg vector to check"
// are different facts, and only one of them is coverage.
//
// EVERY REASON BELOW IS THE TASK'S OWN, read off the logger the census attaches
// to each drive — not inferred by reading the code. An inferred reason can be
// wrong, and this file exists because inferred coverage was wrong.
var noDispatchTasks = map[string]string{
	// --- no external tool at all -------------------------------------------
	// 18-06 CORRECTION. The old reason read "pure Go DNS/zone analysis over the
	// seeded corpus; dispatches no external tool, so there is no arg vector to
	// check". FALSE of the file: SubNSDelegationTask.Run dispatches dnsx through
	// app.Tools.Run at internal/modules/subdomains/scraping.go:366 and builds a
	// real arg vector (-l/-ns/-resp/-silent, plus -t and -rl). It lands in this
	// bucket for an INPUT reason, not an absence-of-tool one. This Task logs
	// nothing on that early return, so the census's own logger could not
	// contradict the claim — which is precisely how an inferred reason survives.
	"subdomains.ns_delegation":    "reads subdomains/subdomains.txt and returns StatusSkipped before its dnsx dispatch when that file is absent; the generic seed writes inputs/subdomains.txt, a DIFFERENT path, so the Task never reaches app.Tools.Run(\"dnsx\", ...) at scraping.go:366. Seeding subdomains/subdomains.txt would drive it, and dnsx HAS a flag table, so it would land in `checked` rather than `notable`",
	"subdomains.resolvers.health": "reads and scores the resolver file in Go; dispatches no external tool",
	"web.url_ext":                 "classifies the URL corpus by extension in Go; dispatches no external tool (logged \"completed corpus_urls=3 extensions=0\")",
	"web.wellknown":               "fetches /.well-known/* with its own net/http client, never a tool; also gated off by default (cfg.Web.WellKnown.Enabled=false)",

	// --- gated on richer input than a generic seed can fabricate ------------
	"osint.metadata": "enriches documents already downloaded into the workspace; logs \"no workspace docs — skipping enrichment\". Seeding a realistic document corpus is a fixture, not a seed",

	// --- DEEP-gated: correct behaviour, not a gap --------------------------
	"vulns.spray": "DEEP-gated by design — \"use --deep or set spray.deep_only=false\". Flipping the gate in the seed would drive a credential-spraying Task from a unit test",
	"web.arjun":   "deep_only=true and the census runs in normal mode — \"skipped — deep_only=true and not in deep mode\"",

	// --- reaches a dispatch only on richer input, or on a populated PATH ----
	//
	// THIS HEADING USED TO READ "BYPASSES backend.Runner: a FINDING", and it was
	// false of every entry left under it by the end of phase 18. Phase 18 routed
	// the whole bypass cohort onto the seam (BYPASS_CENSUS 14 files/30 sites ->
	// 3 files/5 sites); no Task named below builds a command with
	// exec.CommandContext any more. What each one still does is decline to reach
	// its dispatch under the census sandbox — an empty PATH and an empty tools
	// root — and THAT is what puts it in this bucket.
	//
	// 18-06 re-checked all ten reasons in this map against their own files. Two
	// were wrong: web.screenshot (below) and subdomains.ns_delegation (above).
	// Both were rewritten rather than deleted, because bucket MEMBERSHIP was
	// correct in both cases and only the stated cause was false — the same
	// correction 18-04 made for web.shortscan.
	"vulns.llm": "julius is not in tools.lock, so the Runner returns \"tool not registered\" and the best-effort branch swallows it; no argv is ever built",
	// 18-06 CORRECTION. The old reason read "exec.CommandContext at
	// web/screenshot.go, bypassing backend.Runner (FINDING)". That file contains
	// NO direct dispatch and never did in this tree: its only tool call is
	// app.Tools.Stream at web/screenshot.go:152, and its only exec reference is
	// the exec.LookPath availability gate at :76. Verified with
	// `grep -n 'CommandContext\|app.Tools' internal/modules/web/screenshot.go`.
	// The claim was unfalsifiable prose of exactly the shape 18-03's manifest
	// STALE check now refuses — MUTATION 3 in 18-03 proved the manifest would
	// reject this very sentence. The true reason is read off the Task's own log.
	"web.screenshot": "gates on exec.LookPath(\"nuclei\") at web/screenshot.go:76 and the census sandbox has an EMPTY PATH — \"web.screenshot: nuclei binary not found — skipping (D-W6)\". It dispatches through app.Tools.Stream (screenshot.go:152), not around it; seeding a nuclei stub onto PATH plus a templates dir would drive it",
	// 18-04 brought web.shortscan home to backend.Runner, so its OLD reason here
	// ("exec.CommandContext ... bypassing backend.Runner") is now FALSE and would
	// be exactly the stale claim 18-03's manifest checks refuse. It stays in this
	// bucket for a DIFFERENT and true reason, read off its own log rather than
	// predicted: the generic seed writes no inputs/findings.nuclei.jsonl, so the
	// Task skips at its input gate long before it reaches a dispatch.
	"web.shortscan": "reads IIS targets from inputs/findings.nuclei.jsonl, which the generic seed does not write — \"inputs/findings.nuclei.jsonl absent — IIS target detection skipped\". It DOES now dispatch through backend.Runner (18-04); seeding a nuclei staging file with an iis-version record would drive it",
}

// censusExcludedTasks names Tasks deliberately kept out of the generic drive,
// with the reason. Same reason requirement.
var censusExcludedTasks = map[string]string{}

// ---------------------------------------------------------------------------
// Pinned totals
// ---------------------------------------------------------------------------
//
// Every bucket is a constant. A Task added later cannot slip into an unchecked
// bucket without a visible diff, which is the whole mechanism: 16-04's coverage
// drained away without one.

// 17-07 (CR-05) DELETED subdomains.passive.hackertarget, so three constants fall
// by exactly one: registered 97 -> 96, driven 76 -> 75, checked 22 -> 21. This is
// the ONE case where a falling number is not coverage draining away — the Task it
// counted is gone, not unchecked. It was `driven` and `checked` because it did
// dispatch a tool (httpx, which has a flag table); the accounting-identity test
// named all three rather than the change being guessed at.
//
// Why it went: it ran `httpx -silent -u <hackertarget api url>` and parsed the
// output as the API response BODY. httpx prints the PROBED URL, which contains no
// comma, so the URL was lowercased and staged as a hostname and the Task reported
// `subdomains_found: 1` on every run; the scope filter dropped it downstream. It
// never once staged a real subdomain. subfinder queries hackertarget among its own
// sources, so the data source is retained.
const (
	censusRegistered = 96
	censusDriven     = 83
	// checked 17 -> 20 and notable 59 -> 56 when Task 2 added the sj and subjs
	// flag tables: three Tasks (osint.swagger, subdomains.scraping, web.subjs)
	// moved from "dispatched, checked by nothing" to "checked". A rise here is
	// what adding a flag table is FOR.
	//
	// checked 20 -> 22 and notable 56 -> 54 when 17-06 added the gotator and
	// regulator flag tables (CR-03, CR-04). Two more Tasks — subdomains.permut
	// and subdomains.permut.regex — moved from "dispatched, checked by nothing"
	// to "checked". Both had been dispatching a vector nothing looked at, and
	// both were wrong.
	// checked 22 -> 21 when 17-07 deleted subdomains.passive.hackertarget (above).
	// 18-04 ROUTED SIX BYPASSING FILES ONTO backend.Runner, and coverage goes UP
	// rather than down. driveTaskGeneric dispatches against a registry seeded
	// from the whole of tools.lock and never checks Tool.Path, so a Task that
	// used to skip at its own exec.LookPath gate now reaches the arg-capturing
	// backend and leaves `nodispatch` for a DRIVEN bucket. Which driven bucket
	// was read off this test's own failure, never predicted: none of Gxss,
	// hakoriginfinder, mantra, dalfox or shortscan has an entry in
	// knownToolFlags, so every one of them lands in `notable` — "dispatched,
	// checked by nothing" — which is an honest statement of where they now
	// stand and an invitation to 18-06 to give them flag tables.
	//
	//	web.gxss            nodispatch -> notable (Gxss)
	//	web.hakoriginfinder nodispatch -> notable (hakoriginfinder)
	//	web.mantra          nodispatch -> notable (mantra)
	//	vulns.xss           nodispatch -> notable (Gxss; dalfox is still gated
	//	                    behind a reflection hit the capture backend does not
	//	                    fabricate, so the second dispatch is not reached)
	//
	// TWO OF THE SIX DID NOT MOVE, and the accounting-identity test said so
	// rather than the prediction being trusted:
	//
	//	vulns.spray     DEEP-gated, returns before any dispatch, so brutus coming
	//	                home changes nothing this census can see.
	//	web.shortscan   skips at its INPUT gate — the generic seed writes no
	//	                inputs/findings.nuclei.jsonl — so it never reaches the
	//	                dispatch it now has. Its noDispatchTasks reason was
	//	                rewritten to say that instead of the bypass claim, which
	//	                the move made false.
	// NET: checked 21 (unchanged — none of these tools has a flag table),
	// notable 54 -> 58, nodispatch 18 -> 14, driven 75 -> 79.
	//
	// 18-05 CONTINUES THE SAME MOVEMENT, and again the bucket was READ OFF THIS
	// TEST'S OWN FAILURE rather than predicted:
	//
	//	web.nomore403  nodispatch -> notable (Task 1). It used to skip at its own
	//	               os.Stat probe against the census's empty tools root; it now
	//	               dispatches through the Runner, whose registry seed does not
	//	               check Tool.Path. "nomore403" has no knownToolFlags entry, so
	//	               it lands in notable — dispatched, checked by nothing.
	//	               driven 79 -> 80, notable 58 -> 59, nodispatch 14 -> 13.
	//
	// Task 2 moved three more, and ONE OF THEM WAS NOT PREDICTED — the test said
	// so and the prediction was corrected, not the test:
	//
	//	vulns.bypass4xx  nodispatch -> notable (nomore403). Predicted.
	//	web.jsa          nodispatch -> notable (JSA). Predicted.
	//	web.wordlistgen  nodispatch -> notable (roboxtractor). NOT PREDICTED. Its
	//	                 noDispatchTasks reason said the Task "generates wordlists
	//	                 in Go ... and getjswords needs the tools root", which was
	//	                 true of BOTH its legs while both bypassed the Runner. Task
	//	                 2 routed the roboxtractor leg onto the seam, so the Task
	//	                 now dispatches under the generic seed and the claim became
	//	                 false. The entry is REMOVED rather than reworded, because
	//	                 unlike web.shortscan in 18-04 this Task really does reach a
	//	                 dispatch now. Its getjswords leg remains a declared bypass
	//	                 (adjudicated in 18-05) and is invisible to this census, as
	//	                 every bypass is — which is what the BYPASS_CENSUS counts.
	//
	// TASK 3 MOVED NO BUCKET AT ALL, and that is recorded rather than left to look
	// like an oversight. vulns.ssrf and osint.github_repos were ALREADY driven and
	// notable — ssrf on ffuf, github_repos on enumerepo — so routing their
	// remaining direct dispatches (interactsh-client, git) onto the seam added
	// tools to those Tasks without moving either Task between buckets. The change
	// IS visible, in the gap list: `interactsh-client` and `git` now appear in
	// ARGV_COVERAGE_GAP, which they could not while nothing dispatched them
	// through the Runner.
	//
	// NET for 18-05: driven 79 -> 83, notable 58 -> 62, nodispatch 14 -> 10,
	// checked UNCHANGED at 21 — none of nomore403, JSA, roboxtractor,
	// interactsh-client or git has a knownToolFlags entry, so every Task involved
	// lands in "dispatched, checked by nothing". That is an honest statement of
	// where they stand and the same invitation to 18-06 that 18-04 left.
	//
	// 18-06 MOVED NO CONSTANT, and the reason is written here rather than left as
	// an absence. This plan routes nothing onto the seam; it reconciles what the
	// five plans before it moved. The first thing it did was RUN the census
	// (`go test -count=1 -v -run TestEveryRegisteredTaskIsAccountedFor
	// ./internal/core/backend/`, exit 0) and read the reported line —
	//
	//	registered=96 driven=83 checked=21 notable=62 nodispatch=10 timedout=0 excluded=3
	//
	// — which already agreed with every pin below, because 18-04 and 18-05 each
	// raised their constants in the SAME diff that moved the Tasks. That is the
	// mechanism working, not an absent check: a bucket cannot absorb a movement
	// silently, so by the time the reconciling plan runs there is nothing left to
	// reconcile. The plan asked for "the failing run that produced the
	// constants"; there was none, and inventing one would be the fabrication this
	// file exists to prevent. MUTATION 1 and MUTATION 2 (below, in
	// TestCensusAccountingIdentity's comment) were run instead, to prove the pins
	// still FAIL on a wrong value rather than merely agreeing with a right one.
	//
	// What 18-06 DID change here is two REASONS, both false of their own files
	// and neither one visible to any count: web.screenshot claimed a direct
	// dispatch that file has never had, and subdomains.ns_delegation claimed it
	// dispatches no external tool while dispatching dnsx. Both are annotated at
	// their entries above. A wrong reason moves no number, which is exactly why
	// it needs a check of its own rather than a pin.
	censusChecked    = 21
	censusNotable    = 62
	censusNoDispatch = 10
	// A TIMED-OUT TASK IS A FAILURE, not a bucket to grow. Pinned at zero so a
	// Task that starts hanging cannot be absorbed as "accounted for".
	censusTimedOut = 0
	censusExcluded = 3
)

// ---------------------------------------------------------------------------
// The census
// ---------------------------------------------------------------------------

type censusOutcome struct {
	task     string
	tool     string
	argv     []string
	bucket   string // driven-checked | driven-notable | nodispatch | timedout | excluded
	panicked string
	// gaps names tools this Task dispatched that have NO flag table.
	gaps []string
	// why carries the Task's own log output when it dispatched nothing — its
	// reason in its own words, rather than a reason inferred from reading it.
	why string
}

// TestEveryRegisteredTaskIsAccountedFor is the guard that would have caught
// subdomains.brute.
func TestEveryRegisteredTaskIsAccountedFor(t *testing.T) {
	blockNetworkEgress(t)

	all := task.Default.All()
	if len(all) == 0 {
		t.Fatal("the Task registry is EMPTY — the blank imports in argvector_drift_test.go are the " +
			"only thing that populates it, and without them this whole file reports full coverage of nothing")
	}

	driven := map[string]driveCase{}
	for _, dc := range driveCases {
		driven[dc.taskName] = dc
	}

	var outcomes []censusOutcome
	for _, tk := range all {
		name := tk.Name()

		if why, ok := censusExcludedTasks[name]; ok {
			outcomes = append(outcomes, censusOutcome{task: name, bucket: "excluded"})
			t.Logf("EXCLUDED %s — %s", name, why)
			continue
		}
		if why, ok := undrivableTasks[name]; ok {
			outcomes = append(outcomes, censusOutcome{task: name, bucket: "excluded"})
			t.Logf("EXCLUDED %s — undrivable: %s", name, why)
			continue
		}

		res := driveTaskGeneric(t, tk, driven[name])
		outcomes = append(outcomes, res)
	}

	// Classify and assert.
	var (
		nChecked, nNotable, nNoDispatch, nTimedOut, nExcluded int
		notableTools                                          = map[string]int{}
	)
	for _, o := range outcomes {
		switch o.bucket {
		case "excluded":
			nExcluded++
		case "timedout":
			nTimedOut++
			t.Errorf("%s EXCEEDED the %s census deadline.\n"+
				"  It is therefore NOT COVERED, and a timed-out Task that is silently dropped is exactly\n"+
				"  the omission this census exists to remove. Give it a driveCase whose seed reaches its\n"+
				"  tool call quickly, or put it in censusExcludedTasks WITH a reason.",
				o.task, censusTaskDeadline)
		case "nodispatch":
			nNoDispatch++
			if o.why != "" {
				t.Logf("NO DISPATCH %s — its own log: %s", o.task, firstLines(o.why, 2))
			}
			if _, ok := noDispatchTasks[o.task]; !ok {
				t.Errorf("%s dispatched NO tool under the generic seed and is not in noDispatchTasks.\n"+
					"  This is the subdomains.brute shape: a Task in NEITHER driveCases NOR any reasoned\n"+
					"  bucket, so nothing checks its arg vector and nothing says so. Either seed it so it\n"+
					"  reaches its tool call, or add it to noDispatchTasks with the reason it has no\n"+
					"  external-tool arg vector to check.", o.task)
			}
		case "driven-checked":
			nChecked++
			for _, g := range o.gaps {
				notableTools[g]++
			}
		case "driven-notable":
			nNotable++
			for _, g := range o.gaps {
				notableTools[g]++
			}
			t.Logf("NOT CHECKED %s -> %s: the Task was driven and dispatched, but %q has no entry in\n"+
				"  knownToolFlags, so its argv is captured and asserted by NOTHING. argv: %v",
				o.task, o.tool, o.tool, o.argv)
		}
		if o.panicked != "" {
			t.Errorf("%s PANICKED under the generic drive: %s\n"+
				"  A Task that cannot survive a seeded workspace is not covered by this census, and the\n"+
				"  panic is itself a finding.", o.task, o.panicked)
		}
	}
	nDriven := nChecked + nNotable
	nRegistered := len(all)

	t.Logf("ARGV_COVERAGE registered=%d driven=%d checked=%d notable=%d nodispatch=%d timedout=%d excluded=%d",
		nRegistered, nDriven, nChecked, nNotable, nNoDispatch, nTimedOut, nExcluded)

	if len(notableTools) > 0 {
		var names []string
		for tool := range notableTools {
			names = append(names, tool)
		}
		sort.Strings(names)
		t.Logf("ARGV_COVERAGE_GAP tools dispatched but with NO flag table: %s", strings.Join(names, ","))
	}

	// The accounting identity. Without it the buckets could each be plausible
	// while a Task fell out of all of them.
	if got, want := nDriven+nNoDispatch+nTimedOut+nExcluded, nRegistered; got != want {
		t.Errorf("bucket totals sum to %d but %d Tasks are registered — %d Task(s) fell out of every "+
			"bucket, which is the exact silence this census removes", got, want, want-got)
	}

	pin := func(label string, got, want int) {
		if got != want {
			t.Errorf("ARGV_COVERAGE %s=%d, pinned constant says %d.\n"+
				"  If coverage went UP, raise the constant in the same change. If it went DOWN, say why:\n"+
				"  a falling number here is coverage draining away, which is how the subdomains.brute\n"+
				"  hole opened in the first place.", label, got, want)
		}
	}
	pin("registered", nRegistered, censusRegistered)
	pin("driven", nDriven, censusDriven)
	pin("checked", nChecked, censusChecked)
	pin("notable", nNotable, censusNotable)
	pin("nodispatch", nNoDispatch, censusNoDispatch)
	pin("timedout", nTimedOut, censusTimedOut)
	pin("excluded", nExcluded, censusExcluded)
}

// TestCensusAccountingIdentity asserts the PINNED CONSTANTS are internally
// consistent, without driving a single Task.
//
// TestEveryRegisteredTaskIsAccountedFor already checks the identity over the
// LIVE counts and then pins each bucket separately. This test checks the same
// identity over the CONSTANTS, and it is not a duplicate of that:
//
//   - It costs microseconds, so an arithmetically impossible pin set is
//     rejected before the ~20-second drive even starts.
//   - It fails on a constant edit that no live count can contradict. Raise
//     censusRegistered by one and lower nothing, and the live test reports one
//     disagreement (registered) while the CONSTANTS silently stop summing. Here
//     that is a second, differently-worded failure that names the identity.
//   - It pins censusDriven as a DERIVED value (checked+notable). The live test
//     computes nDriven the same way, so the live test can never see the two
//     drift apart; only a constants-side check can.
//
// # WHY A PER-BUCKET PIN IS ALSO REQUIRED, PROVEN BY MUTATION
//
// The identity alone is INSUFFICIENT, and 18-06 proved it rather than asserting
// it. MUTATION 1 raised censusNotable 62 -> 63 and lowered censusNoDispatch
// 10 -> 9, keeping the sum at 96. Under the identity alone that is invisible: a
// Task could move between buckets — coverage going down — with the total
// balanced. It fails only because TestEveryRegisteredTaskIsAccountedFor pins
// EVERY bucket individually, which it has done since 17-04:
//
//	ARGV_COVERAGE notable=62, pinned constant says 63.
//	ARGV_COVERAGE nodispatch=10, pinned constant says 9.
//
// So the per-bucket pins are the load-bearing guard and this identity is the
// cheap cross-check that keeps THEM consistent with each other. Deleting either
// one leaves a hole the other does not cover; say which class you are giving up
// before removing one.
func TestCensusAccountingIdentity(t *testing.T) {
	if sum := censusChecked + censusNotable + censusNoDispatch + censusTimedOut + censusExcluded; sum != censusRegistered {
		t.Errorf("the pinned buckets sum to %d but censusRegistered = %d.\n"+
			"  checked=%d + notable=%d + nodispatch=%d + timedout=%d + excluded=%d must equal registered.\n"+
			"  A pin set that cannot describe any real run is not a pin — it is a number that will be\n"+
			"  edited until the test passes, which is the failure mode this census exists to remove.",
			sum, censusRegistered,
			censusChecked, censusNotable, censusNoDispatch, censusTimedOut, censusExcluded)
	}
	if censusChecked+censusNotable != censusDriven {
		t.Errorf("censusDriven = %d but checked(%d) + notable(%d) = %d.\n"+
			"  `driven` is DERIVED, not measured: the live census computes it as checked+notable, so it\n"+
			"  can never report this disagreement. Only a constants-side identity can.",
			censusDriven, censusChecked, censusNotable, censusChecked+censusNotable)
	}
	if censusTimedOut != 0 {
		t.Errorf("censusTimedOut = %d, want 0. A timed-out Task is NOT COVERED; pinning a non-zero "+
			"value converts a hang into an accounted bucket, which is the absorption this file forbids.",
			censusTimedOut)
	}
	if len(noDispatchTasks) != censusNoDispatch {
		t.Errorf("noDispatchTasks holds %d entries but censusNoDispatch = %d.\n"+
			"  Every Task in the nodispatch bucket must have an entry (the live census errors if one\n"+
			"  does not), so a surplus entry is a STALE excuse for a Task that has come home, and a\n"+
			"  shortfall means the pin was raised without writing the reason.",
			len(noDispatchTasks), censusNoDispatch)
	}
}

// TestCensusBucketsCarryReasons asserts the reasoned buckets are reasoned,
// exactly as TestUndrivableListIsPinned already does for its list.
func TestCensusBucketsCarryReasons(t *testing.T) {
	for _, b := range []struct {
		name string
		m    map[string]string
	}{
		{"noDispatchTasks", noDispatchTasks},
		{"censusExcludedTasks", censusExcludedTasks},
	} {
		for name, why := range b.m {
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s[%q] has no reason — an unexplained bucket entry is indistinguishable from "+
					"an oversight, and this census exists to tell those two apart", b.name, name)
			}
			if _, ok := task.Default.Lookup(name); !ok {
				t.Errorf("%s[%q] names a Task that is NOT REGISTERED — the entry is STALE and is "+
					"silently excusing nothing", b.name, name)
			}
		}
	}
	for name := range censusExcludedTasks {
		if _, dup := undrivableTasks[name]; dup {
			t.Errorf("%q is in BOTH censusExcludedTasks and undrivableTasks — one of the two reasons "+
				"is wrong", name)
		}
	}
}

// ---------------------------------------------------------------------------
// The generic drive
// ---------------------------------------------------------------------------

// driveTaskGeneric runs one Task against an arg-capturing backend under a
// deadline, using its explicit driveCase seed when it has one and the generic
// seed otherwise.
func driveTaskGeneric(t *testing.T, tk task.Task, dc driveCase) censusOutcome {
	t.Helper()
	name := tk.Name()
	out := censusOutcome{task: name}

	workDir := t.TempDir()
	cfg := config.Defaults()
	genericSeed(t, workDir, cfg)
	if dc.seed != nil {
		dc.seed(t, workDir, cfg)
	}

	before := countWorkspaceEntries(t, workDir)

	capture := &multiCapture{}
	// A logger, so a Task that dispatches nothing says WHY in its own words.
	// A reason inferred by reading the code is a reason that can be wrong, and
	// this file exists because inferred coverage was wrong.
	logBuf := &syncBuffer{}
	app := &appctx.AppContext{
		Log:    slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Tools:  backend.NewRunner(capture, censusToolRegistry(t), nil),
		Tree:   permissiveTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), censusTaskDeadline)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				out.panicked = fmt.Sprint(r)
			}
			close(done)
		}()
		_, _ = tk.Run(ctx, app)
	}()

	select {
	case <-done:
	case <-time.After(censusTaskDeadline + time.Second):
		out.bucket = "timedout"
		return out
	}

	if after := countWorkspaceEntries(t, workDir); after < before {
		t.Errorf("%s DELETED files from the seeded workspace (%d entries -> %d). The census sandbox is "+
			"a t.TempDir(); a Task that removes seeded input is a finding, not a seeding mistake",
			name, before, after)
	}

	dispatches := capture.all()
	if len(dispatches) == 0 {
		out.bucket = "nodispatch"
		out.why = logBuf.String()
		return out
	}

	// EVERY dispatch, not just the first. A Task that reaches for three tools
	// has three arg vectors, and checking only the first would report the other
	// two as covered. osint.domain_info is the case that proves it: its first
	// dispatch is `whois` (no flag table) and its dnsx record lookups — the ones
	// that were broken — come second.
	checked := false
	for _, d := range dispatches {
		if _, covered := knownToolFlags[d.tool]; !covered {
			out.gaps = appendUnique(out.gaps, d.tool)
			continue
		}
		assertFlagsDefined(t, d.tool, d.args)
		checked = true
		if out.tool == "" {
			out.tool, out.argv = d.tool, d.args
		}
	}
	if !checked {
		out.tool, out.argv = dispatches[0].tool, dispatches[0].args
		out.bucket = "driven-notable"
		return out
	}
	out.bucket = "driven-checked"
	return out
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// blockNetworkEgress points the proxy env at a closed local port for the
// duration of the test.
//
// T-17-04-02. Four module files (osint/ip_info.go, subdomains/geo.go,
// web/wellknown.go, web/portscan.go) build their own http.Client and call out
// DIRECTLY — the arg-capturing backend never sees those, because they are not
// tool dispatches at all. Without this, driving all 97 Tasks would send real
// requests to ipinfo.io and shodan.io from `go test`.
//
// http.DefaultTransport honours ProxyFromEnvironment, so a proxy on a closed
// port turns every such call into an immediate connection refusal.
func blockNetworkEgress(t *testing.T) {
	t.Helper()

	// AN EMPTY PATH remains load-bearing even after phase 18 reduced the declared
	// bypass census to three files/five sites. It prevents the remaining allowed
	// direct subprocesses and legacy LookPath gates from reaching ambient tools;
	// Runner-dispatched tools are intercepted by the arg-capturing backend.
	// Together with the empty tools root seeded below, this keeps the census
	// identical on bare CI and fully provisioned operator hosts.
	t.Setenv("PATH", "")

	const dead = "http://127.0.0.1:1"
	t.Setenv("HTTP_PROXY", dead)
	t.Setenv("HTTPS_PROXY", dead)
	t.Setenv("http_proxy", dead)
	t.Setenv("https_proxy", dead)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	// Belt and braces: both ipinfo.io callers honour this override, so even a
	// proxy-ignoring client lands on a closed local port rather than a vendor.
	t.Setenv("RECONFTW_IPINFO_BASE_URL", "http://127.0.0.1:1")
}

// genericSeed populates a workspace with the artefacts and inputs Tasks
// commonly read, and enables the module gates.
//
// A Task that skips for want of input dispatches nothing, and a Task that
// dispatches nothing READS AS COVERAGE while asserting nothing. The seed is
// therefore deliberately generous.
func genericSeed(t *testing.T, workDir string, cfg *config.Config) {
	t.Helper()
	for _, d := range []string{"inputs", "artefacts", "raw", "logs", "osint", "out"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	in := func(p string) string { return filepath.Join(workDir, "inputs", p) }
	art := func(p string) string { return filepath.Join(workDir, "artefacts", p) }

	// Host / subdomain corpus.
	seedFile(t, in("resolved.merged.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, in("subdomains.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, in("httpx.hosts.txt"), "api.example.com\n")
	seedFile(t, art("subdomains.jsonl"), `{"subdomain":"api.example.com"}`+"\n")
	// LOCAL, CLOSED PORT — never a third-party host. Anything that escapes the
	// arg-capturing backend must land on 127.0.0.1:1.
	seedFile(t, art("hosts.jsonl"),
		`{"host":"api.example.com","url":"http://127.0.0.1:1","scheme":"http","port":"1","status":200,"ip":"127.0.0.1"}`+"\n")
	seedFile(t, art("ips.jsonl"), `{"ip":"127.0.0.1"}`+"\n")
	seedFile(t, in("urls.txt"), "http://127.0.0.1:1/api?x=1\n")
	seedFile(t, in("js.txt"), "http://127.0.0.1:1/app.js\n")
	seedFile(t, in("params.txt"), "http://127.0.0.1:1/api?x=1\n")

	// urls.jsonl carries a JS URL and a GraphQL endpoint. Six Tasks
	// (web.subjs, web.mantra, web.jsa, web.sourcemapper, web.wordlistgen,
	// osint.gqlspection) skip without them, and a skipping Task is not coverage.
	seedFile(t, art("urls.jsonl"),
		`{"url":"http://127.0.0.1:1/api?x=1"}`+"\n"+
			`{"url":"http://127.0.0.1:1/app.js"}`+"\n"+
			`{"url":"http://127.0.0.1:1/graphql"}`+"\n")
	seedFile(t, in("urls.katana.jsonl"), `{"url":"http://127.0.0.1:1/api?x=1"}`+"\n")
	seedFile(t, art("fuzz.jsonl"), `{"url":"http://127.0.0.1:1/admin","status":403}`+"\n")
	seedFile(t, in("passive.merged.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, filepath.Join(workDir, "raw", "sourcemaps", "app.js"), "var a=1;\n")
	seedFile(t, filepath.Join(workDir, "hosts", "portscan_active.gnmap"),
		"Host: 127.0.0.1 ()\tPorts: 22/open/tcp//ssh///\n")

	// gf pattern buckets — seven vulns Tasks gate on a non-empty bucket.
	for _, b := range []string{"xss", "sqli", "ssrf", "redirect", "lfi", "ssti", "rce", "idor", "ssti"} {
		seedFile(t, in(filepath.Join("gf", b+".txt")), "http://127.0.0.1:1/api?x=1\n")
	}

	// nuclei template tree, with the dast/ subdirectory three Tasks stat.
	templates := filepath.Join(workDir, "templates")
	seedFile(t, filepath.Join(templates, "dast", "x.yaml"), "id: x\n")
	seedFile(t, filepath.Join(templates, "x.yaml"), "id: x\n")
	cfg.Paths.NucleiTemplates = templates

	// A SYNTHETIC token file. Six OSINT Tasks skip without one, and every tool
	// they then reach for goes through the arg-capturing backend, so no process
	// starts and no request is made. The value is not a credential.
	tokens := in("github_tokens.txt")
	seedFile(t, tokens, "ghp_0000000000000000000000000000000000\n")
	cfg.Paths.GitHubTokens = tokens
	cfg.Paths.GitLabTokens = tokens

	// Wordlists and resolvers, as real files.
	wl := in("wordlist.txt")
	seedFile(t, wl, "www\napi\ndev\n")
	resolvers := in("resolvers.txt")
	seedFile(t, resolvers, resolverLines(12))

	// AN EMPTY TOOLS ROOT. Clone-backed registry entries and the remaining
	// getjswords clone-path bypass must never resolve against the operator's real
	// $HOME/Tools during a unit test. Keep the legacy DataDir value isolated too,
	// because unrelated task inputs still consult it.
	cfg.Paths.DataDir = filepath.Join(workDir, "tools-root")
	if err := os.MkdirAll(cfg.Paths.DataDir, 0o755); err != nil {
		t.Fatalf("mkdir tools-root: %v", err)
	}
	// 18-02: paths.tools_dir is now the NAMED tools root and Config.ToolsRoot()
	// falls back to $HOME/Tools when it is unset — the same fallback, one level
	// up. Point it at the same empty directory, for the same reason: a census run
	// must not be able to reach a real binary in the operator's home.
	cfg.Paths.ToolsDir = cfg.Paths.DataDir

	cfg.Paths.Resolvers = resolvers
	cfg.Paths.SubsWordlist = wl
	cfg.Paths.SubsWordlistBig = wl
	cfg.Paths.FuzzWordlist = wl
	cfg.Paths.LFIWordlist = wl
	cfg.Paths.SSTIWordlist = wl
	cfg.Paths.ResolversTrusted = resolvers
}

// countWorkspaceEntries counts files under root — the before/after check that
// keeps the sandbox honest (T-17-04-04).
func countWorkspaceEntries(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// ---------------------------------------------------------------------------
// A registry that knows every tool
// ---------------------------------------------------------------------------

var (
	censusRegOnce sync.Once
	censusReg     *backend.ToolRegistry
	censusRegErr  error
)

// censusToolRegistry builds a ToolRegistry from tools.lock.
//
// Runner.Run returns "tool not registered" for an unknown name and never
// reaches the backend, so a registry with two tools in it would classify 95
// Tasks as dispatching nothing — a false green with the shape of coverage.
//
// tools.lock is parsed here rather than read off backend.Default because this
// package's Blocker-7 audit gate forbids *_test.go references to that
// singleton. Parsing the same file keeps default_args and timeout_seconds real.
func censusToolRegistry(t *testing.T) *backend.ToolRegistry {
	t.Helper()
	censusRegOnce.Do(func() {
		data, err := os.ReadFile("tools.lock")
		if err != nil {
			censusRegErr = err
			return
		}
		var lock struct {
			Tools []struct {
				Name           string   `toml:"name"`
				DefaultArgs    []string `toml:"default_args"`
				TimeoutSeconds int      `toml:"timeout_seconds"`
			} `toml:"tools"`
		}
		if err := tomlv2.Unmarshal(data, &lock); err != nil {
			censusRegErr = err
			return
		}
		reg := backend.NewToolRegistry()
		for _, tl := range lock.Tools {
			reg.Register(&backend.Tool{
				Name:        tl.Name,
				DefaultArgs: append([]string(nil), tl.DefaultArgs...),
				// Timeout deliberately NOT applied: tools.lock timeouts are
				// minutes-scale and the backend here never starts a process, so
				// honouring them would only slow the census. default_args DO
				// matter — they reach the argv this census asserts on.
			})
		}
		if len(lock.Tools) == 0 {
			censusRegErr = fmt.Errorf("tools.lock parsed to ZERO tools")
		}
		censusReg = reg
	})
	if censusRegErr != nil {
		t.Fatalf("census tool registry: %v", censusRegErr)
	}
	return censusReg
}

// TestCensusToolRegistryIsPopulated pins the registry the census drives
// through. An empty one would make every Task report "dispatched nothing".
func TestCensusToolRegistryIsPopulated(t *testing.T) {
	reg := censusToolRegistry(t)
	if n := len(reg.All()); n < 50 {
		t.Fatalf("census registry holds %d tools, expected the full tools.lock inventory (>=50). "+
			"A thin registry silently converts every dispatch into 'tool not registered', which this "+
			"census would then report as 'dispatched nothing' — coverage-shaped silence", n)
	}
}

// ---------------------------------------------------------------------------
// multiCapture
// ---------------------------------------------------------------------------

// multiCapture records every dispatch, with the TOOL NAME.
//
// argCapture records argv only, which is enough when the caller already knows
// the tool. The census does not: it drives a Task without knowing what that
// Task will reach for, and the tool name is what decides whether the argv can
// be checked at all.
type multiCapture struct {
	mu    sync.Mutex
	tools []string
	args  [][]string
}

func (c *multiCapture) record(tool string, args []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = append(c.tools, tool)
	c.args = append(c.args, append([]string(nil), args...))
}

type dispatch struct {
	tool string
	args []string
}

// all returns every dispatch, in order.
func (c *multiCapture) all() []dispatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]dispatch, 0, len(c.tools))
	for i := range c.tools {
		out = append(out, dispatch{tool: c.tools[i], args: c.args[i]})
	}
	return out
}

// forTool returns the first dispatch to the named tool.
//
// The FIRST dispatch is not always the interesting one: osint.swagger reaches
// for SwaggerSpy before sj, and subdomains.scraping for favirecon before subjs.
// A capture that only ever kept the first would have asserted on the wrong tool
// for three of the six vectors this phase fixes.
func (c *multiCapture) forTool(name string) ([]string, bool) {
	for _, d := range c.all() {
		if d.tool == name {
			return d.args, true
		}
	}
	return nil, false
}

// syncBuffer is a mutex-guarded bytes.Buffer: the Task under drive may log from
// a goroutine of its own.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// firstLines trims a log dump to its first n lines for a readable census.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

func (c *multiCapture) Exec(_ context.Context, tl *backend.Tool, args []string) (*backend.Result, error) {
	c.record(tl.Name, args)
	return &backend.Result{ExitCode: 0}, nil
}

func (c *multiCapture) ExecEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return c.Exec(ctx, tl, args)
}

func (c *multiCapture) Stream(_ context.Context, tl *backend.Tool, args []string) (<-chan backend.Event, error) {
	c.record(tl.Name, args)
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (c *multiCapture) StreamEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return c.Stream(ctx, tl, args)
}

func (c *multiCapture) HealthCheck(_ context.Context) error { return nil }
func (c *multiCapture) Capacity() int                       { return 1 }

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (c *multiCapture) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return c.ExecEnv(ctx, t, args, opts.Env)
	}
	return c.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (c *multiCapture) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return c.StreamEnv(ctx, t, args, opts.Env)
	}
	return c.Stream(ctx, t, args)
}
