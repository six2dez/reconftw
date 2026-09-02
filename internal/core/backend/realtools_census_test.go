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
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"

	tomlv2 "github.com/pelletier/go-toml/v2"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
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

// ---------------------------------------------------------------------------
// Availability: THREE states, resolved the way production resolves (18-06)
// ---------------------------------------------------------------------------
//
// # WHAT WAS WRONG BEFORE
//
// Every probe below used to check exec.LookPath and, on failure, record the
// tool ABSENT. That was already only half true when it was written and 18-02
// made it a false NEGATIVE: ToolRegistry.Discover resolves a repo-clone tool
// from declared tools.lock coordinates under paths.tools_dir, so a probe that
// checks PATH reports "absent" for a tool PRODUCTION WILL HAPPILY RUN.
//
// A false-negative census is strictly worse than the false-positive one it
// replaces. A tool wrongly called absent is a tool nobody probes, listed with a
// reason that reads plausible forever — and the ratchet's stale direction, the
// one thing that could notice, never fires because the tool never appears
// present.
//
// MEASURED, not argued: eight of the nine entries the old lists carried
// (EmailHarvester, dorks_hunter, gato, SwaggerSpy, Spoofy, cmseek, sqlmap,
// testssl.sh) are ON DISK under ~/Tools on the box this was rewritten on. Their
// clone directories were listed by hand; the derivations are in 18-06-SUMMARY.
// They were UNFINDABLE, never absent.
//
// # THE THREE STATES, MATCHING 18-02's DEFINITIONS EXACTLY
//
//	resolved       Tool.Path is populated — by PATH, or from a declared clone
//	               with its interpreter and script argv prefix. The probe RUNS.
//	unresolvable   the clone DIRECTORY exists but its declared entry point does
//	               not, or containment refused it. Remedy: repair that one clone.
//	absent         not on PATH and nothing on disk. Remedy: install it.
//
// The old vocabulary had one bucket for the last two, which is exactly the
// conflation Gate 13's skip list inherited and the reason the reconbox3
// "29 tools absent" figure cannot be read as 29 uninstalled tools.

// toolAvailability is the three-state partition, mirroring
// ToolRegistry.Absent() / Unresolvable() / a populated Tool.Path.
type toolAvailability int

const (
	toolResolved toolAvailability = iota
	toolUnresolvable
	toolAbsent
	// toolStateUnstated is used ONLY by a seeded known-unavailable file whose
	// entry does not declare a state. It is never an observation.
	toolStateUnstated
)

func (a toolAvailability) String() string {
	switch a {
	case toolResolved:
		return "resolved"
	case toolUnresolvable:
		return "unresolvable"
	case toolAbsent:
		return "absent"
	default:
		return "unstated"
	}
}

// resolvedTool is one tool's resolution, in the shape a probe needs to RUN it:
// the executable, the argv prefix a clone interpreter requires, and the working
// directory a clone that declared clone_workdir must run in.
type resolvedTool struct {
	Name         string
	Availability toolAvailability
	Path         string
	ArgvPrefix   []string
	WorkDir      string
	// Reason is populated for unresolvable (the registry's own text, which
	// always names the path it looked for) and for absent.
	Reason string
	// Registered records whether the name is a tools.lock entry at all. A tool
	// that is not (python3, sh) can only ever be answered by PATH.
	Registered bool
	// ViaPath records WHICH ROUTE answered, observed rather than inferred.
	//
	// 18-06 wrote this field after its own first attempt got it wrong. The first
	// logResolution decided the route from side effects — "no ArgvPrefix and no
	// WorkDir means it came from PATH" — and mislabelled THREE clone-resolved
	// tools as PATH-resolved: `gato` (clone_entry venv/bin/gato), `ghleaks` and
	// `testssl.sh` are console-script / prebuilt-binary clones that need neither
	// an interpreter prefix nor a working directory, so they are indistinguishable
	// from PATH tools by that signal. None of the three is on PATH at all, which a
	// direct exec.LookPath probe showed immediately.
	//
	// The route is now OBSERVED: LookPath is consulted purely as a LABEL, after
	// the registry has already decided availability. It is not part of the
	// availability decision and must never become part of it again.
	ViaPath bool
}

// argv prepends the clone interpreter's script prefix to a probe's arguments.
// For a PATH tool the prefix is empty and this is the identity — the same
// zero-prefix guarantee 18-01 pinned in applyToolContract.
func (r resolvedTool) argv(args []string) []string {
	if len(r.ArgvPrefix) == 0 {
		return args
	}
	out := make([]string, 0, len(r.ArgvPrefix)+len(args))
	out = append(out, r.ArgvPrefix...)
	return append(out, args...)
}

// describe renders a one-line SKIP explanation that names the remedy.
func (r resolvedTool) describe() string {
	switch r.Availability {
	case toolUnresolvable:
		return fmt.Sprintf("UNRESOLVABLE (the clone is on disk; repair or reinstall THAT clone): %s", r.Reason)
	case toolAbsent:
		return fmt.Sprintf("ABSENT (install it): %s", r.Reason)
	default:
		return "resolved"
	}
}

var (
	realtoolsRegOnce sync.Once
	realtoolsReg     *backend.ToolRegistry
	realtoolsRegErr  error
)

// realtoolsRegistry builds the SAME registry production builds: every tools.lock
// row including its clone coordinates, with ToolsDir set from
// Config.ToolsRoot(), Discover()ed once.
//
// Parsed from tools.lock on disk rather than read off backend.Default, per this
// package's Blocker-7 audit gate and following argvector_coverage_test.go's
// precedent.
func realtoolsRegistry(t *testing.T) *backend.ToolRegistry {
	t.Helper()
	realtoolsRegOnce.Do(func() {
		data, err := os.ReadFile("tools.lock")
		if err != nil {
			realtoolsRegErr = err
			return
		}
		var lock struct {
			Tools []struct {
				Name             string   `toml:"name"`
				DefaultArgs      []string `toml:"default_args"`
				CloneDir         string   `toml:"clone_dir"`
				CloneEntry       string   `toml:"clone_entry"`
				CloneInterpreter string   `toml:"clone_interpreter"`
				CloneWorkDir     bool     `toml:"clone_workdir"`
			} `toml:"tools"`
		}
		if err := tomlv2.Unmarshal(data, &lock); err != nil {
			realtoolsRegErr = err
			return
		}
		if len(lock.Tools) == 0 {
			realtoolsRegErr = fmt.Errorf("tools.lock parsed to ZERO tools — every probe would then " +
				"report its tool absent, and a census of nothing reads as a clean run")
			return
		}
		reg := backend.NewToolRegistry()
		for _, tl := range lock.Tools {
			reg.Register(&backend.Tool{
				Name:             tl.Name,
				DefaultArgs:      append([]string(nil), tl.DefaultArgs...),
				CloneDir:         tl.CloneDir,
				CloneEntry:       tl.CloneEntry,
				CloneInterpreter: tl.CloneInterpreter,
				CloneWorkDir:     tl.CloneWorkDir,
			})
		}
		// The REAL tools root — the same one appctx.Boot and health-check pass.
		// A probe that resolved against an empty root would reproduce the very
		// PATH-only blindness this replaces.
		reg.ToolsDir = config.Defaults().ToolsRoot()
		if err := reg.Discover(context.Background()); err != nil {
			realtoolsRegErr = err
			return
		}
		realtoolsReg = reg
	})
	if realtoolsRegErr != nil {
		t.Fatalf("realtools registry: %v", realtoolsRegErr)
	}
	return realtoolsReg
}

// realtoolsResolve answers "can this box run that tool, and how" using the
// registry rather than PATH.
func realtoolsResolve(t *testing.T, name string) resolvedTool {
	t.Helper()
	reg := realtoolsRegistry(t)

	tool, ok := reg.Lookup(name)
	if !ok {
		// Not a tools.lock entry — python3, sh and friends. PATH is the only
		// possible answer and there is no clone to be unresolvable.
		if p, err := exec.LookPath(name); err == nil {
			return resolvedTool{Name: name, Availability: toolResolved, Path: p, ViaPath: true}
		}
		return resolvedTool{
			Name:         name,
			Availability: toolAbsent,
			Reason:       "not a tools.lock entry and not on PATH",
		}
	}
	if strings.TrimSpace(tool.Path) != "" {
		// LABEL ONLY — availability was already decided by Discover above.
		onPath, lookErr := exec.LookPath(name)
		return resolvedTool{
			Name:         name,
			Availability: toolResolved,
			Path:         tool.Path,
			ArgvPrefix:   append([]string(nil), tool.ArgvPrefix...),
			WorkDir:      tool.WorkDir,
			Registered:   true,
			ViaPath:      lookErr == nil && onPath == tool.Path,
		}
	}
	if why, unresolvable := reg.UnresolvableReason(name); unresolvable {
		return resolvedTool{
			Name:         name,
			Availability: toolUnresolvable,
			Reason:       why,
			Registered:   true,
		}
	}
	return resolvedTool{
		Name:         name,
		Availability: toolAbsent,
		Reason:       fmt.Sprintf("not on PATH and no clone directory under %s", reg.ToolsDir),
		Registered:   true,
	}
}

// ---------------------------------------------------------------------------
// The known-unavailable lists, classified by state
// ---------------------------------------------------------------------------

// unavailability is one list entry: WHICH of the two unavailable states, and
// what would fix it.
//
// The state is part of the entry because the remedy differs and because a list
// that cannot tell them apart is what produced Gate 13's conflated skip set. An
// entry claiming a state the box disagrees with FAILS in REFERENCE mode, the
// same way a stale entry does.
type unavailability struct {
	State toolAvailability
	Why   string
}

type knownUnavailable map[string]unavailability

// smokeKnownAbsent is the known-unavailable list for TestRealToolArgVectors.
//
// SEEDED from the 2026-08-20 provisioned-box run recorded in 16-04-PLAN.md,
// which reported 37 PASS / 0 FAIL / 9 SKIPPED. It has NOT been re-verified on a
// provisioned box since.
//
// 18-06 removed `regulator` and added `dnstake`. Every other entry is a
// uv-installed PATH tool with no clone coordinates, so PATH and the registry
// give the same answer and the entry survives the reclassification unchanged in
// meaning.
//
//	regulator REMOVED — its clone is declared in tools.lock and resolves through
//	          the registry (REALTOOLS_RESOLVED tool=regulator via=CLONE
//	          path=~/Tools/regulator/venv/bin/python3). It is not absent on any
//	          box that has the clone, and leaving it listed fails the stale
//	          direction. This is the reclassification's first dividend.
//	dnstake   ADDED — the forward direction demanded it, and it is a verifiable
//	          universal absence rather than a guess: 18-02 established that
//	          ~/Tools/dnstake is an UNBUILT Go source tree (cmd/, go.mod, no
//	          binary), so it resolves nowhere until someone builds it. It was
//	          absent and unlisted, which is precisely the silent skip this list
//	          exists to forbid.
//
// # WHICH BOX THIS LIST DESCRIBES — reconbox3, provisioned, 2026-09-02
//
// The previous revision recorded that a REFERENCE run failed with SEVEN stale
// entries, deliberately left them listed, and set a standing condition:
// "Anyone tempted to 'fix' that by deleting them should first establish which
// box they intend the compiled-in list to describe, and say so here." This does
// that.
//
// THE BOX: reconbox3, the provisioned host the Phase 20 sign-off criterion is
// written against ("`make release-gates` exits 0 on a provisioned box"). The
// 2026-08-20 seed described a host that no longer exists in that state.
//
// THE EVIDENCE: `REALTOOLS_REFERENCE=1 make realtools-args` on reconbox3 on
// 2026-09-02 reported, for all four census tests,
// `absent=0 absent_tools=(none) unresolvable=0 unresolvable_tools=(none)`
// (present = 39 / 25 / 19 / 5). All nine entries below were named by the
// ratchet's STALE direction, and each was then confirmed by hand to resolve to a
// real executable:
//
//	arjun p1radup subwiz urless wafw00f waymore  → ~/.local/bin (uv tool install)
//	subzy dnstake                                → ~/go/bin, compiled ELF binaries.
//	                                               dnstake's is dated 2026-03-13,
//	                                               so "UNBUILT Go source tree"
//	                                               described the developer laptop,
//	                                               never this host.
//	dnscewl                                      → ~/go/bin, built by the new
//	                                               make_clone kind. Its tools.lock
//	                                               entry declared kind="go" with a
//	                                               go_module, which can never
//	                                               install a C++ Makefile project,
//	                                               so this entry was recording an
//	                                               installer defect as a property
//	                                               of the box.
//
// WHY EMPTY RATHER THAN RE-SEEDED: an entry here is a tool NOBODY IS PROBING, so
// the list is a debt, not an asset. Most of these became installable only when
// the tools.lock corrections landed on the same day; keeping them listed would
// re-hide the very arg vectors that installing them exists to verify.
//
// If a future host genuinely lacks a tool, the ratchet's FORWARD direction fails
// and names it. That is the signal to add it back WITH its reason — not to
// pre-populate against a machine nobody has.
var smokeKnownAbsent = knownUnavailable{}

// vulnsKnownAbsent is the known-unavailable list for TestRealtoolsVulnsPhase6.
//
// EMPTIED by 18-06. It held two entries and BOTH were wrong:
//
//	sqlmap      "system/repo-clone tool; observed absent 2026-08-24" — the clone
//	            is at ~/Tools/sqlmap with .venv/bin/python3 and sqlmap.py, both
//	            declared in tools.lock since 18-02. `ls -d ~/Tools/sqlmap/.venv/bin/python3
//	            ~/Tools/sqlmap/sqlmap.py` lists both.
//	testssl.sh  "repo-clone shell tool; observed absent 2026-08-24" — the clone
//	            is at ~/Tools/testssl.sh and its entry point testssl.sh is a
//	            1.2 MB executable shell script (`ls -l ~/Tools/testssl.sh/testssl.sh`).
//
// Neither was ever absent on this box; both were invisible to exec.LookPath.
// They now RESOLVE and their arg vectors are verified against the real tools for
// the first time.
var vulnsKnownAbsent = knownUnavailable{}

// osintKnownAbsent is the known-unavailable list for TestRealtoolsOSINTPhase7.
//
// EMPTIED by 18-06. It held seven entries all reading "repo-clone python tool;
// observed absent 2026-08-24", and SIX of the seven were on disk the whole time.
// Re-derived by listing each directory (outputs in 18-06-SUMMARY):
//
//	EmailHarvester  ~/Tools/EmailHarvester  -> EmailHarvester.py + venv/
//	dorks_hunter    ~/Tools/dorks_hunter    -> dorks_hunter.py + venv/
//	SwaggerSpy      ~/Tools/SwaggerSpy      -> swaggerspy.py + venv/
//	Spoofy          ~/Tools/Spoofy          -> spoofy.py + venv/
//	cmseek          ~/Tools/CMSeeK          -> cmseek.py + venv/  (CASE MISMATCH,
//	                                           which is why a name-derived guess
//	                                           fails and the declared clone_dir works)
//	gato            ~/Tools/gato            -> venv/bin/gato (console script, no interpreter)
//
// The seventh, `ghleaks`, was ALSO wrong in the same direction:
// ~/Tools/ghleaks/ghleaks is a 15 MB built Go binary. Seven of seven.
var osintKnownAbsent = knownUnavailable{}

// fixedVectorKnownAbsent is the expected-unavailable list for
// TestRealtoolsFixedArgVectors.
//
// EMPTY on purpose, unchanged by 18-06. All five binaries are installed on the
// box this was written on, so any absence here is a real gap in the evidence and
// must be declared deliberately — via REALTOOLS_KNOWN_ABSENT for a box that
// genuinely lacks one, not by pre-emptively excusing it here.
var fixedVectorKnownAbsent = knownUnavailable{}

// probeCensus accumulates one test function's per-tool outcomes.
//
// Guarded by a mutex even though the probes are sequential today: a future
// t.Parallel() in a subtest would otherwise corrupt the census silently, and a
// corrupted census is worse than none.
type probeCensus struct {
	mu      sync.Mutex
	present map[string]bool
	// absent is the UNION of the two unavailable states, kept under its original
	// name because scripts/release-gates.sh's Gate 13 reads `skipped_tools=` off
	// the census line and the union is what that field has always meant.
	absent map[string]bool
	// state and reason carry the 18-06 three-state detail, reported alongside
	// the union rather than instead of it.
	state  map[string]toolAvailability
	reason map[string]string
}

func newProbeCensus() *probeCensus {
	return &probeCensus{
		present: map[string]bool{},
		absent:  map[string]bool{},
		state:   map[string]toolAvailability{},
		reason:  map[string]string{},
	}
}

// recordUnavailable is the 18-06 replacement for recordAbsent: it keeps the
// union field the gate script parses AND records which of the two states the
// registry reported, with the registry's own reason text.
func (c *probeCensus) recordUnavailable(tool string, r resolvedTool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.present[tool] {
		return
	}
	c.absent[tool] = true
	c.state[tool] = r.Availability
	c.reason[tool] = r.Reason
}

// byState returns the sorted names in one unavailable state.
func (c *probeCensus) byState(want toolAvailability) []string {
	var out []string
	for tool := range c.absent {
		if c.state[tool] == want {
			out = append(out, tool)
		}
	}
	sort.Strings(out)
	return out
}

// recordPresent notes that tool's binary was found and its probe ran.
func (c *probeCensus) recordPresent(tool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.present[tool] = true
	delete(c.absent, tool)
	delete(c.state, tool)
	delete(c.reason, tool)
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
func reportRealtoolsCensus(t *testing.T, testName string, c *probeCensus, knownAbsent knownUnavailable) {
	t.Helper()

	// A SEEDED list wins over the compiled-in one. See resolveKnownAbsent.
	knownAbsent = resolveKnownAbsent(t, testName, knownAbsent)

	mode, reason := realtoolsMode(c)
	c.mu.Lock()
	present := c.sorted(c.present)
	absentUnion := c.sorted(c.absent)
	trulyAbsent := c.byState(toolAbsent)
	unresolvable := c.byState(toolUnresolvable)
	c.mu.Unlock()

	// The union field (skipped=/skipped_tools=) is UNCHANGED — Gate 13 parses it
	// and 17-03 closed four false greens in that script; renaming it would be a
	// silent parse failure that reads as an empty skip set. The two states are
	// reported ALONGSIDE it, so a reader can tell "install it" from "repair that
	// one clone" without the gate's parser changing meaning.
	t.Logf("REALTOOLS_CENSUS test=%s mode=%s present=%d skipped=%d skipped_tools=%s absent=%d absent_tools=%s unresolvable=%d unresolvable_tools=%s",
		testName, mode, len(present), len(absentUnion), joinOrNone(absentUnion),
		len(trulyAbsent), joinOrNone(trulyAbsent),
		len(unresolvable), joinOrNone(unresolvable))
	t.Logf("REALTOOLS_CENSUS_REASON test=%s %s", testName, reason)
	for _, tool := range unresolvable {
		t.Logf("REALTOOLS_UNRESOLVABLE test=%s tool=%s reason=%s", testName, tool, c.reason[tool])
	}

	switch mode {
	case "NOT_EXECUTED":
		t.Errorf("%s: NOT EXECUTED — %s.\n"+
			"  This is a FAILURE and not a pass: no arg vector was verified, so the run says nothing\n"+
			"  about whether the tools accept what the Tasks send them. Install the toolchain, or run\n"+
			"  this target only on a provisioned box.\n"+
			"  tools resolved: %s", testName, reason, joinOrNone(present))
		return

	case "CENSUS_ONLY":
		t.Logf("%s: the known-unavailable ratchet was NOT ENFORCED in this mode. The skip list above is\n"+
			"  a report, not an assertion. Only a REFERENCE run can tell a correct list from a stale one.",
			testName)
		// PREVIEW, not an assertion. A mode that asserts nothing and says nothing
		// is inert, and an inert mode is the default mode — so it reports what the
		// ratchet WOULD say. The operator sees the delta before the provisioned-box
		// run rather than discovering it there.
		fwd, stale, misstated := ratchetDelta(c, present, absentUnion, knownAbsent)
		if len(fwd) == 0 && len(stale) == 0 && len(misstated) == 0 {
			t.Logf("%s: RATCHET PREVIEW — the known-unavailable list matches this box exactly.", testName)
			return
		}
		if len(fwd) > 0 {
			t.Logf("%s: RATCHET PREVIEW — unavailable and NOT listed (would FAIL in REFERENCE mode): %s",
				testName, strings.Join(fwd, ","))
		}
		if len(stale) > 0 {
			t.Logf("%s: RATCHET PREVIEW — listed but RESOLVED here, so stale on this box (would FAIL in\n"+
				"  REFERENCE mode): %s\n"+
				"  If this box is not the reference box, that is expected and is not a defect.",
				testName, strings.Join(stale, ","))
		}
		if len(misstated) > 0 {
			t.Logf("%s: RATCHET PREVIEW — listed with the WRONG STATE (would FAIL in REFERENCE mode): %s",
				testName, strings.Join(misstated, ","))
		}
		return
	}

	// REFERENCE mode: all three directions.
	//
	// BOTH ORIGINAL DIRECTIONS ARE PRESERVED EXACTLY. 18-03's manifest work and
	// 16-04's design both turn on the stale direction — it is what makes a tool
	// BECOMING resolvable a visible event rather than a silent one, and 18-02
	// made fourteen tools do precisely that. The third direction is additive: it
	// catches an entry that names the wrong remedy, which the old single-bucket
	// list could not express at all.
	for _, tool := range absentUnion {
		if _, listed := knownAbsent[tool]; !listed {
			t.Errorf("%s: %q is %s and not on the known-unavailable list.\n"+
				"  Its arg vector was not verified by this run, and nothing else in the tree verifies it.\n"+
				"  Either install/repair it, or add it to the list WITH its state and the reason — a skip\n"+
				"  that nobody wrote down is indistinguishable from coverage.\n"+
				"  registry reason: %s", testName, tool, c.state[tool], c.reason[tool])
		}
	}
	for tool, entry := range knownAbsent {
		if c.present[tool] {
			t.Errorf("%s: %q is on the known-unavailable list (%s: %q) but RESOLVES on this box.\n"+
				"  Delete the entry. A list that outlives its reason quietly excuses the next genuine\n"+
				"  absence, which is the whole failure mode this ratchet exists to stop.\n"+
				"  NOTE (18-06): after clone-aware resolution, \"resolves\" no longer means \"on PATH\" —\n"+
				"  a declared clone under paths.tools_dir resolves too, and eight entries that had been\n"+
				"  listed as absent for months were exactly that.", testName, tool, entry.State, entry.Why)
			continue
		}
		if observed, unavailable := c.state[tool]; unavailable &&
			entry.State != toolStateUnstated && entry.State != observed {
			t.Errorf("%s: %q is listed as %s but this box reports it %s.\n"+
				"  The two states carry DIFFERENT REMEDIES — absent means install it, unresolvable means\n"+
				"  repair that one clone — so a wrong state sends an operator to the wrong fix. Correct\n"+
				"  the entry.\n  registry reason: %s", testName, tool, entry.State, observed, c.reason[tool])
		}
	}
}

// ratchetDelta computes all three ratchet directions without asserting any, so
// CENSUS_ONLY can preview what REFERENCE would decide.
func ratchetDelta(c *probeCensus, present, absent []string, knownAbsent knownUnavailable) (forward, stale, misstated []string) {
	for _, tool := range absent {
		if _, listed := knownAbsent[tool]; !listed {
			forward = append(forward, tool)
		}
	}
	presentSet := map[string]bool{}
	for _, p := range present {
		presentSet[p] = true
	}
	for tool, entry := range knownAbsent {
		if presentSet[tool] {
			stale = append(stale, tool)
			continue
		}
		if observed, unavailable := c.state[tool]; unavailable &&
			entry.State != toolStateUnstated && entry.State != observed {
			misstated = append(misstated, fmt.Sprintf("%s(listed=%s,observed=%s)", tool, entry.State, observed))
		}
	}
	sort.Strings(forward)
	sort.Strings(stale)
	sort.Strings(misstated)
	return forward, stale, misstated
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "(none)"
	}
	return strings.Join(s, ",")
}

// ---------------------------------------------------------------------------
// Per-box seeding of the known-absent list (17-04)
// ---------------------------------------------------------------------------

// knownAbsentEnv names a file holding the expected-absent set for THIS box.
//
// Following REALTOOLS_REFERENCE's convention: an env var, read at test time, no
// build tag, no flag.
const knownAbsentEnv = "REALTOOLS_KNOWN_ABSENT"

// resolveKnownAbsent returns the seeded expected-absent set for testName when
// REALTOOLS_KNOWN_ABSENT names a readable file, and the compiled-in set
// otherwise.
//
// # WHY THE LIST HAD TO BECOME SEEDABLE
//
// 16-04 hard-coded three lists into Go source and said plainly that they are a
// property of ONE BOX. Three boxes have since produced three different censuses:
// the 2026-08-20 provisioned box, the 2026-08-24 developer laptop, and reconbox3
// (16-06 §2.2), where Gate 13 FAILed exactly as 16-04 predicted. Hard-coding
// makes every box but one wrong, and a guard that is wrong everywhere is a guard
// that gets disabled.
//
// # WHAT SEEDING DOES NOT CHANGE
//
// BOTH RATCHET DIRECTIONS STILL BITE, against whichever list is in force:
// absent-and-unlisted still fails forward, listed-and-present still fails stale.
// Seeding changes WHICH list is compared, never WHETHER it is compared. A seed
// file that is unreadable, unparseable, or has no section for this test is a
// FAILURE — silently falling back would let a typo in the path turn an enforced
// ratchet into an unenforced one while the run still said REFERENCE.
func resolveKnownAbsent(t *testing.T, testName string, compiledIn knownUnavailable) knownUnavailable {
	t.Helper()
	path := strings.TrimSpace(os.Getenv(knownAbsentEnv))
	if path == "" {
		return compiledIn
	}
	seeded, err := parseKnownAbsentFile(path)
	if err != nil {
		t.Fatalf("%s=%q could not be read: %v\n"+
			"  Refusing to fall back to the compiled-in list: a typo in this path would silently turn\n"+
			"  an enforced ratchet into an unenforced one while the run still reported REFERENCE.",
			knownAbsentEnv, path, err)
	}
	section, ok := seeded[testName]
	if !ok {
		t.Fatalf("%s=%q has no [%s] section.\n"+
			"  Every probe needs its own expected-absent set; an absent section is not an empty one.",
			knownAbsentEnv, path, testName)
	}
	t.Logf("REALTOOLS_KNOWN_ABSENT test=%s source=%s entries=%d (compiled-in list of %d NOT used)",
		testName, path, len(section), len(compiledIn))
	return section
}

// parseKnownAbsentFile reads the INI-ish seed format documented in
// testdata/known-absent.reconbox3.txt.
//
// A reason is REQUIRED on every entry, for the same reason it is required on the
// compiled-in maps: an unexplained skip is indistinguishable from coverage.
func parseKnownAbsentFile(path string) (map[string]knownUnavailable, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied test fixture path
	if err != nil {
		return nil, err
	}
	out := map[string]knownUnavailable{}
	section := ""
	for n, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				return nil, fmt.Errorf("%s:%d: empty section header", path, n+1)
			}
			if _, dup := out[section]; dup {
				return nil, fmt.Errorf("%s:%d: section [%s] appears twice", path, n+1, section)
			}
			out[section] = knownUnavailable{}
			continue
		}
		if section == "" {
			return nil, fmt.Errorf("%s:%d: entry %q before any [section]", path, n+1, line)
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			return nil, fmt.Errorf("%s:%d: %q is not `tool = reason`", path, n+1, line)
		}
		tool, reason := strings.TrimSpace(k), strings.TrimSpace(v)
		if tool == "" || reason == "" {
			return nil, fmt.Errorf("%s:%d: entry %q needs both a tool and a REASON — an unexplained "+
				"skip is indistinguishable from coverage", path, n+1, line)
		}
		// 18-06: an OPTIONAL `absent:` / `unresolvable:` prefix states which of
		// the two states this box reports, so the seed can express the same
		// distinction the compiled-in lists now carry.
		//
		// A value with no prefix parses as toolStateUnstated and the state
		// direction of the ratchet is simply not applied to it. That is
		// deliberate and is NOT a loosening: it is byte-for-byte the behaviour
		// every seeded entry had before this change, and inventing a default
		// would be exactly the absent/unresolvable conflation being removed. The
		// checked-in reconbox3 seed is left unprefixed for that reason — this box
		// cannot observe that box's states, and guessing them would put an
		// unverifiable claim into a file a cutover reviewer reads.
		state := toolStateUnstated
		if prefix, rest, found := strings.Cut(reason, ":"); found {
			switch strings.ToLower(strings.TrimSpace(prefix)) {
			case "absent":
				state, reason = toolAbsent, strings.TrimSpace(rest)
			case "unresolvable":
				state, reason = toolUnresolvable, strings.TrimSpace(rest)
			}
			if state != toolStateUnstated && reason == "" {
				return nil, fmt.Errorf("%s:%d: entry %q states a state but no reason", path, n+1, line)
			}
		}
		out[section][tool] = unavailability{State: state, Why: reason}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s parsed to ZERO sections — an empty seed would silently disable the "+
			"ratchet it is meant to make correct", path)
	}
	return out, nil
}

// TestKnownAbsentSeedFileParses pins the checked-in reconbox3 seed.
//
// A seed file nobody parses is a file that rots. This asserts it parses, is
// non-empty, and carries a section for each of the three probes — so a
// hand-edit that breaks it fails HERE, on a laptop, rather than on the
// provisioned box during a cutover sign-off.
func TestKnownAbsentSeedFileParses(t *testing.T) {
	const path = "testdata/known-absent.reconbox3.txt"
	seeded, err := parseKnownAbsentFile(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	for _, probe := range []string{
		"TestRealToolArgVectors", "TestRealtoolsVulnsPhase6", "TestRealtoolsOSINTPhase7",
	} {
		section, ok := seeded[probe]
		if !ok {
			t.Errorf("%s has no [%s] section", path, probe)
			continue
		}
		if len(section) == 0 {
			t.Errorf("%s: [%s] is empty — an empty section reads as \"nothing is expected absent\", "+
				"which on this box is false", path, probe)
		}
		for tool, entry := range section {
			if strings.TrimSpace(entry.Why) == "" {
				t.Errorf("%s: [%s] %q has no reason", path, probe, tool)
			}
		}
	}
	// The counts recorded in 16-06 §2.2. Pinned so an edit that drops entries is
	// a visible failure rather than a quietly smaller list.
	//
	// 18-06 CAVEAT, recorded and NOT acted on. These three counts were derived
	// from a PATH-ONLY census on reconbox3, before ToolRegistry.Discover could
	// resolve a repo clone. On the box this note was written, that same change
	// moved SIX tools out of the unavailable set (EmailHarvester, dorks_hunter,
	// SwaggerSpy, Spoofy, cmseek, sqlmap all resolve via=CLONE and none of them
	// is on PATH). If reconbox3 carries those clones too, its real counts are
	// LOWER than 9/6/14 by however many it has.
	//
	// The numbers are NOT adjusted here, because this box cannot observe that
	// box and a guessed count is worse than a stale one that says it is stale.
	// Re-derive them there with:
	//
	//	REALTOOLS_REFERENCE=1 make realtools-args 2>&1 | grep REALTOOLS_CENSUS
	//
	// and read absent_tools= and unresolvable_tools= separately — the union in
	// skipped_tools= is what produced the conflated figure in the first place.
	for probe, want := range map[string]int{
		"TestRealToolArgVectors":   9,
		"TestRealtoolsVulnsPhase6": 6,
		"TestRealtoolsOSINTPhase7": 14,
	} {
		if got := len(seeded[probe]); got != want {
			t.Errorf("%s: [%s] holds %d entries, the reconbox3 census recorded %d skipped "+
				"(16-06-PARITY.md §2.2). Reconcile against that record, not against this box.",
				path, probe, got, want)
		}
	}
}
