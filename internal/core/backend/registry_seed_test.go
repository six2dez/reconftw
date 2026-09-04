// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 2.
//
// registry_seed_test.go validates that the embedded tools.lock auto-
// populates backend.Default at init() time with the 10 Phase 4 tools per
// CONTEXT default (b), and that the Critical-tier flagging (Blocker 5)
// for the critical tier (pinned in TestRegistrySeed_CriticalTier) is honored end-to-end.
//
// BLOCKER 7 ALLOWLIST: this is the ONE test file in
// internal/core/backend/ that references backend.Default. Plan 04 tests
// MUST use NewToolRegistry() — they need fresh, hermetic state. The
// audit gate (a grep against backend.Default in *_test.go) explicitly
// exempts this file.
package backend_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// Test 5: After binary startup, backend.Default.All() returns >=10 tools
// sorted alphabetically by name.
func TestRegistrySeed_PopulatesDefault(t *testing.T) {
	all := backend.Default.All()
	if len(all) < 10 {
		t.Fatalf("expected ≥10 tools in backend.Default after init(), got %d", len(all))
	}
	names := make([]string, 0, len(all))
	for _, tool := range all {
		names = append(names, tool.Name)
	}
	// Spot-check: every expected name present.
	wantNames := []string{
		"anew", "asnmap", "crt", "dnsx", "gotator", "httpx",
		"puredns", "s3scanner", "subfinder", "subzy",
	}
	for _, want := range wantNames {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected tool %q in backend.Default; got names=%v", want, names)
		}
	}
}

// Test 6: the critical tier in tools.lock is EXACTLY this set — nothing more,
// nothing less. Membership is deliberately hard to change: the bit aborts
// `install`, decides the exit code of both health-checks, and defines what
// `install --profile core` installs, so a tool added here without thought
// starts failing installs, and one dropped starts passing broken ones.
//
// The list grew from the original {subfinder, httpx, dnsx}, which was scoped to
// "any meaningful Phase 4 run" and never revisited once it began gating the
// installer — leaving 101 of 104 tools able to fail while `install` exited 0.
// The rationale for each addition is written out in tools.lock's header.
func TestRegistrySeed_CriticalTier(t *testing.T) {
	wantCritical := map[string]bool{
		"subfinder": true, // primary passive source
		"httpx":     true, // DAG root of the entire web module
		"dnsx":      true, // DNS resolution
		"puredns":   true, // only wildcard-filtering + brute resolver
		"massdns":   true, // puredns's engine; never invoked directly
		"nuclei":    true, // the findings deliverable, in recon as well as all
		"gf":        true, // candidate source for seven vuln classes
	}
	for _, tool := range backend.Default.All() {
		want, listed := wantCritical[tool.Name]
		if !listed {
			if tool.Critical {
				t.Errorf("tool %q is Critical=true but is not in the declared tier — "+
					"add it here WITH its rationale in tools.lock, or clear the bit", tool.Name)
			}
			continue
		}
		if tool.Critical != want {
			t.Errorf("tool %q: expected Critical=%v, got %v", tool.Name, want, tool.Critical)
		}
	}
	// The other direction: a name listed here that the manifest no longer
	// carries would silently shrink the tier back.
	for name := range wantCritical {
		tool, ok := backend.Default.Lookup(name)
		if !ok {
			t.Errorf("critical tool %q is not in tools.lock at all", name)
			continue
		}
		if !tool.Critical {
			t.Errorf("critical tool %q has Critical=false in tools.lock", name)
		}
	}
}

// Test 5b: whatever MissingCritical reports must carry Critical=true in the
// manifest. That is the invariant; it is read from the manifest rather than
// from a second hand-written copy of the tier.
//
// The previous version hard-coded {subfinder, httpx, dnsx} as the allowlist —
// a duplicate of the set TestRegistrySeed_CriticalTier already pins. When the
// tier grew to seven, that duplicate was missed, and the miss was INVISIBLE on
// every box where the four new tools were installed: MissingCritical never
// listed them there, so the subset check passed vacuously. Only a CI runner
// with no tools at all exercised it, and there it failed on all four. A test
// whose verdict depends on which tools the developer happens to have is the
// false-green shape this repo keeps paying for; the invariant below does not.
func TestRegistrySeed_MissingCriticalIsCriticalSubset(t *testing.T) {
	_ = backend.Default.Discover(context.Background())
	for _, name := range backend.Default.MissingCritical() {
		tool, ok := backend.Default.Lookup(name)
		if !ok {
			t.Errorf("MissingCritical reported %q, which is not in the registry at all", name)
			continue
		}
		if !tool.Critical {
			t.Errorf("MissingCritical reported %q, whose manifest entry has Critical=false", name)
		}
	}
}

// Test 7: tools.lock TOML is parseable. (Implicit — if init() failed, the
// other tests would fail. This test is a belt-and-suspenders explicit
// check that the seed populated >0 entries.)
func TestRegistrySeed_TOMLParseSucceeded(t *testing.T) {
	if len(backend.Default.All()) == 0 {
		t.Fatal("backend.Default empty — tools.lock failed to parse OR init() didn't fire")
	}
}

// --- Phase 11 (Installer) — tools.lock schema + inventory coverage ---

func toolByName(name string) *backend.Tool {
	for _, t := range backend.Default.All() {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// TestToolsLockSchemaFields asserts the Phase 11 schema extension is wired:
// a pinned tool carries its Version + install metadata copied from tools.lock.
func TestToolsLockSchemaFields(t *testing.T) {
	sf := toolByName("subfinder")
	if sf == nil {
		t.Fatal("subfinder not registered from tools.lock")
	}
	if sf.Version != "v2.14.0" {
		t.Errorf("subfinder Version = %q, want v2.14.0 (pinned in tools.lock)", sf.Version)
	}
	if sf.Kind != "go" {
		t.Errorf("subfinder Kind = %q, want go", sf.Kind)
	}
	if sf.GoModule == "" {
		t.Error("subfinder GoModule empty — install metadata not copied from tools.lock to Tool")
	}
}

// TestToolsLockVersionsPopulated (BLOCKER 2 fix) — every go/python/rust/
// go_clone/python_venv/make_clone kind tool MUST carry a non-empty, non-zero
// Version so `go install module@version` / `uv tool install pkg==version`
// resolve and the D-04 idempotency probe has something to compare against.
// system kind is exempt (the OS package manager owns versioning).
//
// make_clone is version-bearing for the SECOND reason only: it clones and runs
// `make`, so there is no registry pin to resolve, but installMakeClone's
// "already on PATH and Version == latest" fast path reads it. A make_clone entry
// with an empty Version would reinstall on every run.
func TestToolsLockVersionsPopulated(t *testing.T) {
	for _, tool := range backend.Default.All() {
		switch tool.Kind {
		case "go", "python", "rust", "go_clone", "python_venv", "make_clone":
			if tool.Version == "" || tool.Version == "v0.0.0" {
				t.Errorf("tool %q (kind=%s) has invalid Version %q — must be a real tag or \"latest\"",
					tool.Name, tool.Kind, tool.Version)
			}
		case "system":
			// exempt — pkg manager handles versioning
		default:
			t.Errorf("tool %q has unexpected kind %q (extend this switch if a new kind is added)",
				tool.Name, tool.Kind)
		}
	}
}

// TestToolsLockNameCoverage (BLOCKER 4 fix) — every orchestrated tool from
// install.sh that is a real installable binary MUST have a tools.lock entry.
// Enforces the install.sh-vs-tools.lock audit at test time; a count floor
// alone is insufficient (INST-02). Add names here as install.sh grows.
func TestToolsLockNameCoverage(t *testing.T) {
	expected := []string{
		// subdomain + DNS
		"subfinder", "httpx", "dnsx", "puredns", "naabu", "asnmap", "dnsvalidator",
		"gotator", "subwiz", "dsieve", "subzy", "mapcidr",
		// web + crawling + JS + fuzzing
		"katana", "ffuf", "nuclei", "dalfox", "anew", "qsreplace", "unfurl", "gf",
		"xnLinkFinder", "roboxtractor", "nmapurls", "smap", "inscope", "mantra",
		// osint + notify + collab + misc
		"notify", "github-endpoints", "cent", "grpcurl", "interlace",
		"interactsh-client", "tlsx", "brutespray", "LeakSearch",
		// Phase 13 (Domain Parity) additions — verified against install.sh.
		"nmap", "nerva", "brutus", "titus", "Scopify",
	}
	have := map[string]bool{}
	for _, tool := range backend.Default.All() {
		have[tool.Name] = true
	}
	var missing []string
	for _, name := range expected {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("tools.lock missing %d orchestrated tool(s) from install.sh: %v", len(missing), missing)
	}
}

// TestSeedCarriesCloneCoordinates asserts the tools.lock clone keys survive the
// round trip onto the *Tool (18-02).
//
// THREE PLACES CHANGE TOGETHER for a clone coordinate — the anonymous per-tool
// struct in toolsLockSchema, the block that copies it onto *Tool, and the Clone*
// fields on backend.Tool — and a miss in the MIDDLE one is completely silent:
// the TOML parses, the tool registers, and Discover then reports it absent
// because its coordinates are empty. That is indistinguishable from "not
// installed", which is the exact confusion 18-02 exists to remove. Hence a test
// rather than a comment.
func TestSeedCarriesCloneCoordinates(t *testing.T) {
	// regulator is the tracer row: interpreter shape, clone_dir == name.
	tool, ok := backend.Default.Lookup("regulator")
	if !ok {
		t.Fatalf("regulator is not registered — tools.lock did not seed")
	}
	if tool.CloneDir != "regulator" {
		t.Errorf("regulator CloneDir = %q, want %q — the copy block in registry_seed.go "+
			"dropped clone_dir", tool.CloneDir, "regulator")
	}
	if tool.CloneInterpreter != "venv/bin/python3" {
		t.Errorf("regulator CloneInterpreter = %q, want %q", tool.CloneInterpreter, "venv/bin/python3")
	}
	if tool.CloneEntry != "main.py" {
		t.Errorf("regulator CloneEntry = %q, want %q", tool.CloneEntry, "main.py")
	}
}

// ---------------------------------------------------------------------------
// 18-02 Task 3: the declared clone inventory.
// ---------------------------------------------------------------------------

// cloneCensusDeclared is the PINNED number of tools.lock rows carrying a
// clone_dir — the coordinate without which a row cannot resolve at all.
//
// A pinned constant, following argvector_coverage_test.go's convention: the
// total is a constant and a change to it must be a visible diff with a written
// reason. A row silently LOSING its coordinates is coverage draining away —
// eight tools spent their entire life reported "not installed" while sitting on
// disk precisely because nothing counted them.
//
// 15 as of 2026-08-26: regulator, EmailHarvester, dorks_hunter, SwaggerSpy,
// Spoofy, cmseek, LeakSearch, gato, SSTImap, Scopify, JSA, ghleaks, nomore403,
// sqlmap, testssl.sh.
const cloneCensusDeclared = 15

// cloneCensusWithInterpreter is the PINNED number of those rows that declare an
// interpreter. It is pinned SEPARATELY because the two shapes are two different
// code paths in Discover, and a manifest that drifted to all-of-one-shape would
// leave the other branch unexercised by every real row. 11 interpreter rows
// (the python venvs + sqlmap) and 4 console-script/binary rows (gato, ghleaks,
// nomore403, testssl.sh).
const cloneCensusWithInterpreter = 11

// declaredClones returns every seeded tool carrying ANY clone coordinate.
//
// ANY, not all: a row with an entry and no directory is exactly the partial
// state TestEveryDeclaredCloneEntryIsRelative's completeness check exists to
// catch, so it must be in this set to be checked at all.
func declaredClones() []*backend.Tool {
	var out []*backend.Tool
	for _, t := range backend.Default.All() {
		if t.CloneDir != "" || t.CloneEntry != "" || t.CloneInterpreter != "" {
			out = append(out, t)
		}
	}
	return out
}

// resolvableClones returns the tools whose clone_dir is declared — the rows that
// can actually resolve. This, NOT declaredClones, is what the census pins.
//
// The distinction is load-bearing and I got it wrong first: with an any-of-three
// predicate, deleting a row's clone_dir left clone_entry behind, the row stayed
// "declared", and the census absorbed the deletion without failing. A pin that
// absorbs the mutation it exists to catch is decorative. MUTATION 7 is what
// surfaced it.
func resolvableClones() []*backend.Tool {
	var out []*backend.Tool
	for _, t := range backend.Default.All() {
		if t.CloneDir != "" {
			out = append(out, t)
		}
	}
	return out
}

// TestEveryDeclaredCloneEntryIsRelative refuses an absolute or upward-traversing
// clone coordinate AT THE MANIFEST (T-18-02-02).
//
// A manifest row is the ONE place an absolute path would bypass Discover's
// containment check by never being joined under the tools root at all. Discover
// refuses it too, but a manifest that can hold the value is a manifest an
// unreviewed edit can weaponise.
func TestEveryDeclaredCloneEntryIsRelative(t *testing.T) {
	for _, tool := range declaredClones() {
		for label, rel := range map[string]string{
			"clone_dir":         tool.CloneDir,
			"clone_entry":       tool.CloneEntry,
			"clone_interpreter": tool.CloneInterpreter,
		} {
			if rel == "" {
				continue
			}
			if filepath.IsAbs(rel) {
				t.Errorf("%s: %s = %q is ABSOLUTE. Clone coordinates are joined under the "+
					"tools root; an absolute value bypasses the containment check by never "+
					"being joined (T-18-02-02).", tool.Name, label, rel)
			}
			if rel != filepath.Clean(rel) {
				t.Errorf("%s: %s = %q is not in cleaned form (want %q) — an uncleaned value "+
					"hides traversal from a reader", tool.Name, label, rel, filepath.Clean(rel))
			}
			for _, seg := range strings.Split(filepath.ToSlash(rel), "/") {
				if seg == ".." {
					t.Errorf("%s: %s = %q TRAVERSES UPWARD out of the tools root", tool.Name, label, rel)
				}
			}
		}
		// A coordinate set must be COMPLETE. A row with an interpreter and no
		// entry, or an entry and no directory, resolves to nothing and reports
		// as absent — the silent shape this whole plan exists to remove.
		if tool.CloneDir == "" || tool.CloneEntry == "" {
			t.Errorf("%s: incomplete clone coordinates (clone_dir=%q clone_entry=%q). Both are "+
				"required whenever either is set; a partial row resolves to nothing and reports "+
				"'absent', which is exactly the false report 18-02 removes",
				tool.Name, tool.CloneDir, tool.CloneEntry)
		}
	}
}

// TestCloneCoordinatesCensus emits one greppable line and pins the declared
// count.
//
// THE _here COUNTS ARE LOGGED, NOT ASSERTED. They depend on what the operator
// running the suite happens to have installed, and a gate that depends on the
// operator's box is a gate that fails for the wrong reason. `declared` does not
// depend on the box at all, so that is the one that is pinned.
func TestCloneCoordinatesCensus(t *testing.T) {
	declared := resolvableClones()

	// Resolve against the REAL tools root, in a FRESH registry holding COPIES —
	// Discover mutates Path/ArgvPrefix/WorkDir, and clobbering backend.Default
	// here would leak into every other test in the package.
	probe := backend.NewToolRegistry()
	if home, err := os.UserHomeDir(); err == nil {
		probe.ToolsDir = filepath.Join(home, "Tools")
	}
	for _, tool := range declared {
		clone := *tool
		clone.Path, clone.ArgvPrefix, clone.WorkDir = "", nil, ""
		probe.Register(&clone)
	}
	if err := probe.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	unresolvableHere := len(probe.Unresolvable())
	absentHere := len(probe.Absent())
	resolvedHere := len(declared) - unresolvableHere - absentHere

	t.Logf("CLONE_COVERAGE declared=%d resolved_here=%d unresolvable_here=%d absent_here=%d",
		len(declared), resolvedHere, unresolvableHere, absentHere)
	for _, name := range probe.Unresolvable() {
		reason, _ := probe.UnresolvableReason(name)
		t.Logf("CLONE_UNRESOLVABLE_HERE %s: %s", name, reason)
	}
	if absent := probe.Absent(); len(absent) > 0 {
		t.Logf("CLONE_ABSENT_HERE %s", strings.Join(absent, " "))
	}

	if got := len(declared); got != cloneCensusDeclared {
		t.Errorf("CLONE_COVERAGE declared=%d, pinned constant says %d.\n"+
			"  If a row GAINED coordinates, raise the constant in the same change. If a row LOST\n"+
			"  them, say why: a falling number here is a tool going back to being reported\n"+
			"  'not installed' while sitting on disk, which is the defect this plan closed.",
			got, cloneCensusDeclared)
	}
	withInterp := 0
	for _, tool := range declared {
		if tool.CloneInterpreter != "" {
			withInterp++
		}
	}
	if withInterp != cloneCensusWithInterpreter {
		t.Errorf("CLONE_COVERAGE with_interpreter=%d, pinned constant says %d — the two shapes "+
			"(interpreter+script, and bare executable) are two distinct branches in Discover and "+
			"both must keep at least one real manifest row",
			withInterp, cloneCensusWithInterpreter)
	}
	if withInterp == 0 || withInterp == len(declared) {
		t.Errorf("every declared clone has the same shape — one of Discover's two branches is no " +
			"longer exercised by any real row")
	}
}

// Test 5c: the same invariant, made impossible to satisfy vacuously.
//
// 5b discovers on the developer's real PATH, so on a box with every critical
// tool installed MissingCritical is empty and the loop body never runs. This
// copies the seed into a fresh registry and discovers under a PATH that holds
// nothing, so EVERY critical tool is missing and the check has to do work —
// and it pins that the missing-critical set is then exactly the declared tier.
func TestRegistrySeed_MissingCriticalUnderEmptyPATHIsExactlyTheTier(t *testing.T) {
	reg := backend.NewToolRegistry()
	for _, tool := range backend.Default.All() {
		cp := *tool // never hand Default's pointers to a Discover that mutates them
		reg.Register(&cp)
	}
	t.Setenv("PATH", t.TempDir()) // resolves nothing
	_ = reg.Discover(context.Background())

	want := map[string]bool{}
	for _, tool := range backend.Default.All() {
		if tool.Critical {
			want[tool.Name] = true
		}
	}
	got := map[string]bool{}
	for _, name := range reg.MissingCritical() {
		got[name] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("critical tool %q is absent from an empty PATH but MissingCritical did not report it", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("MissingCritical reported %q, which is not Critical in the manifest", name)
		}
	}
	if len(got) == 0 {
		t.Fatal("MissingCritical is empty under an empty PATH — the test is vacuous again")
	}
}
