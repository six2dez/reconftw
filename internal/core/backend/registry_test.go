// SPDX-License-Identifier: MIT
//
// Tests 1-8 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 2
// (ToolRegistry with Critical tier per Blocker 5).
//
// Per Blocker 7: NO test in this file may reference backend.Default. Every test
// constructs a fresh *ToolRegistry{tools: map[string]*Tool{}} instance.
// Verified at acceptance time via:
//
//	grep -r 'backend\.Default' internal/core/backend/*_test.go  (must be empty)
package backend_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// newFreshRegistry constructs the per-test fresh registry per Blocker 7.
func newFreshRegistry() *backend.ToolRegistry { return backend.NewToolRegistry() }

// Test 1: Register adds tool, Lookup retrieves it.
func TestToolRegistry_RegisterAndLookup(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "subfinder", Path: "/usr/local/bin/subfinder"})

	got, ok := r.Lookup("subfinder")
	if !ok {
		t.Fatalf("Lookup(subfinder) ok=false, want true")
	}
	if got.Name != "subfinder" {
		t.Errorf("Lookup returned Name=%q, want %q", got.Name, "subfinder")
	}
	if got.Path != "/usr/local/bin/subfinder" {
		t.Errorf("Lookup returned Path=%q", got.Path)
	}
}

// Test 2: Registering a duplicate name panics.
func TestToolRegistry_DuplicateRegistration_Panics(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "subfinder"})

	defer func() {
		if recover() == nil {
			t.Errorf("Register(duplicate) did not panic")
		}
	}()
	r.Register(&backend.Tool{Name: "subfinder"})
}

// Test 3: Discover walks PATH via exec.LookPath; populates Path.
// /bin/echo is on PATH on every supported platform (Linux + macOS).
func TestToolRegistry_Discover_PopulatesPath(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "echo"})

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover returned err=%v", err)
	}
	got, ok := r.Lookup("echo")
	if !ok {
		t.Fatalf("post-Discover Lookup(echo) ok=false")
	}
	if got.Path == "" {
		t.Errorf("Discover did not populate echo.Path")
	}
}

// Test 4: After Discover, missing tools (regardless of Critical) appear in MissingRequired.
func TestToolRegistry_MissingRequired_IncludesAllMissingRegardlessOfCritical(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "this-tool-does-not-exist-foo-noncritical", Critical: false})
	r.Register(&backend.Tool{Name: "this-tool-does-not-exist-foo-critical", Critical: true})
	r.Register(&backend.Tool{Name: "echo"}) // exists — should NOT appear

	_ = r.Discover(context.Background())

	missing := r.MissingRequired()
	want := []string{"this-tool-does-not-exist-foo-critical", "this-tool-does-not-exist-foo-noncritical"}
	if !reflect.DeepEqual(missing, want) {
		t.Errorf("MissingRequired() = %v, want %v (must include BOTH critical and non-critical missing)", missing, want)
	}
}

// Test 5: MissingCritical returns only missing tools with Critical=true.
func TestToolRegistry_MissingCritical_FiltersByCriticalBool(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "this-tool-does-not-exist-foo-noncritical", Critical: false})
	r.Register(&backend.Tool{Name: "this-tool-does-not-exist-foo-critical", Critical: true})

	_ = r.Discover(context.Background())

	got := r.MissingCritical()
	want := []string{"this-tool-does-not-exist-foo-critical"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MissingCritical() = %v, want %v", got, want)
	}
}

// Test 6: Tool present on PATH appears in NEITHER MissingRequired NOR MissingCritical.
func TestToolRegistry_PresentTool_NotInMissing(t *testing.T) {
	r := newFreshRegistry()
	r.Register(&backend.Tool{Name: "echo", Critical: true})

	_ = r.Discover(context.Background())

	if got := r.MissingRequired(); len(got) != 0 {
		t.Errorf("MissingRequired() = %v, want empty (echo is on PATH)", got)
	}
	if got := r.MissingCritical(); len(got) != 0 {
		t.Errorf("MissingCritical() = %v, want empty (echo is on PATH)", got)
	}
}

// Test 7: All() returns tools sorted by name.
func TestToolRegistry_All_SortedByName(t *testing.T) {
	r := newFreshRegistry()
	for _, name := range []string{"zeta", "alpha", "mu", "beta"} {
		r.Register(&backend.Tool{Name: name})
	}
	got := r.All()
	want := []string{"alpha", "beta", "mu", "zeta"}
	gotNames := make([]string, len(got))
	for i, t := range got {
		gotNames[i] = t.Name
	}
	if !reflect.DeepEqual(gotNames, want) {
		t.Errorf("All() names = %v, want %v (stable sort by name)", gotNames, want)
	}
}

func TestToolRegistry_SnapshotsAreIndependent(t *testing.T) {
	original := &backend.Tool{
		Name:        "snapshot-tool",
		Path:        "/initial/path",
		DefaultArgs: []string{"--initial"},
		ArgvPrefix:  []string{"initial-prefix"},
	}
	r := newFreshRegistry()
	r.Register(original)

	original.Path = "/mutated/original"
	original.DefaultArgs[0] = "--mutated-original"
	original.ArgvPrefix[0] = "mutated-original-prefix"

	lookup, ok := r.Lookup(original.Name)
	if !ok {
		t.Fatal("registered tool is missing")
	}
	lookup.Path = "/mutated/lookup"
	lookup.DefaultArgs[0] = "--mutated-lookup"
	lookup.ArgvPrefix[0] = "mutated-lookup-prefix"

	all := r.All()
	all[0].Path = "/mutated/all"
	all[0].DefaultArgs[0] = "--mutated-all"
	all[0].ArgvPrefix[0] = "mutated-all-prefix"

	got, ok := r.Lookup(original.Name)
	if !ok {
		t.Fatal("registered tool disappeared")
	}
	if got.Path != "/initial/path" || !reflect.DeepEqual(got.DefaultArgs, []string{"--initial"}) ||
		!reflect.DeepEqual(got.ArgvPrefix, []string{"initial-prefix"}) {
		t.Fatalf("external mutation changed registry state: %+v", got)
	}
}

func TestToolRegistry_ConcurrentDiscoverAndSnapshotsAreRaceFree(t *testing.T) {
	root := t.TempDir()
	const toolName = "reconftw-registry-race-fixture"
	writeExecutable(t, filepath.Join(root, "clone", "tool"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.SetToolsDir(root)
	r.Register(&backend.Tool{
		Name:       toolName,
		CloneDir:   "clone",
		CloneEntry: "tool",
	})

	const iterations = 500
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		for range iterations {
			_ = r.Discover(context.Background())
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for range iterations {
			if got, ok := r.Lookup(toolName); ok {
				_, _, _ = got.Path, got.WorkDir, strings.Join(got.ArgvPrefix, "\x00")
			}
			for _, got := range r.All() {
				_, _, _ = got.Path, got.WorkDir, strings.Join(got.ArgvPrefix, "\x00")
			}
		}
	}()
	close(start)
	wg.Wait()
}

// Test 8 (Blocker 7 enforcement): file-scope assertion.
//
// There is no in-test assertion needed here — Blocker 7 is verified at acceptance
// time by:
//
//   grep -r 'backend\.Default' internal/core/backend/*_test.go
//
// which MUST return no matches. This comment exists so future maintainers know
// not to add backend.Default references to this file (or any Plan 04 test file).
//
// Plan 07's registry_seed_test.go will be exempt from this rule because Plan 07
// is what populates Default — but until then, every Plan 04 test must use a
// fresh *ToolRegistry via newFreshRegistry().

// ---------------------------------------------------------------------------
// 18-02 (RS-B): clone-aware resolution.
//
// A large minority of reconFTW's inventory is installed as a repo clone under
// the tools root with its own virtualenv, which exec.LookPath cannot see. These
// tests pin the three properties that make resolving them safe:
// the DECLARED directory is used (never one derived from the tool's name), PATH
// still wins, and a clone that escapes the tools root is refused.
// ---------------------------------------------------------------------------

// evaluatedRoot returns dir with symlinks evaluated. Discover normalises the
// tools root this way, so on macOS — where t.TempDir() lives under /var/folders,
// itself a symlink to /private/var/folders — the resolved paths carry the
// evaluated form and a test comparing against the raw t.TempDir() would fail for
// a reason that has nothing to do with the behaviour under test.
func evaluatedRoot(t *testing.T, dir string) string {
	t.Helper()
	got, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", dir, err)
	}
	return got
}

// writeExecutable creates an executable file at path, creating parents.
func writeExecutable(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

// writeFileAt creates a NON-executable file at path, creating parents. Scripts
// handed to an interpreter need to exist and be readable, not executable.
func writeFileAt(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

// TestDiscoverResolvesADeclaredClone is the tracer's hermetic leg.
//
// THE FIXTURE'S DIRECTORY NAME DIFFERS FROM THE TOOL NAME ON PURPOSE, and that
// mismatch IS the test. `cmseek` really does live in a directory called
// `CMSeeK`; a name-derived implementation resolves it on macOS, where the
// filesystem is case-insensitive, and fails on Linux, where scans actually run.
// Make the two equal and this test passes under an implementation that ignores
// the manifest entirely.
func TestDiscoverResolvesADeclaredClone(t *testing.T) {
	root := t.TempDir()
	const toolName = "reconftw-clone-fixture"  // deliberately not on any PATH
	const cloneDir = "TotallyDifferentDirName" // deliberately != toolName

	writeExecutable(t, filepath.Join(root, cloneDir, "venv", "bin", "python3"), "#!/bin/sh\nexit 0\n")
	writeFileAt(t, filepath.Join(root, cloneDir, "main.py"), "print('hi')\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{
		Name:             toolName,
		CloneDir:         cloneDir,
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "main.py",
		CloneWorkDir:     true,
	})

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got, _ := r.Lookup(toolName)
	evRoot := evaluatedRoot(t, root)
	wantPath := filepath.Join(evRoot, cloneDir, "venv", "bin", "python3")
	wantPrefix := filepath.Join(evRoot, cloneDir, "main.py")
	wantWorkDir := filepath.Join(evRoot, cloneDir)

	if got.Path != wantPath {
		t.Errorf("Path = %q, want %q — the interpreter must become the executable", got.Path, wantPath)
	}
	if len(got.ArgvPrefix) != 1 || got.ArgvPrefix[0] != wantPrefix {
		t.Errorf("ArgvPrefix = %v, want [%q] — the script must become the argv prefix", got.ArgvPrefix, wantPrefix)
	}
	if got.WorkDir != wantWorkDir {
		t.Errorf("WorkDir = %q, want %q — clone tools resolve their own data files relative to their clone root", got.WorkDir, wantWorkDir)
	}
	if len(r.MissingRequired()) != 0 {
		t.Errorf("MissingRequired() = %v, want empty — the tool resolved", r.MissingRequired())
	}
}

// TestDiscoverResolvesACloneWithNoInterpreter pins the SECOND shape, which is
// not a variant but a different code path: `gato` ships a console script at
// venv/bin/gato and takes no interpreter, so the entry itself is the executable
// and there must be NO argv prefix.
func TestDiscoverResolvesACloneWithNoInterpreter(t *testing.T) {
	root := t.TempDir()
	const toolName = "reconftw-console-script-fixture"
	const cloneDir = "ConsoleScriptClone"

	writeExecutable(t, filepath.Join(root, cloneDir, "venv", "bin", "theTool"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{Name: toolName, CloneDir: cloneDir, CloneEntry: "venv/bin/theTool"})

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got, _ := r.Lookup(toolName)
	want := filepath.Join(evaluatedRoot(t, root), cloneDir, "venv", "bin", "theTool")
	if got.Path != want {
		t.Errorf("Path = %q, want %q", got.Path, want)
	}
	if len(got.ArgvPrefix) != 0 {
		t.Errorf("ArgvPrefix = %v, want empty — a console script takes no interpreter prefix", got.ArgvPrefix)
	}
}

// TestDiscoverPrefersPATHOverClone: a tool present in BOTH places resolves to
// the PATH entry (T-18-02-04). Without this a planted clone directory could
// shadow a correctly installed tool, and every tool that resolves today would
// silently change which binary it runs.
func TestDiscoverPrefersPATHOverClone(t *testing.T) {
	onPath, err := exec.LookPath("echo")
	if err != nil {
		t.Skipf("echo not on PATH: %v", err)
	}
	root := t.TempDir()
	writeExecutable(t, filepath.Join(root, "echo-clone", "echo"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{Name: "echo", CloneDir: "echo-clone", CloneEntry: "echo"})

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got, _ := r.Lookup("echo")
	if got.Path != onPath {
		t.Errorf("Path = %q, want the PATH entry %q — PATH must win over a clone", got.Path, onPath)
	}
	if got.WorkDir != "" || len(got.ArgvPrefix) != 0 {
		t.Errorf("PATH resolution left clone state behind: WorkDir=%q ArgvPrefix=%v", got.WorkDir, got.ArgvPrefix)
	}
}

// TestDiscoverRefusesCloneEscapingToolsRoot: a clone_dir that traverses upward
// leaves the tool unresolved and does NOT populate Path (T-18-02-01).
//
// paths.tools_dir comes from a config file and clone_dir from a manifest; without
// containment a value of "../../.." turns either one into an arbitrary executable
// running as the operator.
func TestDiscoverRefusesCloneEscapingToolsRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "tools")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	// A perfectly runnable executable, planted OUTSIDE the tools root.
	writeExecutable(t, filepath.Join(parent, "escape", "payload"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{
		Name:       "reconftw-escape-fixture",
		CloneDir:   filepath.Join("..", "escape"),
		CloneEntry: "payload",
	})

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got, _ := r.Lookup("reconftw-escape-fixture")
	if got.Path != "" {
		t.Errorf("Path = %q, want \"\" — a clone resolving OUTSIDE the tools root must be refused, "+
			"not executed", got.Path)
	}
	if got.WorkDir != "" {
		t.Errorf("WorkDir = %q, want \"\"", got.WorkDir)
	}
	missing := r.MissingRequired()
	if len(missing) != 1 || missing[0] != "reconftw-escape-fixture" {
		t.Errorf("MissingRequired() = %v, want [reconftw-escape-fixture]", missing)
	}
}

// TestDiscoverRefusesAbsoluteCloneCoordinates: an absolute clone coordinate is
// the way a manifest row would bypass the containment check by never being
// joined (T-18-02-02). TestEveryDeclaredCloneEntryIsRelative refuses it at the
// manifest; this refuses it at resolution time as well.
func TestDiscoverRefusesAbsoluteCloneCoordinates(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "tools")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	writeExecutable(t, filepath.Join(parent, "elsewhere", "payload"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{
		Name:       "reconftw-absolute-fixture",
		CloneDir:   filepath.Join(parent, "elsewhere"),
		CloneEntry: "payload",
	})
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got, _ := r.Lookup("reconftw-absolute-fixture")
	if got.Path != "" {
		t.Errorf("Path = %q, want \"\" — an ABSOLUTE clone coordinate must be refused", got.Path)
	}
}

// TestDiscoverWithNoToolsDirIsTodaysBehaviour: a registry nobody configured
// resolves exactly as it did before 18-02. This is what keeps every pre-existing
// test hermetic — clone resolution is opt-in via ToolsDir.
func TestDiscoverWithNoToolsDirIsTodaysBehaviour(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, filepath.Join(root, "someclone", "bin"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry() // ToolsDir deliberately left empty
	r.Register(&backend.Tool{Name: "reconftw-unconfigured-fixture", CloneDir: "someclone", CloneEntry: "bin"})
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got, _ := r.Lookup("reconftw-unconfigured-fixture")
	if got.Path != "" {
		t.Errorf("Path = %q, want \"\" — an unconfigured ToolsDir must disable clone resolution", got.Path)
	}
	if len(r.Absent()) != 1 {
		t.Errorf("Absent() = %v, want the single unconfigured tool", r.Absent())
	}
}

// TestDiscoverRefusesASymlinkedCloneDir pins the SECOND containment arm
// independently.
//
// WHY IT EXISTS: while running MUTATION 2 I removed only the lexical
// stays-under-the-root check and TestDiscoverRefusesCloneEscapingToolsRoot STILL
// PASSED — the symlink-evaluating arm absorbed it. Two arms sharing one test
// means either can be deleted without a failure, which is the shape of a guard
// that quietly stops guarding. This fixture is the symlink half of T-18-02-01:
// a clone directory that is on paper inside the tools root and in fact points
// out of it.
func TestDiscoverRefusesASymlinkedCloneDir(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "tools")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("mkdir root: %v", err)
	}
	writeExecutable(t, filepath.Join(parent, "outside", "payload"), "#!/bin/sh\nexit 0\n")
	if err := os.Symlink(filepath.Join(parent, "outside"), filepath.Join(root, "innocent")); err != nil {
		t.Skipf("symlinks unsupported on this filesystem: %v", err)
	}

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{Name: "reconftw-symlink-fixture", CloneDir: "innocent", CloneEntry: "payload"})
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got, _ := r.Lookup("reconftw-symlink-fixture")
	if got.Path != "" {
		t.Errorf("Path = %q, want \"\" — a clone_dir SYMLINKED out of the tools root must be "+
			"refused; it is lexically innocent and materially an escape", got.Path)
	}
	reason, ok := r.UnresolvableReason("reconftw-symlink-fixture")
	if !ok || !strings.Contains(reason, "symlink") {
		t.Errorf("UnresolvableReason = %q (ok=%v), want a reason naming the symlink", reason, ok)
	}
}

// ---------------------------------------------------------------------------
// 18-02 Task 2: absent and unresolvable stop reporting identically.
//
// The two states have DIFFERENT REMEDIES — "install it" versus "repair that one
// clone" — and were previously a single undifferentiated `missing` list. Gate
// 13's REFERENCE lists inherited that confusion; so did every operator reading
// health-check.
// ---------------------------------------------------------------------------

// partitionFixture builds a registry holding exactly one tool of each kind:
//
//	broken   a clone directory that EXISTS but whose entry script does not
//	nothing  a tool with no clone coordinates at all and nothing on PATH
func partitionFixture(t *testing.T) *backend.ToolRegistry {
	t.Helper()
	root := t.TempDir()
	// The clone is there; the entry point is not. This is the state that used to
	// be indistinguishable from "never installed".
	if err := os.MkdirAll(filepath.Join(root, "BrokenClone"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{
		Name:             "reconftw-broken-clone",
		CloneDir:         "BrokenClone",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "main.py",
	})
	r.Register(&backend.Tool{Name: "reconftw-not-installed-at-all"})
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	return r
}

func containsName(haystack []string, want string) bool {
	for _, got := range haystack {
		if got == want {
			return true
		}
	}
	return false
}

// TestUnresolvableIsNotAbsent asserts BOTH DIRECTIONS of the partition.
// Asserting one direction lets an implementation that puts everything in a
// single bucket pass, which is precisely today's behaviour.
func TestUnresolvableIsNotAbsent(t *testing.T) {
	r := partitionFixture(t)

	// Direction 1: a clone on disk with a missing entry point is UNRESOLVABLE,
	// and must NOT be reported as absent. Remedy: repair that clone.
	if !containsName(r.Unresolvable(), "reconftw-broken-clone") {
		t.Errorf("Unresolvable() = %v, want it to contain reconftw-broken-clone — its clone "+
			"directory exists on disk, so the remedy is to repair it, not to install it",
			r.Unresolvable())
	}
	if containsName(r.Absent(), "reconftw-broken-clone") {
		t.Errorf("Absent() = %v, must NOT contain reconftw-broken-clone — reporting an installed "+
			"clone as 'not installed' is the exact confusion this partition removes", r.Absent())
	}

	// Direction 2: a tool with nothing on disk is ABSENT and NOT unresolvable.
	if !containsName(r.Absent(), "reconftw-not-installed-at-all") {
		t.Errorf("Absent() = %v, want it to contain reconftw-not-installed-at-all", r.Absent())
	}
	if containsName(r.Unresolvable(), "reconftw-not-installed-at-all") {
		t.Errorf("Unresolvable() = %v, must NOT contain reconftw-not-installed-at-all — there is "+
			"nothing on disk to repair", r.Unresolvable())
	}
}

// TestMissingRequiredIsStillTheUnion makes the back-compat claim a test rather
// than a comment. MissingRequired is consumed by health-check and by the critical
// tier; narrowing it would be a silent behaviour change in the plan whose purpose
// is to end silent behaviour changes.
func TestMissingRequiredIsStillTheUnion(t *testing.T) {
	r := partitionFixture(t)

	want := []string{"reconftw-broken-clone", "reconftw-not-installed-at-all"}
	if got := r.MissingRequired(); !reflect.DeepEqual(got, want) {
		t.Errorf("MissingRequired() = %v, want the exact union %v", got, want)
	}
	if got, want := len(r.Absent())+len(r.Unresolvable()), len(r.MissingRequired()); got != want {
		t.Errorf("Absent()+Unresolvable() = %d entries but MissingRequired() = %d — the two "+
			"buckets must PARTITION the union, with nothing double-counted and nothing lost",
			got, want)
	}

	// Copy semantics, unchanged: mutating the result must not reach the registry.
	got := r.MissingRequired()
	got[0] = "CLOBBERED"
	if r.MissingRequired()[0] == "CLOBBERED" {
		t.Errorf("MissingRequired() leaked its backing array — the FOUND-08 copy contract broke")
	}
	if a := r.Absent(); len(a) > 0 {
		a[0] = "CLOBBERED"
		if r.Absent()[0] == "CLOBBERED" {
			t.Errorf("Absent() leaked its backing array")
		}
	}
	if u := r.Unresolvable(); len(u) > 0 {
		u[0] = "CLOBBERED"
		if r.Unresolvable()[0] == "CLOBBERED" {
			t.Errorf("Unresolvable() leaked its backing array")
		}
	}
}

// TestUnresolvableCarriesTheExpectedPath: the reason NAMES THE PATH that was
// looked for. An operator told only "unresolvable" has to go find that path
// themselves, and that friction is what produced the $HOME/Tools hardcoding in
// the module layer this phase is removing.
func TestUnresolvableCarriesTheExpectedPath(t *testing.T) {
	r := partitionFixture(t)

	reason, ok := r.UnresolvableReason("reconftw-broken-clone")
	if !ok {
		t.Fatalf("UnresolvableReason(reconftw-broken-clone) not recorded")
	}
	if !strings.Contains(reason, filepath.Join("BrokenClone", "main.py")) {
		t.Errorf("reason = %q, want it to name the expected entry-point path under BrokenClone", reason)
	}
	if !strings.Contains(reason, "BrokenClone") {
		t.Errorf("reason = %q, want it to name the clone directory that DOES exist", reason)
	}
	if _, ok := r.UnresolvableReason("reconftw-not-installed-at-all"); ok {
		t.Errorf("an ABSENT tool must carry no unresolvable reason — there is nothing to explain")
	}

	// The OTHER arm: entry present, interpreter gone. A venv wiped by a Python
	// upgrade is the common real-world shape of this, and naming main.py there
	// would send the operator to a file that is perfectly fine.
	root := t.TempDir()
	writeFileAt(t, filepath.Join(root, "HalfClone", "main.py"), "print(1)\n")
	r2 := newFreshRegistry()
	r2.ToolsDir = root
	r2.Register(&backend.Tool{
		Name:             "reconftw-dead-venv",
		CloneDir:         "HalfClone",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "main.py",
	})
	if err := r2.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	reason2, ok := r2.UnresolvableReason("reconftw-dead-venv")
	if !ok {
		t.Fatalf("reconftw-dead-venv is not unresolvable; Absent()=%v", r2.Absent())
	}
	if !strings.Contains(reason2, filepath.Join("HalfClone", "venv", "bin", "python3")) {
		t.Errorf("reason = %q, want it to name the MISSING INTERPRETER, not the entry that is "+
			"present", reason2)
	}
}

// TestDiscoverSetsWorkDirOnlyWhenDeclared pins BOTH directions of the
// clone_workdir opt-in.
//
// The OFF direction is the one that matters and it is a correctness pin, not a
// style pin: reconFTW's default workspace root is the RELATIVE "workspaces", so
// modules hand tools cwd-relative argv paths. Populating WorkDir for every clone
// would silently re-point regulator's `-f inputs/resolved.merged.txt` into
// ~/Tools/regulator, where it does not exist — a scan that finds nothing and
// says so quietly. Only a tool with a demonstrated need declares it.
func TestDiscoverSetsWorkDirOnlyWhenDeclared(t *testing.T) {
	root := t.TempDir()
	writeExecutable(t, filepath.Join(root, "OptOut", "run"), "#!/bin/sh\nexit 0\n")
	writeExecutable(t, filepath.Join(root, "OptIn", "run"), "#!/bin/sh\nexit 0\n")

	r := newFreshRegistry()
	r.ToolsDir = root
	r.Register(&backend.Tool{Name: "reconftw-workdir-off", CloneDir: "OptOut", CloneEntry: "run"})
	r.Register(&backend.Tool{
		Name: "reconftw-workdir-on", CloneDir: "OptIn", CloneEntry: "run", CloneWorkDir: true,
	})
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	off, _ := r.Lookup("reconftw-workdir-off")
	if off.Path == "" {
		t.Fatalf("reconftw-workdir-off did not resolve at all")
	}
	if off.WorkDir != "" {
		t.Errorf("WorkDir = %q, want \"\" — a clone that did NOT declare clone_workdir must "+
			"inherit the process cwd. Populating it re-points every cwd-relative argv path a "+
			"module built from app.Target.WorkDir into the tools root.", off.WorkDir)
	}

	on, _ := r.Lookup("reconftw-workdir-on")
	if want := filepath.Join(evaluatedRoot(t, root), "OptIn"); on.WorkDir != want {
		t.Errorf("WorkDir = %q, want %q — a tool that DID declare clone_workdir must get its "+
			"clone directory", on.WorkDir, want)
	}
}
