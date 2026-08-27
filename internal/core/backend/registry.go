// SPDX-License-Identifier: MIT
//
// ToolRegistry — FOUND-08 self-registering tool catalog with two-tier missing handling.
//
// FOUND-08 (REQUIREMENTS.md line 47) calls for:
//   - "warn on missing-but-required"   → in registry, absent from PATH, Critical=false
//   - "fail on missing-and-critical"   → in registry, absent from PATH, Critical=true
//
// MissingRequired() returns the union of both tiers; MissingCritical() returns only
// the latter (Blocker 5).
//
// # THE THIRD STATE (18-02)
//
// The two FOUND-08 tiers are orthogonal to a distinction the registry could not
// previously make at all: a tool that is NOT INSTALLED and a tool that IS installed
// but whose declared entry point cannot be found have different remedies — "install
// it" versus "repair that one clone" — and were reported identically. Discover now
// partitions the unavailable set into:
//
//	absent        nothing on disk to run: not on PATH, and either it declares no
//	              clone coordinates or its clone directory does not exist.
//	unresolvable  a clone directory EXISTS under the tools root but its declared
//	              entry (or interpreter) is missing, not executable, or was refused
//	              by the containment check.
//
// MissingRequired() is UNCHANGED: it still returns the union of the two, keeping
// its FOUND-08 contract and its copy semantics intact. Absent() and Unresolvable()
// expose the partition, and UnresolvableReason names the path that was expected —
// an operator told only "unresolvable" has to go find that path themselves, and
// that friction is what produced the $HOME/Tools hardcoding in the module layer in
// the first place.
//
// `Default` is the process-singleton populated by Phase 4+ Task `init()` registrations
// + Plan 07 tools.lock seed. Plan 04 unit tests use fresh registries (Blocker 7) so
// they don't accidentally observe state from Plan 07.
package backend

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ToolRegistry is the catalog of external tools known to reconFTW v2.
type ToolRegistry struct {
	// ToolsDir is the root that repo-clone tools are resolved under — v1's
	// ${tools}, set by appctx.Boot and by health-check from Config.ToolsRoot().
	//
	// A FIELD, not a Discover parameter, so Discover(ctx) keeps its shape and
	// every existing call site keeps compiling. Set it BEFORE calling Discover,
	// and set it THROUGH SetToolsDir — Discover reads this field under r.mu, so a
	// bare assignment races with it.
	//
	// The original comment here claimed the field needed no mutex because it was
	// "boot-time wiring, not per-request state". That was false for backend.Default:
	// the MCP server calls appctx.Boot once PER SCAN and runs scans concurrently,
	// so two boots raced on this assignment while Discover read it under the lock.
	// `go test -race -short ./...` reported 13 data races and 42 failing tests in
	// internal/mcp/handlers; the same command on the pre-phase-18 tree was clean.
	//
	// An EMPTY ToolsDir disables clone resolution entirely, which is what keeps
	// every pre-18-02 test hermetic: a registry nobody configured behaves exactly
	// as it did before this field existed.
	ToolsDir string

	mu    sync.RWMutex
	tools map[string]*Tool
	// missing is the UNION of absent and unresolvable, alphabetical — the exact
	// list MissingRequired() has always returned.
	missing []string
	// absent: not on PATH and nothing on disk to run.
	absent []string
	// unresolvable: a clone directory exists but its declared entry point does not.
	unresolvable []string
	// unresolvableReasons maps an unresolvable tool name to the human-readable
	// reason, which always NAMES THE PATH that was looked for.
	unresolvableReasons map[string]string
}

// NewToolRegistry constructs an empty registry. Used by tests (Blocker 7) and by
// callers that want a per-request registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: map[string]*Tool{}, unresolvableReasons: map[string]string{}}
}

// Default is the process-singleton ToolRegistry. Phase 4+ Tasks self-register
// against Default via blank-imported package init() hooks; Plan 07 tools.lock
// seed populates it at startup.
//
// BLOCKER 7 NOTE: Plan 04 unit tests use NewToolRegistry() instead, so they
// don't observe Plan 07 state. Audit gate at plan-04 acceptance:
//
//	grep -r 'backend\.Default' internal/core/backend/*_test.go  (must be empty)
//
//nolint:gochecknoglobals // process-singleton — pattern owned by ADR §5.1 task.Default
var Default = NewToolRegistry()

// SetToolsDir sets the repo-clone tools root under the registry mutex.
//
// Discover reads r.ToolsDir while holding r.mu, so callers MUST go through this
// setter rather than assigning the field directly — an unsynchronised write from
// a concurrent appctx.Boot is a data race against that read.
//
// NOTE ON SEMANTICS, deliberately not fixed here: this makes the write SAFE, not
// per-scan ISOLATED. backend.Default is a process singleton (ADR §5.1), so two
// concurrent scans configured with DIFFERENT tools roots still resolve against
// whichever wrote last. That is a design question about the singleton, not a
// memory-safety one, and it is recorded as a finding rather than changed here.
func (r *ToolRegistry) SetToolsDir(dir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ToolsDir = dir
}

// Register adds tool t to the registry. Panics if a tool with the same Name
// is already registered (matches task.Register panic semantics per ADR §5.1).
//
// SELF-REGISTRATION pattern: Phase 4+ Tasks call this from a package init():
//
//	func init() { backend.Default.Register(&backend.Tool{Name: "subfinder", ...}) }
func (r *ToolRegistry) Register(t *Tool) {
	if t == nil {
		panic("reconftw: backend.ToolRegistry.Register: nil tool")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[t.Name]; exists {
		panic("reconftw: duplicate tool registration: " + t.Name)
	}
	r.tools[t.Name] = cloneTool(t)
}

// Lookup returns an independent snapshot of the registered Tool by name. The
// second return value is false if the name is not registered.
func (r *ToolRegistry) Lookup(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return cloneTool(t), ok
}

// All returns every registered tool, sorted alphabetically by name. The slice
// and every Tool it contains are independent snapshots.
func (r *ToolRegistry) All() []*Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.tools))
	for n := range r.tools {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]*Tool, 0, len(names))
	for _, n := range names {
		out = append(out, cloneTool(r.tools[n]))
	}
	return out
}

func cloneTool(t *Tool) *Tool {
	if t == nil {
		return nil
	}
	clone := *t
	clone.DefaultArgs = append([]string(nil), t.DefaultArgs...)
	clone.ArgvPrefix = append([]string(nil), t.ArgvPrefix...)
	return &clone
}

// Discover resolves every registered tool to an executable path.
//
// RESOLUTION ORDER, and it matters:
//
//  1. exec.LookPath(name). PATH WINS. Everything that resolved before 18-02
//     resolves identically, and a planted clone directory cannot shadow a
//     correctly installed tool (T-18-02-04).
//  2. Only if that fails, and only if the tool declares clone_dir AND the
//     registry has a ToolsDir, the clone branch runs.
//
// A tool that resolves has Path (and, for the interpreter shape, ArgvPrefix and
// WorkDir) populated. A tool that does not lands in exactly one of the absent /
// unresolvable buckets; MissingRequired() remains their union.
//
// A refusal or a broken clone leaves THAT ONE TOOL unresolved and does not abort
// Discover for the other 102 (T-18-02-05), which is why this returns nil rather
// than surfacing the per-tool reason as an error. Reasons are retrievable via
// UnresolvableReason.
func (r *ToolRegistry) Discover(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// The tools root, cleaned and symlink-evaluated ONCE, is the containment
	// boundary every clone directory is checked against.
	toolsRoot := cleanToolsRoot(r.ToolsDir)

	r.missing = r.missing[:0]
	r.absent = r.absent[:0]
	r.unresolvable = r.unresolvable[:0]
	r.unresolvableReasons = map[string]string{}

	for name, t := range r.tools {
		if path, err := exec.LookPath(name); err == nil {
			t.Path = path
			// PATH resolution carries no interpreter and no clone root. Clearing
			// these keeps Discover idempotent: a second call after a clone was
			// installed on PATH must not leave the previous run's prefix behind.
			t.ArgvPrefix = nil
			t.WorkDir = ""
			continue
		}

		state, reason := r.resolveClone(t, toolsRoot)
		if state != cloneResolved {
			// WR-03: the PATH branch above clears these and says so — "Clearing
			// these keeps Discover idempotent" — but the clone-failure paths used to
			// leave the PREVIOUS run's coordinates in place. A tool that resolved on
			// one Discover and whose clone is removed before the next was then
			// reported in `missing` AND still carried a stale, dispatchable Path and
			// ArgvPrefix, so both states coexisted. That is reachable in one process:
			// cmd/reconftw/healthcheck.go re-Discovers the same backend.Default that
			// appctx.Boot already populated.
			t.Path, t.ArgvPrefix, t.WorkDir = "", nil, ""
		}
		switch state {
		case cloneResolved:
			continue
		case cloneUnresolvable:
			r.unresolvable = append(r.unresolvable, name)
			r.unresolvableReasons[name] = reason
		default: // cloneAbsent
			r.absent = append(r.absent, name)
		}
		r.missing = append(r.missing, name)
	}

	sort.Strings(r.missing)
	sort.Strings(r.absent)
	sort.Strings(r.unresolvable)
	return nil
}

// cloneState is the outcome of the clone branch for one tool.
type cloneState int

const (
	cloneAbsent cloneState = iota // nothing on disk to run
	cloneResolved
	cloneUnresolvable // a clone directory exists but its entry point does not
)

// cleanToolsRoot normalises the containment boundary. Returns "" when clone
// resolution is disabled (no ToolsDir configured) or the root does not exist.
func cleanToolsRoot(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	// EvalSymlinks so a symlinked tools root compares equal to the paths derived
	// under it (on macOS /tmp is itself a symlink to /private/tmp, which would
	// otherwise make every t.TempDir()-based fixture fail containment).
	if evaluated, err := filepath.EvalSymlinks(abs); err == nil {
		return evaluated
	}
	return filepath.Clean(abs)
}

// resolveClone populates t from its declared clone coordinates, or explains why
// it could not.
//
// CONTAINMENT (T-18-02-01), stated precisely because the precise version is the
// one that both holds and works:
//
//   - The CLONE DIRECTORY is the symlink-evaluated boundary. It is joined under
//     the tools root, cleaned, and its EvalSymlinks result must still be under the
//     symlink-evaluated root. That refuses both a clone_dir of "../../.." and a
//     clone directory symlinked out of the tree — the two attacks in the register.
//   - The entry and interpreter are then required to be LEXICALLY inside that
//     directory (relative, no upward traversal after cleaning). They are NOT
//     symlink-evaluated, and that is deliberate: every venv on disk symlinks its
//     interpreter at the system Python (~/Tools/regulator/venv/bin/python3 ->
//     python3.13 -> /opt/homebrew/...), so evaluating them would refuse all eight
//     of the clone tools this plan exists to revive. An attacker who can plant a
//     symlink INSIDE the clone directory can equally replace the binary itself, so
//     evaluating there buys nothing the directory boundary does not already cover.
func (r *ToolRegistry) resolveClone(t *Tool, toolsRoot string) (cloneState, string) {
	if t.CloneDir == "" || toolsRoot == "" {
		return cloneAbsent, ""
	}

	// A manifest row must not be able to bypass the join. Belt and braces with
	// TestEveryDeclaredCloneEntryIsRelative, which refuses it at the source.
	for _, rel := range []string{t.CloneDir, t.CloneEntry, t.CloneInterpreter} {
		if rel != "" && filepath.IsAbs(rel) {
			return cloneUnresolvable, "refused: clone coordinate " + rel + " is absolute; clone_dir/clone_entry/clone_interpreter must be relative to the tools root"
		}
	}

	dir := filepath.Clean(filepath.Join(toolsRoot, t.CloneDir))
	if !underRoot(toolsRoot, dir) {
		return cloneUnresolvable, "refused: clone_dir " + t.CloneDir + " resolves to " + dir + ", outside the tools root " + toolsRoot
	}
	// Symlink-evaluate the directory itself — a symlinked clone dir is the second
	// half of T-18-02-01.
	if evaluated, err := filepath.EvalSymlinks(dir); err == nil {
		if !underRoot(toolsRoot, evaluated) {
			return cloneUnresolvable, "refused: clone_dir " + t.CloneDir + " is a symlink to " + evaluated + ", outside the tools root " + toolsRoot
		}
		dir = evaluated
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		// Nothing on disk. This is ABSENT, not unresolvable: the remedy is to
		// install the tool, not to repair a clone that is not there.
		return cloneAbsent, ""
	}

	// From here the clone EXISTS, so every failure below is unresolvable — the
	// operator has something to repair.
	if t.CloneEntry == "" {
		return cloneUnresolvable, "clone directory " + dir + " exists but the manifest declares no clone_entry"
	}
	entry, ok := joinInside(dir, t.CloneEntry)
	if !ok {
		return cloneUnresolvable, "refused: clone_entry " + t.CloneEntry + " escapes the clone directory " + dir
	}
	if _, err := os.Stat(entry); err != nil {
		return cloneUnresolvable, "expected entry point " + entry + " is missing (clone directory " + dir + " exists)"
	}

	if t.CloneInterpreter == "" {
		// No interpreter: the entry IS the executable and must be executable.
		if !isExecutable(entry) {
			return cloneUnresolvable, "expected executable " + entry + " exists but is not executable"
		}
		t.Path = entry
		t.ArgvPrefix = nil
		t.WorkDir = cloneWorkDir(t, dir)
		return cloneResolved, ""
	}

	interp, ok := joinInside(dir, t.CloneInterpreter)
	if !ok {
		return cloneUnresolvable, "refused: clone_interpreter " + t.CloneInterpreter + " escapes the clone directory " + dir
	}
	if _, err := os.Stat(interp); err != nil {
		return cloneUnresolvable, "expected interpreter " + interp + " is missing (clone directory " + dir + " exists)"
	}
	if !isExecutable(interp) {
		return cloneUnresolvable, "expected interpreter " + interp + " exists but is not executable"
	}
	t.Path = interp
	// The script is part of the executable's IDENTITY, so it goes in ArgvPrefix
	// ahead of DefaultArgs (see Tool.ArgvPrefix). Absolute, not relative to
	// WorkDir, so the argv is unambiguous in logs/tools.jsonl.
	t.ArgvPrefix = []string{entry}
	t.WorkDir = cloneWorkDir(t, dir)
	return cloneResolved, ""
}

// cloneWorkDir returns the clone directory ONLY for a tool that declared
// clone_workdir, and "" otherwise.
//
// THE DEFAULT IS "", AND THAT IS THE WHOLE POINT. reconFTW's default workspace
// root is the RELATIVE "workspaces" (cmd/reconftw/root.go's -o default; see also
// workspaceRootOrFallback's own comment, "an empty configured root means the
// workspace lands in ./workspaces relative to cwd"). Modules build tool argv with
// filepath.Join(app.Target.WorkDir, ...), so under the default config those paths
// are CWD-RELATIVE. Setting cmd.Dir to the clone directory for every clone tool
// would silently re-point every input and output path into ~/Tools —
// regulator's `-f inputs/resolved.merged.txt` would resolve under
// ~/Tools/regulator and find nothing.
//
// So a clone tool inherits the process cwd, exactly as it does today, unless it
// has a DEMONSTRATED need for its own directory and says so in the manifest.
// See Tool.CloneWorkDir.
func cloneWorkDir(t *Tool, dir string) string {
	if t.CloneWorkDir {
		return dir
	}
	return ""
}

// underRoot reports whether p is root itself or lies beneath it. Compared on
// cleaned paths with a separator boundary, NOT with strings.HasPrefix, which
// would accept "/a/Tools-evil" as being under "/a/Tools".
func underRoot(root, p string) bool {
	root = filepath.Clean(root)
	p = filepath.Clean(p)
	if p == root {
		return true
	}
	return strings.HasPrefix(p, root+string(os.PathSeparator))
}

// joinInside joins rel under dir and reports whether the result stayed inside.
func joinInside(dir, rel string) (string, bool) {
	if filepath.IsAbs(rel) {
		return "", false
	}
	joined := filepath.Clean(filepath.Join(dir, rel))
	return joined, underRoot(dir, joined)
}

// isExecutable reports whether path is a regular file with any execute bit set.
func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// MissingRequired returns every registered tool that could NOT be resolved at
// the last Discover() call, regardless of Critical bit. FOUND-08: emit structured
// WARN for these entries.
//
// UNCHANGED BY 18-02, deliberately: this is the UNION of Absent() and
// Unresolvable(), which is exactly the set it has always returned. It is consumed
// by health-check and by the critical tier, and narrowing it would be a silent
// behaviour change in a plan whose whole purpose is to end silent behaviour
// changes. TestMissingRequiredIsStillTheUnion holds it to that.
//
// The returned slice is a copy — modifying it does not affect the registry.
func (r *ToolRegistry) MissingRequired() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.missing))
	copy(out, r.missing)
	return out
}

// Absent returns the tools with NOTHING ON DISK TO RUN: not on PATH, and either
// declaring no clone coordinates or having no clone directory under the tools
// root. REMEDY: install them.
//
// Sorted; the returned slice is a copy.
func (r *ToolRegistry) Absent() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.absent))
	copy(out, r.absent)
	return out
}

// Unresolvable returns the tools whose clone directory EXISTS under the tools
// root but whose declared entry point is missing, not executable, or refused by
// the containment check. REMEDY: repair or reinstall that one clone.
//
// Sorted; the returned slice is a copy. Use UnresolvableReason for the why.
func (r *ToolRegistry) Unresolvable() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.unresolvable))
	copy(out, r.unresolvable)
	return out
}

// UnresolvableReason returns the recorded reason for name, which always NAMES
// THE PATH that was expected. Second return value is false when name is not
// unresolvable.
func (r *ToolRegistry) UnresolvableReason(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	reason, ok := r.unresolvableReasons[name]
	return reason, ok
}

// MissingCritical returns ONLY missing tools whose Critical bool is true.
// FOUND-08 + Blocker 5: emit structured ERROR for these; health-check exits 1.
//
// The returned slice is sorted alphabetically.
func (r *ToolRegistry) MissingCritical() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []string{}
	for _, name := range r.missing {
		if t, ok := r.tools[name]; ok && t.Critical {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
