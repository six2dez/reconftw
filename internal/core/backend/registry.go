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
// `Default` is the process-singleton populated by Phase 4+ Task `init()` registrations
// + Plan 07 tools.lock seed. Plan 04 unit tests use fresh registries (Blocker 7) so
// they don't accidentally observe state from Plan 07.
package backend

import (
	"context"
	"os/exec"
	"sort"
	"sync"
)

// ToolRegistry is the catalog of external tools known to reconFTW v2.
type ToolRegistry struct {
	mu      sync.RWMutex
	tools   map[string]*Tool
	missing []string // populated by Discover — alphabetical list of names absent from PATH
}

// NewToolRegistry constructs an empty registry. Used by tests (Blocker 7) and by
// callers that want a per-request registry.
func NewToolRegistry() *ToolRegistry {
	return &ToolRegistry{tools: map[string]*Tool{}}
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
	r.tools[t.Name] = t
}

// Lookup returns the registered Tool by name. The second return value is false
// if the name is not registered.
func (r *ToolRegistry) Lookup(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// All returns every registered tool, sorted alphabetically by name. The slice
// is a snapshot — mutating the elements affects the registry, but the slice
// itself is independent.
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
		out = append(out, r.tools[n])
	}
	return out
}

// Discover walks PATH via exec.LookPath for every registered tool. Tools found
// have their Path field populated; tools NOT on PATH are recorded in the
// missing list (consumed by MissingRequired and MissingCritical).
//
// Always returns nil at present; reserved for future use (e.g. surfacing
// IOError from `tool --version` invocations once version detection is wired).
func (r *ToolRegistry) Discover(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.missing = r.missing[:0]
	for name, t := range r.tools {
		path, err := exec.LookPath(name)
		if err != nil {
			r.missing = append(r.missing, name)
			continue
		}
		t.Path = path
	}
	sort.Strings(r.missing)
	return nil
}

// MissingRequired returns every registered tool NOT found on PATH at the last
// Discover() call, regardless of Critical bit. FOUND-08: emit structured WARN
// for these entries.
//
// The returned slice is a copy — modifying it does not affect the registry.
func (r *ToolRegistry) MissingRequired() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, len(r.missing))
	copy(out, r.missing)
	return out
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
