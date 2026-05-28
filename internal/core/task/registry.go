// Source: ADR 0002 §5.1 lines 1589-1604 + this plan's §"behavior" Task 1
// for the Build() extension.
//
// Registry holds all registered Tasks. `Default` is the process-singleton
// populated by `init() { task.Register(t) }` calls in module packages.
// Build() is called once at startup (Plan 06 cmd/reconftw/main.go) — it
// validates the DAG (topological sort + cycle detection) and returns the
// ordered slice the Scheduler will dispatch from.

package task

import "sync"

// Registry is the catalogue of Tasks discovered at process start time.
//
// Thread-safety: All exported methods acquire an internal RWMutex; the
// expected usage pattern is registration during init() (no concurrency)
// followed by long-running read-only access from Scheduler goroutines.
type Registry struct {
	mu    sync.RWMutex
	tasks map[string]Task
}

// NewRegistry constructs an empty Registry. Used by tests that want
// isolation from the Default singleton.
func NewRegistry() *Registry {
	return &Registry{tasks: map[string]Task{}}
}

// Default is the process-singleton Task registry. Module packages register
// via blank-imported package init():
//
//	import _ "github.com/six2dez/reconftw/internal/modules/subdomains"
//
// where subdomains/init.go contains:
//
//	func init() { task.Register(&PassiveTask{}) }
//
//nolint:gochecknoglobals // process-singleton — pattern owned by ADR §5.1
var Default = NewRegistry()

// Register adds t to the Default registry. Panics on duplicate Name (caught
// at startup — the operator sees the offending name in the panic message).
//
// SELF-REGISTRATION pattern: each module package init():
//
//	func init() { task.Register(&PassiveTask{}) }
//
// The panic semantics match backend.ToolRegistry.Register; both registries
// are populated once and read forever after.
func Register(t Task) {
	Default.Register(t)
}

// Register adds t to this Registry. Panics on duplicate Name.
func (r *Registry) Register(t Task) {
	if t == nil {
		panic("reconftw: task.Registry.Register: nil task")
	}
	name := t.Name()
	if name == "" {
		panic("reconftw: task.Registry.Register: empty Name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tasks[name]; exists {
		panic("reconftw: duplicate task registration: " + name)
	}
	r.tasks[name] = t
}

// All returns every registered Task. The returned slice is sorted by
// Name() for determinism. The slice itself is independent of the registry
// — appending to it is safe.
func (r *Registry) All() []Task {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tasks, _ := r.snapshot()
	return tasks
}

// Lookup returns the registered Task by Name. Second return value is false
// if no Task with that Name exists.
func (r *Registry) Lookup(name string) (Task, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tasks[name]
	return t, ok
}

// Build performs dependency resolution and topological sort cycle
// detection on the registered Tasks. Returns the topo-ordered slice or
// *errors.ConfigError on cycle / missing-dependency.
//
// MUST be called once at startup (cmd/reconftw/main.go in Plan 06) before
// the Scheduler accepts any submissions. On error, the binary exits with
// the ConfigError message — never deadlocks the Scheduler (per ADR §6
// PITFALL NOTE).
func (r *Registry) Build() ([]Task, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Sort works on a copy of the map so concurrent reads stay consistent.
	snapshot := make(map[string]Task, len(r.tasks))
	for n, t := range r.tasks {
		snapshot[n] = t
	}
	return Sort(snapshot)
}

// snapshot returns a sorted-by-name slice and the underlying map. Caller
// must already hold the read lock.
func (r *Registry) snapshot() ([]Task, map[string]Task) {
	tasks := make([]Task, 0, len(r.tasks))
	for _, t := range r.tasks {
		tasks = append(tasks, t)
	}
	sortByName(tasks)
	m := make(map[string]Task, len(r.tasks))
	for n, t := range r.tasks {
		m[n] = t
	}
	return tasks, m
}

// sortByName sorts tasks alphabetically by Name() — used by All() for
// deterministic iteration.
func sortByName(tasks []Task) {
	// Plain insertion sort is fine — Task counts are O(100) at full Phase
	// 4-7 deployment; allocation-free; clearer than importing sort.Slice.
	for i := 1; i < len(tasks); i++ {
		j := i
		for j > 0 && tasks[j-1].Name() > tasks[j].Name() {
			tasks[j-1], tasks[j] = tasks[j], tasks[j-1]
			j--
		}
	}
}
