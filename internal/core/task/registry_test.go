// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior tests 4-6 — Registry.Register / All / Build.
package task_test

import (
	"context"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// tinyTask is a lightweight Task fake used by the Registry tests.
type tinyTask struct {
	name string
	deps []string
}

func (t *tinyTask) Name() string                { return t.name }
func (t *tinyTask) Module() string              { return "test" }
func (t *tinyTask) Description() string         { return "test task " + t.name }
func (t *tinyTask) Enabled(*config.Config) bool { return true }
func (t *tinyTask) DependsOn() []string         { return t.deps }
func (t *tinyTask) Run(context.Context, *appctx.AppContext) (task.Result, error) {
	return task.Result{Status: task.StatusDone}, nil
}

// Test 4: task.Register adds to Default; duplicate panics.
func TestRegisterAddsAndDuplicatePanics(t *testing.T) {
	r := task.NewRegistry()
	r.Register(&tinyTask{name: "alpha"})
	if _, ok := r.Lookup("alpha"); !ok {
		t.Fatalf("Lookup(alpha) after Register should succeed")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate Register; got nil")
		} else if !strings.Contains(toString(r), "duplicate") {
			t.Fatalf("panic message should contain 'duplicate'; got %v", r)
		}
	}()
	r.Register(&tinyTask{name: "alpha"})
}

// Test 5: All() returns tasks sorted by Name.
func TestAllReturnsTasksSortedByName(t *testing.T) {
	r := task.NewRegistry()
	r.Register(&tinyTask{name: "charlie"})
	r.Register(&tinyTask{name: "alpha"})
	r.Register(&tinyTask{name: "bravo"})

	all := r.All()
	if len(all) != 3 {
		t.Fatalf("All() len = %d, want 3", len(all))
	}
	got := []string{all[0].Name(), all[1].Name(), all[2].Name()}
	want := []string{"alpha", "bravo", "charlie"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("All()[%d].Name() = %q, want %q", i, got[i], want[i])
		}
	}
}

// Test 6: Build() performs topo sort; duplicate DependsOn entries
// are deduplicated transparently.
func TestBuildToposortAndDedup(t *testing.T) {
	r := task.NewRegistry()
	r.Register(&tinyTask{name: "a"})
	// b depends on a twice — Build should dedup and produce [a, b]
	r.Register(&tinyTask{name: "b", deps: []string{"a", "a"}})

	out, err := r.Build()
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("Build() len = %d, want 2", len(out))
	}
	if out[0].Name() != "a" || out[1].Name() != "b" {
		t.Errorf("Build() order = [%s, %s], want [a, b]", out[0].Name(), out[1].Name())
	}
}

// Test 4b: nil Task panics.
func TestRegisterNilPanics(t *testing.T) {
	r := task.NewRegistry()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Register")
		}
	}()
	r.Register(nil)
}

// Test 4c: empty Name panics.
func TestRegisterEmptyNamePanics(t *testing.T) {
	r := task.NewRegistry()
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty Name")
		}
	}()
	r.Register(&tinyTask{name: ""})
}

// Test (smoke): package-level task.Register routes to Default. We register
// a uniquely-named tinyTask to avoid colliding with anything else under
// task.Default during the test run.
func TestPackageRegisterRoutesToDefault(t *testing.T) {
	name := "task_test.smoke.unique." + t.Name()
	task.Register(&tinyTask{name: name})
	if _, ok := task.Default.Lookup(name); !ok {
		t.Errorf("Default.Lookup(%q) after task.Register should succeed", name)
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
