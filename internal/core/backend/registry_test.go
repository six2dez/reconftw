// SPDX-License-Identifier: MIT
//
// Tests 1-8 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 2
// (ToolRegistry with Critical tier per Blocker 5).
//
// Per Blocker 7: NO test in this file may reference backend.Default. Every test
// constructs a fresh *ToolRegistry{tools: map[string]*Tool{}} instance.
// Verified at acceptance time via:
//   grep -r 'backend\.Default' internal/core/backend/*_test.go  (must be empty)
package backend_test

import (
	"context"
	"reflect"
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
