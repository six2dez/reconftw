// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior tests 7-10 — topo sort + cycle + missing-dep detection.
package task_test

import (
	"errors"
	"strings"
	"testing"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/task"
)

// Test 7: linear chain A→B→C produces [A, B, C].
func TestSortLinearChain(t *testing.T) {
	m := map[string]task.Task{
		"a": &tinyTask{name: "a"},
		"b": &tinyTask{name: "b", deps: []string{"a"}},
		"c": &tinyTask{name: "c", deps: []string{"b"}},
	}
	out, err := task.Sort(m)
	if err != nil {
		t.Fatalf("Sort error = %v", err)
	}
	got := []string{out[0].Name(), out[1].Name(), out[2].Name()}
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Sort()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// Test 8: diamond A→{B,C}→D produces a valid topo order
// (A first, D last; B and C in either order).
func TestSortDiamond(t *testing.T) {
	m := map[string]task.Task{
		"a": &tinyTask{name: "a"},
		"b": &tinyTask{name: "b", deps: []string{"a"}},
		"c": &tinyTask{name: "c", deps: []string{"a"}},
		"d": &tinyTask{name: "d", deps: []string{"b", "c"}},
	}
	out, err := task.Sort(m)
	if err != nil {
		t.Fatalf("Sort error = %v", err)
	}
	// A must be first, D must be last.
	if out[0].Name() != "a" {
		t.Errorf("diamond: out[0] = %q, want a", out[0].Name())
	}
	if out[3].Name() != "d" {
		t.Errorf("diamond: out[3] = %q, want d", out[3].Name())
	}
	// B and C may be in either order between A and D.
	middle := []string{out[1].Name(), out[2].Name()}
	hasB, hasC := false, false
	for _, n := range middle {
		if n == "b" {
			hasB = true
		}
		if n == "c" {
			hasC = true
		}
	}
	if !hasB || !hasC {
		t.Errorf("diamond: middle = %v, want both b and c", middle)
	}
}

// Test 9: cycle A→B→A returns *ConfigError with message containing
// "circular DependsOn detected". Per ADR §6 PITFALL NOTE — cycle is a
// ConfigError, NOT a runtime error.
func TestCycleDetection(t *testing.T) {
	m := map[string]task.Task{
		"a": &tinyTask{name: "a", deps: []string{"b"}},
		"b": &tinyTask{name: "b", deps: []string{"a"}},
	}
	out, err := task.Sort(m)
	if err == nil {
		t.Fatalf("Sort with cycle returned nil error; out=%v", out)
	}
	if out != nil {
		t.Errorf("Sort with cycle returned non-nil order: %v", out)
	}
	var ce *coreerrors.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *coreerrors.ConfigError; got %T: %v", err, err)
	}
	if !strings.Contains(ce.Message, "circular DependsOn detected") {
		t.Errorf("cycle Message = %q; expected 'circular DependsOn detected' substring", ce.Message)
	}
	if ce.Key != "task.depends_on" {
		t.Errorf("cycle Key = %q; want 'task.depends_on'", ce.Key)
	}
	// Sentinel bridge: errors.Is(err, ErrConfig) must traverse the wrapper.
	if !errors.Is(err, coreerrors.ErrConfig) {
		t.Errorf("errors.Is(err, ErrConfig) = false; want true")
	}
}

// Test 10: missing dependency (A→B but B not registered) returns
// *ConfigError with the missing task name.
func TestMissingDependency(t *testing.T) {
	m := map[string]task.Task{
		"a": &tinyTask{name: "a", deps: []string{"ghost"}},
	}
	_, err := task.Sort(m)
	if err == nil {
		t.Fatalf("Sort with missing dep returned nil error")
	}
	var ce *coreerrors.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *coreerrors.ConfigError; got %T: %v", err, err)
	}
	if !strings.Contains(ce.Message, "ghost") {
		t.Errorf("missing-dep Message = %q; expected 'ghost' substring", ce.Message)
	}
	if !strings.Contains(ce.Message, "not registered") {
		t.Errorf("missing-dep Message = %q; expected 'not registered'", ce.Message)
	}
}

// Test (smoke): empty map Sort returns empty slice, no error.
func TestSortEmpty(t *testing.T) {
	out, err := task.Sort(map[string]task.Task{})
	if err != nil {
		t.Fatalf("Sort(empty) error = %v", err)
	}
	if len(out) != 0 {
		t.Errorf("Sort(empty) len = %d, want 0", len(out))
	}
}
