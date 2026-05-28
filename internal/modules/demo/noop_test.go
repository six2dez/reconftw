// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 3
// behavior tests 1-5 — NoopTask satisfies task.Task; init() registers;
// Run writes fixture line.
package demo_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/demo"
)

// Test 1: NoopTask satisfies task.Task — compile-time gate.
func TestNoopSatisfiesTaskInterface(t *testing.T) {
	var _ task.Task = (*demo.NoopTask)(nil)
	var _ task.Task = demo.NoopTask{}
}

// Test 2: methods return canonical values.
func TestNoopMethods(t *testing.T) {
	n := demo.NoopTask{}
	if n.Name() != "noop.demo" {
		t.Errorf("Name() = %q, want noop.demo", n.Name())
	}
	if n.Module() != "demo" {
		t.Errorf("Module() = %q, want demo", n.Module())
	}
	if n.Description() == "" {
		t.Errorf("Description() empty")
	}
	if !n.Enabled(nil) {
		t.Errorf("Enabled(nil) = false, want true")
	}
	if n.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil", n.DependsOn())
	}
}

// Test 3 + 4: Run writes fixture line to demo artefact; Result is Done.
func TestNoopRunWritesFixture(t *testing.T) {
	workdir := t.TempDir()
	tree, err := output.NewTree(workdir, nil) // no scope filter
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	app := &appctx.AppContext{Tree: tree}
	n := demo.NoopTask{}
	res, err := n.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("Status = %q, want done", res.Status)
	}
	if len(res.Outputs) != 1 || !strings.Contains(res.Outputs[0], "demo.jsonl") {
		t.Errorf("Outputs = %v; want [.../demo.jsonl]", res.Outputs)
	}

	// Verify the file content.
	body, err := os.ReadFile(filepath.Join(workdir, "artefacts", "demo.jsonl"))
	if err != nil {
		t.Fatalf("read demo.jsonl: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	if obj["demo"] != "phase-3-kernel" {
		t.Errorf("demo field = %v; want phase-3-kernel", obj["demo"])
	}
	if ts, ok := obj["timestamp"].(string); !ok || !looksLikeRFC3339(ts) {
		t.Errorf("timestamp field invalid: %v", obj["timestamp"])
	}
}

// Test 5: init() registered noop.demo with task.Default.
func TestNoopRegisteredViaInit(t *testing.T) {
	if _, ok := task.Default.Lookup("noop.demo"); !ok {
		t.Errorf("task.Default missing noop.demo — init() did not fire")
	}
	// All() includes it.
	all := task.Default.All()
	found := false
	for _, ta := range all {
		if ta.Name() == "noop.demo" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("task.Default.All() missing noop.demo")
	}
}

// Test (smoke): Run with nil AppContext yields Skipped (defensive).
func TestNoopRunNilAppSkips(t *testing.T) {
	res, err := demo.NoopTask{}.Run(context.Background(), nil)
	if err != nil {
		t.Errorf("Run(nil) err = %v; want nil", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("Run(nil) status = %q; want skipped", res.Status)
	}
}

// Test (smoke): Run with non-nil AppContext but nil Tree also Skips.
func TestNoopRunNilTreeSkips(t *testing.T) {
	res, _ := demo.NoopTask{}.Run(context.Background(), &appctx.AppContext{})
	if res.Status != task.StatusSkipped {
		t.Errorf("nil Tree → status = %q; want skipped", res.Status)
	}
}

// Test (W4 — Phase 4 hand-off): the deletion warning comment is present.
func TestPhase4DeletionComment(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(repoRoot(t), "internal", "modules", "demo", "noop.go"))
	if err != nil {
		t.Fatalf("read noop.go: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "DELETE THIS FILE in Phase 4 plan-01") {
		t.Errorf("noop.go missing Phase 4 deletion warning")
	}
}

func looksLikeRFC3339(s string) bool {
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}
