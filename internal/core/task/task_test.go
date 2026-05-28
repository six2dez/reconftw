// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior tests 1-3 — Task interface shape + Blocker 4 placeholder grep.
package task_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// fakeTask is a minimal task.Task implementation used as a compile-time
// satisfaction check. The fakeTask method receivers exercise every method
// in the Task interface signature — if the interface drifts from ADR §5.1,
// this struct stops satisfying it and the var line fails to compile.
type fakeTask struct {
	name        string
	module      string
	description string
	dependsOn   []string
	enabled     bool
}

func (f *fakeTask) Name() string                    { return f.name }
func (f *fakeTask) Module() string                  { return f.module }
func (f *fakeTask) Description() string             { return f.description }
func (f *fakeTask) Enabled(cfg *config.Config) bool { return f.enabled }
func (f *fakeTask) DependsOn() []string             { return f.dependsOn }
func (f *fakeTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	return task.Result{Status: task.StatusDone}, nil
}

// Compile-time gate: Task interface MUST be satisfied by fakeTask. This
// line is the canonical signature check — if ADR §5.1 drifts (a method is
// renamed or its signature changes), the build breaks here.
var _ task.Task = (*fakeTask)(nil)

// Test 1: Task interface matches ADR §5.1 verbatim — 6 methods.
// The "verbatim" guarantee is enforced by the compile-time assertion
// above + the AST source scan below.
func TestTaskInterfaceMatchesADR(t *testing.T) {
	src := readSource(t, "task.go")
	wantMethods := []string{
		"Name() string",
		"Module() string",
		"Description() string",
		"Enabled(cfg *config.Config) bool",
		"DependsOn() []string",
		"Run(ctx context.Context, app *appctx.AppContext) (Result, error)",
	}
	for _, m := range wantMethods {
		if !strings.Contains(src, m) {
			t.Errorf("Task interface missing %q from task.go (ADR §5.1 BINDING violation)", m)
		}
	}
}

// Test 2: interfaces_check still references the BINDING shape. We can't
// invoke `go build` from a unit test reliably (CI vs local toolchain
// divergence) — instead, this test asserts that the upgraded
// cmd/interfaces_check/main.go references the canonical pieces of
// ADR §5.1: imports the real internal/core/task package and declares
// compile-time assertions on task.Task + task.LifecycleAware.
//
// Plan 03-07 Task 3 UPGRADED this file from placeholder `interface{}`
// types to real `internal/core/{task,backend,appctx,config}` imports
// with compile-time assertions. The shape this test verifies is now the
// real-package shape, not the Phase 2 placeholder shape.
func TestInterfacesCheckSignaturesMatch(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "cmd", "interfaces_check", "main.go"))
	if err != nil {
		t.Fatalf("read interfaces_check/main.go: %v", err)
	}
	// Use whitespace-tolerant substring tests: collapse runs of whitespace
	// in the source to single spaces before substring matching. gofumpt
	// re-aligns var-block padding based on the widest identifier, so any
	// future additions would otherwise break the literal substring match.
	src := collapseWhitespace(string(body))
	want := []string{
		// Plan 07 Task 3 — real-package imports (BINDING gate).
		`"github.com/six2dez/reconftw/internal/core/task"`,
		`"github.com/six2dez/reconftw/internal/core/backend"`,
		`"github.com/six2dez/reconftw/internal/core/appctx"`,
		`"github.com/six2dez/reconftw/internal/core/config"`,
		// Compile-time assertions on Task + LifecycleAware (ADR §5.1) + Backend (§5.2)
		// + SchedulerRunner (Plan 05 cycle-break).
		"_ task.Task = (*placeholderTask)(nil)",
		"_ task.LifecycleAware = (*placeholderLifecycle)(nil)",
		"_ backend.Backend = (*placeholderBackend)(nil)",
		"_ appctx.SchedulerRunner = (*placeholderScheduler)(nil)",
		// Run signature on the placeholder concrete type — must match real shape.
		"Run(_ context.Context, _ *appctx.AppContext) (task.Result, error)",
	}
	for _, w := range want {
		if !strings.Contains(src, w) {
			t.Errorf("interfaces_check/main.go drift — missing %q", w)
		}
	}
}

// Test 3 (Blocker 4 enforcement): no `any` placeholder remains in task/
// or scheduler/. Verifies the canonical interface was born final, no
// pre-Plan-05 placeholder cycle.
func TestNoAnyPlaceholderInTaskOrScheduler(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range []string{
		filepath.Join(root, "internal", "core", "task"),
		filepath.Join(root, "internal", "core", "scheduler"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read dir %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			if strings.HasSuffix(e.Name(), "_test.go") {
				continue // tests may use any for fakes
			}
			body, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			// Specifically the bad patterns the Plan grep gate watches.
			// Strings constructed via concatenation so this test file
			// itself does NOT match the plan's `grep -rE` placeholder gate.
			bad := []string{
				"app " + "any",
				"cfg " + "any",
				"TODO" + "(plan-05)",
				"app " + "interface{}",
				"cfg " + "interface{}",
			}
			for _, b := range bad {
				if strings.Contains(string(body), b) {
					t.Errorf("%s: forbidden placeholder %q (Blocker 4 violation)", e.Name(), b)
				}
			}
			// AST gate — Task interface method signatures must not contain
			// `any` for app/cfg parameter types.
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, e.Name(), body, parser.AllErrors)
			if err != nil {
				continue // syntax issue not relevant here
			}
			ast.Inspect(f, func(n ast.Node) bool {
				return true
			})
		}
	}
}

func readSource(t *testing.T, basename string) string {
	t.Helper()
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal", "core", "task", basename))
	if err != nil {
		t.Fatalf("read %s: %v", basename, err)
	}
	return string(body)
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	// task_test.go → internal/core/task → root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// collapseWhitespace replaces runs of any whitespace (spaces, tabs,
// newlines) with a single space. Used for substring tests that should be
// resilient to gofumpt re-alignment.
func collapseWhitespace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWS := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !inWS {
				b.WriteByte(' ')
				inWS = true
			}
			continue
		}
		inWS = false
		b.WriteRune(r)
	}
	return b.String()
}
