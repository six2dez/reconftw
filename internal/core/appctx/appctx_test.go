// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 2
// behavior tests 1-5 — AppContext shape + Target validator + Boot wiring.
package appctx_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// stubScheduler satisfies appctx.SchedulerRunner — minimal interface
// the Boot caller normally passes a *scheduler.Scheduler for.
type stubScheduler struct{ max int }

func (s *stubScheduler) MaxConcurrency() int { return s.max }

// stubCheckpoint satisfies checkpoint.Interface.
type stubCP struct{}

func (s *stubCP) Begin(_ context.Context, _, _, _ string) error            { return nil }
func (s *stubCP) Complete(_ context.Context, _, _, _ string, _ []string, _ error) error {
	return nil
}
func (s *stubCP) Done(_ context.Context, _, _, _ string) (bool, error) { return false, nil }

var _ checkpoint.Interface = (*stubCP)(nil)

// Test 1: AppContext has 9 fields per ADR §5.3.
func TestAppContextNineFields(t *testing.T) {
	fset := token.NewFileSet()
	src := readAppctxSource(t, "appctx.go")
	f, err := parser.ParseFile(fset, "appctx.go", src, parser.AllErrors)
	if err != nil {
		t.Fatalf("parse appctx.go: %v", err)
	}
	wantFields := []string{"Log", "Cfg", "Scheduler", "Tools", "Tree", "Checkpoint", "Notify", "Target", "UI"}
	got := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "AppContext" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			for _, name := range fld.Names {
				got[name.Name] = true
			}
		}
		return false
	})
	if len(got) != 9 {
		t.Errorf("AppContext has %d fields, want 9: %v", len(got), got)
	}
	for _, w := range wantFields {
		if !got[w] {
			t.Errorf("AppContext missing field %q", w)
		}
	}
}

// Test 2: Target has 5 fields per ADR §5.3.
func TestTargetFiveFields(t *testing.T) {
	src := readAppctxSource(t, "appctx.go")
	wantFields := []string{"Domain", "IsCIDR", "IsIP", "Scope", "WorkDir"}
	for _, w := range wantFields {
		if !strings.Contains(src, w+" ") {
			t.Errorf("Target missing field %q", w)
		}
	}
}

// Test 3: Boot wires every subsystem (smoke — non-nil fields).
func TestBootWiresEverySubsystem(t *testing.T) {
	cfg := newTestConfig()
	tgt, err := appctx.NewTarget("example.com", nil, t.TempDir())
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	sched := &stubScheduler{max: 4}
	cp := &stubCP{}
	app, err := appctx.Boot(
		context.Background(),
		nopLogger(),
		cfg,
		tgt,
		sched,
		appctx.BootOptions{Checkpoint: cp},
	)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if app.Log == nil || app.Cfg == nil || app.Scheduler == nil ||
		app.Tools == nil || app.Tree == nil || app.Checkpoint == nil ||
		app.Notify == nil || app.Target == nil || app.UI == nil {
		t.Errorf("Boot left a nil field: %+v", app)
	}
	if app.Scheduler.MaxConcurrency() != 4 {
		t.Errorf("Boot wired wrong Scheduler: %d", app.Scheduler.MaxConcurrency())
	}
}

// Test 4: NewTarget rejects shell-metacharacter domains.
func TestNewTargetRejectsInjection(t *testing.T) {
	cases := []string{"ex;rm -rf;", "ex|cat /etc/passwd", "ex`whoami`", ""}
	for _, in := range cases {
		_, err := appctx.NewTarget(in, nil, "/tmp")
		if err == nil {
			t.Errorf("NewTarget(%q) returned nil error; want *ScopeError", in)
			continue
		}
		var se *coreerrors.ScopeError
		if !errors.As(err, &se) {
			t.Errorf("NewTarget(%q) returned %T; want *ScopeError", in, err)
		}
	}

	// Valid hostname succeeds.
	tgt, err := appctx.NewTarget("example.com", []string{"*.example.com"}, "/tmp/wd")
	if err != nil {
		t.Fatalf("NewTarget(example.com): %v", err)
	}
	if tgt.Domain != "example.com" {
		t.Errorf("Domain = %q", tgt.Domain)
	}
	if tgt.WorkDir != "/tmp/wd" {
		t.Errorf("WorkDir = %q", tgt.WorkDir)
	}
	// IP succeeds — IsIP=true.
	if tgt, err := appctx.NewTarget("10.0.0.1", nil, "/tmp"); err != nil || !tgt.IsIP {
		t.Errorf("NewTarget(IP) failed or wrong flag: err=%v IsIP=%v", err, tgt.IsIP)
	}
	// CIDR succeeds — IsCIDR=true.
	if tgt, err := appctx.NewTarget("10.0.0.0/24", nil, "/tmp"); err != nil || !tgt.IsCIDR {
		t.Errorf("NewTarget(CIDR) failed or wrong flag: err=%v IsCIDR=%v", err, tgt.IsCIDR)
	}
}

// Test 5: Boot picks AxiomBackend when cfg.Axiom.Enabled = true.
// We verify indirectly by inspecting the Backend type via app.Tools.Backend.
func TestBootBackendSelection(t *testing.T) {
	cfg := newTestConfig()
	cfg.Axiom.Enabled = true
	tgt, _ := appctx.NewTarget("example.com", nil, t.TempDir())
	sched := &stubScheduler{max: 4}
	app, err := appctx.Boot(context.Background(), nopLogger(), cfg, tgt, sched, appctx.BootOptions{Checkpoint: &stubCP{}})
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	// The Backend type-name should be *backend.AxiomBackend.
	bt := fmt.Sprintf("%T", app.Tools.Backend)
	if !strings.Contains(bt, "AxiomBackend") {
		t.Errorf("Axiom-enabled Boot picked %s; want *backend.AxiomBackend", bt)
	}

	cfg.Axiom.Enabled = false
	app2, err := appctx.Boot(context.Background(), nopLogger(), cfg, tgt, sched, appctx.BootOptions{Checkpoint: &stubCP{}})
	if err != nil {
		t.Fatalf("Boot Local: %v", err)
	}
	bt2 := fmt.Sprintf("%T", app2.Tools.Backend)
	if !strings.Contains(bt2, "LocalBackend") {
		t.Errorf("Axiom-disabled Boot picked %s; want *backend.LocalBackend", bt2)
	}
}

// Test (smoke): Boot rejects nil cfg / nil target / nil scheduler.
func TestBootInputValidation(t *testing.T) {
	tgt, _ := appctx.NewTarget("example.com", nil, t.TempDir())
	sched := &stubScheduler{max: 4}
	cfg := newTestConfig()

	if _, err := appctx.Boot(context.Background(), nil, nil, tgt, sched, appctx.BootOptions{}); err == nil {
		t.Errorf("nil cfg did not error")
	}
	if _, err := appctx.Boot(context.Background(), nil, cfg, nil, sched, appctx.BootOptions{}); err == nil {
		t.Errorf("nil target did not error")
	}
	if _, err := appctx.Boot(context.Background(), nil, cfg, tgt, nil, appctx.BootOptions{}); err == nil {
		t.Errorf("nil scheduler did not error")
	}
}

func newTestConfig() *config.Config {
	return &config.Config{
		Concurrency: config.ConcurrencyConfig{
			MaxJobs:           4,
			HeartbeatSeconds:  10,
			KillGraceSeconds:  5,
			LogMode:           "summary",
			TailLines:         20,
			JobTimeoutSeconds: 600,
		},
		Output: config.OutputConfig{Verbosity: 1},
	}
}

func nopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

func readAppctxSource(t *testing.T, basename string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
	body, err := os.ReadFile(filepath.Join(root, "internal", "core", "appctx", basename))
	if err != nil {
		t.Fatalf("read %s: %v", basename, err)
	}
	return string(body)
}
