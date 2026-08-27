// boot_workdir_test.go — Target.WorkDir is cwd-independent after Boot (18-02).
//
// # WHY THIS EXISTS
//
// The default workspace root is the RELATIVE "workspaces" (cmd/reconftw/root.go's
// -o default). Every module builds tool arguments with
// filepath.Join(app.Target.WorkDir, ...), so under that default the arguments a
// tool receives are relative to the reconFTW process's cwd.
//
// That was harmless only for as long as nothing changed a tool's cwd. 18-02
// changes it: repo-clone tools that cannot run anywhere but their own directory
// now run there. regulator is the concrete case — main.py:18 hardcodes
// LOGFILE_NAME = 'logs/regulator.log' and aborts with FileNotFoundError unless
// cwd holds a logs/ directory, so it MUST run from its clone. If its -f/-o paths
// were still cwd-relative they would resolve under ~/Tools/regulator and the tool
// would read nothing and write nowhere — a scan that finds zero and says so
// quietly.
//
// Boot absolutises once, at the single point the workspace enters the kernel.
package appctx_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// TestBootAbsolutisesRelativeWorkDir: a relative workspace becomes absolute, and
// resolves to the same directory it named before.
func TestBootAbsolutisesRelativeWorkDir(t *testing.T) {
	tmp := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	if err := os.MkdirAll("workspaces/example.com", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	tgt, err := appctx.NewTarget("example.com", nil, "workspaces/example.com")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	app, err := appctx.Boot(
		context.Background(), nopLogger(), newTestConfig(), tgt,
		&stubScheduler{max: 4},
		appctx.BootOptions{Checkpoint: &stubCP{}, DisableToolRecorder: true},
	)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}

	if !filepath.IsAbs(app.Target.WorkDir) {
		t.Fatalf("Target.WorkDir = %q is still RELATIVE after Boot. Every tool argument a "+
			"module builds from it is then relative to the reconFTW process cwd, and a "+
			"clone tool running from its own directory would resolve them under the tools "+
			"root instead of the workspace.", app.Target.WorkDir)
	}
	wantReal, err := filepath.EvalSymlinks(filepath.Join(tmp, "workspaces", "example.com"))
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	gotReal, err := filepath.EvalSymlinks(app.Target.WorkDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", app.Target.WorkDir, err)
	}
	if gotReal != wantReal {
		t.Errorf("Target.WorkDir resolves to %q, want %q — absolutising must not change WHICH "+
			"directory the workspace is", gotReal, wantReal)
	}
}

// TestBootLeavesAbsoluteWorkDirAlone: the absolutisation is a no-op for a path
// that is already absolute — an operator's configured data_dir must come through
// byte-for-byte.
func TestBootLeavesAbsoluteWorkDirAlone(t *testing.T) {
	dir := t.TempDir()
	tgt, err := appctx.NewTarget("example.com", nil, dir)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	app, err := appctx.Boot(
		context.Background(), nopLogger(), newTestConfig(), tgt,
		&stubScheduler{max: 4},
		appctx.BootOptions{Checkpoint: &stubCP{}, DisableToolRecorder: true},
	)
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if app.Target.WorkDir != dir {
		t.Errorf("Target.WorkDir = %q, want the unchanged absolute %q", app.Target.WorkDir, dir)
	}
}
