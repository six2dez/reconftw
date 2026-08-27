//go:build realtools

// registry_clone_realtools_test.go — the 18-02 tracer's BINDING end-to-end leg.
//
// # WHY THIS TEST IS THE POINT OF THE PLAN
//
// 17-06 fixed regulator's arg vector (CR-04) and PROVED the fix by running the
// tool out of ~/Tools/regulator by hand. Production could never reach that code:
// ToolRegistry.Discover resolved every tool with exec.LookPath, regulator is not
// on PATH, LocalBackend therefore reported NeverStarted, and the module's
// best-effort branch swallowed it. The fix has been INERT in production ever
// since — a green test over a code path no scan can execute.
//
// This test is the difference between those two states. It boots a registry with
// the REAL tools root, runs the REAL Discover, and dispatches the REAL regulator
// through backend.Runner. If it passes, the inert fix is live.
//
// BUILD TAG: //go:build realtools keeps `go test ./...` hermetic. Run with:
//
//	go test -tags realtools -count=1 -run TestRegulatorDispatchesThroughTheRunner ./internal/core/backend/
package backend_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// TestRegulatorDispatchesThroughTheRunner resolves regulator from its clone and
// runs it, asserting a NON-dispatch-failure outcome.
//
// The assertion is deliberately about DISPATCH, not about exit code: what was
// broken was that the process never started at all. `--help` is regulator's own
// usage form, confirmed by running `~/Tools/regulator/venv/bin/python3 main.py
// --help` once (exit 0, "usage: main.py ... DNS Regulator"); it is not guessed.
func TestRegulatorDispatchesThroughTheRunner(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("REALTOOLS SKIP regulator: no home directory: %v", err)
	}
	toolsRoot := filepath.Join(home, "Tools")
	if _, err := os.Stat(filepath.Join(toolsRoot, "regulator", "main.py")); err != nil {
		t.Skipf("REALTOOLS SKIP regulator: %s/regulator/main.py absent — the clone is not "+
			"installed on this box, so the real-tool leg is UNPROVEN HERE (the hermetic leg, "+
			"TestDiscoverResolvesADeclaredClone, still binds)", toolsRoot)
	}

	reg := backend.NewToolRegistry()
	reg.ToolsDir = toolsRoot
	reg.Register(&backend.Tool{
		Name:             "regulator",
		CloneDir:         "regulator",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "main.py",
		CloneWorkDir:     true,
		Timeout:          60 * time.Second,
	})
	if err := reg.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}

	tool, _ := reg.Lookup("regulator")
	if tool.Path == "" {
		reason, _ := reg.UnresolvableReason("regulator")
		t.Fatalf("regulator did NOT resolve from its clone — this is the defect 18-02 exists to "+
			"fix, still present. reason: %s", reason)
	}
	t.Logf("REALTOOLS regulator resolved: Path=%s ArgvPrefix=%v WorkDir=%s",
		tool.Path, tool.ArgvPrefix, tool.WorkDir)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	runner := backend.NewRunner(backend.NewLocalBackend(5*time.Second), reg, nil)
	res, runErr := runner.RunOpts(ctx, "regulator", []string{"--help"}, backend.ExecOptions{})

	// A non-zero exit is acceptable; a DISPATCH FAILURE is not. That is precisely
	// the distinction phase 16 built the label partition for.
	var toolErr *coreerrors.ToolError
	if runErr != nil && errors.As(runErr, &toolErr) && toolErr.NeverStarted {
		t.Fatalf("regulator DISPATCH FAILED (the process was never created): %v", runErr)
	}
	if res != nil {
		t.Logf("REALTOOLS regulator exit=%d stdout_first_line=%q",
			res.ExitCode, firstLine(res.Stdout))
	}

	// AND IT MUST ACTUALLY WORK, not merely start.
	//
	// The first version of this test asserted only "not a dispatch failure" and
	// PASSED while regulator was exiting 1 on
	// FileNotFoundError: 'logs/regulator.log' — main.py:18 hardcodes that
	// cwd-relative path. A test that accepts a crashing tool as proof that a tool
	// runs is the false green this whole phase exists to delete, so the assertion
	// is exit 0 and real usage output.
	if runErr != nil {
		t.Fatalf("regulator dispatched but FAILED: %v\n"+
			"  If this is FileNotFoundError on logs/regulator.log, clone_workdir is not being\n"+
			"  honoured — the tool must run from its own clone directory.", runErr)
	}
	if res == nil || res.ExitCode != 0 {
		t.Fatalf("regulator did not exit 0: res=%+v", res)
	}
	if !strings.Contains(string(res.Stdout), "usage: main.py") {
		t.Errorf("regulator stdout does not look like its usage output: %q", firstLine(res.Stdout))
	}
}

func firstLine(b []byte) string {
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}
