// testssl_test.go — regression guard for the live all-mode nil-pointer panic
// (2026-08, testssl.go:129, found by the first real `reconftw all` on reconbox3).
//
// TestSSLTask.Run called app.Tools.Run then dereferenced res.Stdout — but
// app.Tools.Run returns a NIL *Result when the tool is unregistered/absent
// (backend/runner.go Lookup miss). testssl.sh was not registered on the box, so
// the run SIGSEGV'd in the vulns stage. The fix guards `res == nil` → StatusSkipped.
// The same shape was fixed in llm.go/websocket.go/fray.go (identical guard); those
// tasks read their URL corpus through a currently-broken path (readURLsJSONL
// double-joins artefacts/urls.jsonl) so they cannot be driven to the Tools.Run
// call in a unit test yet — they are covered by the shared guard + the live
// all-mode re-run. See project_cutover_validation_run memory for the URL bug.
package vulns

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

func TestTestSSLTaskDegradesWhenBinaryMissing(t *testing.T) {
	workDir := t.TempDir()

	// Seed a non-empty testssl input (ips_nocdn.txt is resolveTestSSLInput's
	// priority 1) so Run gets PAST the empty-input skip and reaches app.Tools.Run.
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "ips_nocdn.txt"), []byte("example.com\n"), 0o644); err != nil {
		t.Fatalf("seed ips_nocdn.txt: %v", err)
	}

	// EMPTY registry → app.Tools.Run(anytool) returns (nil, ToolError) — exactly
	// the "testssl.sh not installed/registered" condition that fired the panic.
	reg := backend.NewToolRegistry()
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(backend.NewLocalBackend(time.Second), reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    config.Defaults(),
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	// Must NOT panic (the bug) and must degrade to Skipped (the fix).
	res, err := (&TestSSLTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned error, expected graceful skip: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("Run status = %v, want StatusSkipped (missing tool → degrade, not panic)", res.Status)
	}

	// Self-validation: inputs/testssl_targets.txt is written right BEFORE
	// app.Tools.Run, so its presence proves Run actually reached the nil-res tool
	// call — i.e. the Skipped above came from the nil-res guard, NOT the earlier
	// empty-input return. Without this check the test would pass even unfixed.
	if _, statErr := os.Stat(filepath.Join(workDir, "inputs", "testssl_targets.txt")); statErr != nil {
		t.Fatalf("inputs/testssl_targets.txt not written — Run never reached app.Tools.Run, "+
			"so this test cannot prove the nil-res guard: %v", statErr)
	}
}
