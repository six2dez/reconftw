//go:build realtools

// nomore403_realtools_test.go — the REAL clone, driven through the REAL seam.
//
// Behind the `realtools` tag because it needs ~/Tools/nomore403 on disk. Run it
// with:
//
//	go test -tags realtools -count=1 -run TestNomore403RealCloneDispatches ./internal/modules/web/
//
// SAFETY (T-18-05-04). 17-04's arg-vector census started a real nomore403 out of
// $HOME/Tools and logged `signal: killed`. So this test:
//
//   - targets an httptest server on LOOPBACK ONLY. No third party is contacted,
//     and the target URL is generated at run time so it cannot be edited into a
//     public host by accident.
//   - carries its own short deadline, well under the tools.lock 300s.
//   - is skipped, not failed, when the clone is absent — an UNPROVEN-HERE leg is
//     an honest result; a green test that silently ran nothing is not.
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

func TestNomore403RealCloneDispatches(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("UNPROVEN-HERE: no home directory: %v", err)
	}
	toolsRoot := filepath.Join(home, "Tools")
	entry := filepath.Join(toolsRoot, "nomore403", "nomore403")
	if _, statErr := os.Stat(entry); statErr != nil {
		t.Skipf("UNPROVEN-HERE: %s is absent (%v). Command that would prove it: "+
			"go test -tags realtools -run TestNomore403RealCloneDispatches ./internal/modules/web/", entry, statErr)
	}

	// A loopback 403 — the shape this task exists to attack.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	workDir := t.TempDir()
	for _, d := range []string{"artefacts", "inputs", "logs"} {
		if mkErr := os.MkdirAll(filepath.Join(workDir, d), 0o755); mkErr != nil {
			t.Fatalf("mkdir %s: %v", d, mkErr)
		}
	}
	line, mErr := json.Marshal(FuzzRecord{URL: srv.URL + "/admin", Status: 403})
	if mErr != nil {
		t.Fatalf("marshal: %v", mErr)
	}
	if wErr := os.WriteFile(filepath.Join(workDir, "artefacts", "fuzz.jsonl"),
		append(line, '\n'), 0o600); wErr != nil {
		t.Fatalf("seed fuzz.jsonl: %v", wErr)
	}

	reg := backend.NewToolRegistry()
	reg.ToolsDir = toolsRoot
	reg.Register(&backend.Tool{
		Name:         nomore403ToolName,
		CloneDir:     "nomore403",
		CloneEntry:   "nomore403",
		CloneWorkDir: true,
		Timeout:      90 * time.Second,
	})
	if dErr := reg.Discover(context.Background()); dErr != nil {
		t.Fatalf("Discover: %v", dErr)
	}
	tool, ok := reg.Lookup(nomore403ToolName)
	if !ok || tool.Path == "" {
		t.Fatalf("REALTOOLS: nomore403 did not resolve from %s — Path=%q", toolsRoot, tool.Path)
	}
	t.Logf("REALTOOLS nomore403 resolved: Path=%s WorkDir=%s ArgvPrefix=%v",
		tool.Path, tool.WorkDir, tool.ArgvPrefix)

	logPath := filepath.Join(workDir, "logs", "tools.jsonl")
	cfg := config.Defaults()
	cfg.Vulns.Bypass4xx.Enabled = true
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "127.0.0.1", WorkDir: workDir},
	}
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	res, runErr := (&Nomore403Task{}).Run(ctx, app)
	if runErr != nil {
		t.Fatalf("REALTOOLS Nomore403Task.Run: %v", runErr)
	}
	if cErr := app.Tools.Recorder.Close(); cErr != nil {
		t.Fatalf("close recorder: %v", cErr)
	}
	t.Logf("REALTOOLS nomore403 status=%v stats=%v", res.Status, res.Stats)

	data, rErr := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if rErr != nil {
		t.Fatalf("REALTOOLS: no logs/tools.jsonl — the real clone never crossed the recorder: %v", rErr)
	}
	t.Logf("REALTOOLS recorder:\n%s", data)

	var outcome string
	var sawStart bool
	for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if l == "" {
			continue
		}
		var rec struct {
			Phase   string `json:"phase"`
			Tool    string `json:"tool"`
			Outcome string `json:"outcome"`
		}
		if uErr := json.Unmarshal([]byte(l), &rec); uErr != nil {
			t.Fatalf("tools.jsonl line is not JSON: %v", uErr)
		}
		if rec.Tool != nomore403ToolName {
			continue
		}
		if rec.Phase == "start" {
			sawStart = true
		}
		if rec.Phase == "end" {
			outcome = rec.Outcome
		}
	}
	if !sawStart {
		t.Fatalf("REALTOOLS: no start record for nomore403")
	}
	if outcome == "dispatch_failed" {
		t.Fatalf("REALTOOLS: outcome = dispatch_failed — the real clone was NOT started. "+
			"Path=%s WorkDir=%s", tool.Path, tool.WorkDir)
	}
	t.Logf("REALTOOLS nomore403 outcome=%q (non-dispatch_failed is the criterion)", outcome)

	if res.Status != task.StatusDone && res.Status != task.StatusSkipped {
		t.Fatalf("REALTOOLS: status = %v, want done or skipped", res.Status)
	}
}
