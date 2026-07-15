// csprecon_test.go — TDD tests for SubCspreconTask (PAR-01, 13-02 Task 1).
//
// Verifies the subdomains-stage csprecon discovery task: metadata + gate, the
// plain-line in-scope staging write (inputs/resolved.csprecon.txt), the anchored
// off-scope filter (extract/csp.Extract), and the aux best-effort degrade
// (csprecon tool error → StatusDone, never StatusErrored).
//
// Source: .planning/phases/13-domain-parity/13-02-PLAN.md Task 1.
package subdomains_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// writePassiveMerged writes inputs/passive.merged.txt (the csprecon input surface).
func writePassiveMerged(t *testing.T, workDir string, hosts ...string) {
	t.Helper()
	inputsDir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	body := strings.Join(hosts, "\n")
	if len(hosts) > 0 {
		body += "\n"
	}
	if err := os.WriteFile(filepath.Join(inputsDir, "passive.merged.txt"), []byte(body), 0o644); err != nil {
		t.Fatalf("write passive.merged.txt: %v", err)
	}
}

// -------------------------------------------------------------------------
// Test: metadata + Enabled gate (reuses the scraping gate — no new config field)
// -------------------------------------------------------------------------

func TestCspreconTaskMetadata(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.csprecon")
	if !ok {
		t.Fatal("subdomains.csprecon not registered (SubCspreconTask missing)")
	}
	if tsk.Name() != "subdomains.csprecon" {
		t.Errorf("Name() = %q, want subdomains.csprecon", tsk.Name())
	}
	if tsk.Module() != "subdomains" {
		t.Errorf("Module() = %q, want subdomains", tsk.Module())
	}
	if deps := tsk.DependsOn(); deps != nil {
		t.Errorf("DependsOn() = %v, want nil (sequential RunStage staging)", deps)
	}

	// Enabled must track cfg.Subdomains.Scraping.Enabled exactly.
	off := &config.Config{}
	off.Subdomains.Scraping.Enabled = false
	if tsk.Enabled(off) {
		t.Errorf("Enabled(Scraping.Enabled=false) = true, want false")
	}
	on := &config.Config{}
	on.Subdomains.Scraping.Enabled = true
	if !tsk.Enabled(on) {
		t.Errorf("Enabled(Scraping.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test: csprecon output → PLAIN in-scope hostnames in resolved.csprecon.txt;
//       off-scope hosts filtered out (extract/csp anchored suffix filter).
// -------------------------------------------------------------------------

func TestCspreconTaskStagesInScopeHosts(t *testing.T) {
	workDir := t.TempDir()
	writePassiveMerged(t, workDir, "www.example.com")

	// csprecon plain-text output: 2 in-scope + 2 off-scope hostnames.
	cspOut := "api.example.com\ncdn.example.com\nevil.com\nattacker.net\n"
	mockBe := &mockBackend{result: &backend.Result{Stdout: []byte(cspOut), ExitCode: 0}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "csprecon"})
	runner := backend.NewRunner(mockBe, reg, nil)

	app := newTestApp(workDir, runner, &mockTree{})

	tsk, ok := task.Default.Lookup("subdomains.csprecon")
	if !ok {
		t.Fatal("subdomains.csprecon not registered")
	}
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubCspreconTask.Run: unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}

	staged, err := os.ReadFile(filepath.Join(workDir, "inputs", "resolved.csprecon.txt"))
	if err != nil {
		t.Fatalf("inputs/resolved.csprecon.txt not written: %v", err)
	}
	content := string(staged)

	// In-scope hosts present.
	for _, want := range []string{"api.example.com", "cdn.example.com"} {
		if !strings.Contains(content, want) {
			t.Errorf("resolved.csprecon.txt missing in-scope %q; got:\n%s", want, content)
		}
	}
	// Off-scope hosts filtered out (T-13-02-01).
	for _, bad := range []string{"evil.com", "attacker.net"} {
		if strings.Contains(content, bad) {
			t.Errorf("resolved.csprecon.txt contains off-scope %q — csp.Extract filter bypassed", bad)
		}
	}
	// Staging must be PLAIN lines (MergeStage reads line-by-line, NOT JSON).
	for _, line := range strings.Split(content, "\n") {
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, "{}\"") {
			t.Errorf("staging line %q looks like JSON; staging files must be plain hostnames", line)
		}
	}
}

// -------------------------------------------------------------------------
// Test: csprecon tool error degrades to StatusDone with an empty staging file
//       (aux best-effort discovery source — never StatusErrored).
// -------------------------------------------------------------------------

func TestCspreconTaskDegradesOnToolError(t *testing.T) {
	workDir := t.TempDir()
	writePassiveMerged(t, workDir, "www.example.com")

	failBe := &erroringBackend{err: errors.New("csprecon: binary absent")}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "csprecon"})
	runner := backend.NewRunner(failBe, reg, nil)

	app := newTestApp(workDir, runner, &mockTree{})

	tsk, _ := task.Default.Lookup("subdomains.csprecon")
	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubCspreconTask.Run: tool error must NOT propagate, got err: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done (aux best-effort degrade)", res.Status)
	}

	// An (empty) staging file must exist so MergeStage sees a consistent set.
	staged, err := os.ReadFile(filepath.Join(workDir, "inputs", "resolved.csprecon.txt"))
	if err != nil {
		t.Fatalf("empty staging file not written on degrade: %v", err)
	}
	if strings.TrimSpace(string(staged)) != "" {
		t.Errorf("degrade staging file should be empty, got: %q", string(staged))
	}
}
