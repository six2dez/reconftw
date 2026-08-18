// report_dir_test.go — plan 15-11 Task 2: the `report` subcommand must name the
// directory the renderer ACTUALLY wrote.
//
// It printed filepath.Join(dataDir, "reports") unconditionally. Once reports
// moved to reports/<target-slug>/<scan-id>/ that path holds directories, not a
// report, so the only pointer a CLI user gets would have sent them to the wrong
// place — and nothing would have failed.
package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/ingest"
)

// TestReportCmdPrintsTheRealRenderDirectory runs the subcommand end to end
// against a seeded store and follows the path it printed.
func TestReportCmdPrintsTheRealRenderDirectory(t *testing.T) {
	const target = "cliprint.example"
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"),
		[]byte(`{"host":"api.`+target+`","ip":"1.1.1.1"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write hosts.jsonl: %v", err)
	}
	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", nil); err != nil {
		t.Fatalf("seed ScanIntoStore: %v", err)
	}

	// RECONFTW_PATHS_DATA_DIR → paths.data_dir (loader.go layer 7), so the
	// subcommand resolves the same store this test seeded.
	t.Setenv("RECONFTW_PATHS_DATA_DIR", dataDir)

	cmd := newReportCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--target", target})
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("report subcommand: %v", err)
	}

	const prefix = "reports written to: "
	var printed string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			printed = strings.TrimSpace(strings.TrimPrefix(line, prefix))
			break
		}
	}
	if printed == "" {
		t.Fatalf("the subcommand printed no report location; output was:\n%s", out.String())
	}

	info, err := os.Stat(printed)
	if err != nil {
		t.Fatalf("the printed path %q does not exist: %v", printed, err)
	}
	if !info.IsDir() {
		t.Fatalf("the printed path %q is not a directory", printed)
	}
	if _, err := os.Stat(filepath.Join(printed, "manifest.json")); err != nil {
		t.Errorf("the printed directory holds no manifest.json — it is not a render directory: %v", err)
	}
	if printed == filepath.Join(dataDir, "reports") {
		t.Error("the subcommand printed the reports ROOT, not the scan's render directory")
	}
}

// TestReportCmdHasIncludeHistoricalFlag pins the opt-in's presence and default:
// a report is scan-scoped unless the operator asks otherwise.
func TestReportCmdHasIncludeHistoricalFlag(t *testing.T) {
	cmd := newReportCmd()
	f := cmd.Flags().Lookup("include-historical")
	if f == nil {
		t.Fatal("report has no --include-historical flag")
	}
	if f.DefValue != "false" {
		t.Errorf("--include-historical defaults to %q; want false", f.DefValue)
	}
}
