// manifest_test.go — plan 15-11 Task 2: per-scan report directories and the
// render manifest.
//
// The behaviour under test is "the report tells you what it wrote, and writes
// it somewhere no previous run can contaminate". Both halves are asserted
// against the FILESYSTEM, not against the struct alone: a manifest that agrees
// with itself proves nothing.
package report_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/report"
)

// seedTwoScans ingests two runs of one target and returns (dataDir, scanA, scanB).
func seedTwoScans(t *testing.T, target string) (string, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")

	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl":    hostLine("api."+target, "1.1.1.1") + "\n",
		"findings.jsonl": findingLine("api."+target, "panel", "https://api."+target+"/a") + "\n",
	})
	a := ingestRun(t, dataDir, workDir, target)

	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl":    hostLine("api."+target, "1.1.1.1") + "\n",
		"findings.jsonl": findingLine("api."+target, "panel", "https://api."+target+"/a") + "\n",
	})
	b := ingestRun(t, dataDir, workDir, target)

	if a.ScanID == b.ScanID {
		t.Fatalf("both runs share scan id %s", a.ScanID)
	}
	return dataDir, a.ScanID, b.ScanID
}

// renderOne renders one scan and returns the full manifest.
func renderOne(t *testing.T, dataDir, target, scanID string, cfg *config.Config) report.RenderResult {
	t.Helper()
	if cfg == nil {
		cfg = config.Defaults()
	}
	r, err := report.NewReportRenderer(dataDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer r.Close() //nolint:errcheck
	res, err := r.RenderAll(context.Background(), target, scanID, false, false)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}
	return res
}

// TestRenderAll_TwoScansLandInDifferentDirectories pins the layout:
// <dataDir>/reports/<target-slug>/<scan-id>/, with the slug shared with the
// workspace tree.
func TestRenderAll_TwoScansLandInDifferentDirectories(t *testing.T) {
	const target = "twodirs.example"
	dataDir, scanA, scanB := seedTwoScans(t, target)

	resA := renderOne(t, dataDir, target, scanA, nil)
	resB := renderOne(t, dataDir, target, scanB, nil)

	if resA.Dir == resB.Dir {
		t.Fatalf("both scans rendered into %s — a run can inherit the other's files", resA.Dir)
	}

	ident, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	targetRoot := filepath.Join(dataDir, "reports", ident.Slug)
	for _, tc := range []struct {
		scanID string
		dir    string
	}{{scanA, resA.Dir}, {scanB, resB.Dir}} {
		want := filepath.Join(targetRoot, tc.scanID)
		if tc.dir != want {
			t.Errorf("render dir = %s; want %s (reports/<slug>/<scan-id>)", tc.dir, want)
		}
		if _, statErr := os.Stat(tc.dir); statErr != nil {
			t.Errorf("render dir %s does not exist: %v", tc.dir, statErr)
		}
	}
}

// TestRenderResultFilesMatchTheDirectoryExactly compares the manifest against a
// glob of the directory: the manifest may neither claim a file it did not write
// nor omit one it did.
func TestRenderResultFilesMatchTheDirectoryExactly(t *testing.T) {
	const target = "manifest.example"
	dataDir, scanA, _ := seedTwoScans(t, target)

	res := renderOne(t, dataDir, target, scanA, nil)

	onDisk, err := filepath.Glob(filepath.Join(res.Dir, "*"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var want []string
	for _, p := range onDisk {
		if filepath.Base(p) == report.RenderManifestName {
			continue // the manifest describes the report; it is not part of it
		}
		want = append(want, p)
	}
	sort.Strings(want)
	got := append([]string(nil), res.Files...)
	sort.Strings(got)

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("RenderResult.Files does not match the directory\n got: %v\nwant: %v", got, want)
	}
	if len(got) == 0 {
		t.Error("the render claims to have written nothing")
	}
}

// TestRenderAll_StaleFileIsNotReportedAsThisRun plants a file in the TARGET's
// report root — the shared location a pre-15-11 run wrote to — and asserts the
// new scan neither lists nor inherits it.
func TestRenderAll_StaleFileIsNotReportedAsThisRun(t *testing.T) {
	const target = "stale.example"
	dataDir, scanA, _ := seedTwoScans(t, target)

	ident, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	targetRoot := filepath.Join(dataDir, "reports", ident.Slug)
	if mkErr := os.MkdirAll(targetRoot, 0o755); mkErr != nil {
		t.Fatalf("mkdir target report root: %v", mkErr)
	}
	stale := filepath.Join(targetRoot, "faraday.xml")
	if wErr := os.WriteFile(stale, []byte("<stale/>"), 0o644); wErr != nil {
		t.Fatalf("plant stale file: %v", wErr)
	}

	// Faraday stays disabled for this render, so a correct implementation has
	// no Faraday output of its own to confuse with the stale one.
	cfg := config.Defaults()
	cfg.Integrations.Faraday.Enabled = false
	res := renderOne(t, dataDir, target, scanA, cfg)

	for _, f := range res.Files {
		if f == stale {
			t.Error("the stale file is listed as part of this render")
		}
		if filepath.Base(f) == "faraday.xml" {
			t.Errorf("a Faraday artefact (%s) is reported for a render with Faraday disabled", f)
		}
	}
	if _, statErr := os.Stat(filepath.Join(res.Dir, "faraday.xml")); !os.IsNotExist(statErr) {
		t.Errorf("the stale file leaked into the scan directory; stat err = %v", statErr)
	}
	if _, statErr := os.Stat(stale); statErr != nil {
		t.Errorf("the render deleted a file it does not own: %v", statErr)
	}
}

// TestRenderManifestOnDiskMatchesTheReturnedResult reads manifest.json back.
func TestRenderManifestOnDiskMatchesTheReturnedResult(t *testing.T) {
	const target = "manifestfile.example"
	dataDir, scanA, _ := seedTwoScans(t, target)

	res := renderOne(t, dataDir, target, scanA, nil)

	data, err := os.ReadFile(filepath.Join(res.Dir, report.RenderManifestName))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var onDisk report.RenderResult
	if uErr := json.Unmarshal(data, &onDisk); uErr != nil {
		t.Fatalf("manifest.json does not unmarshal to a RenderResult: %v", uErr)
	}
	if onDisk.ScanID != scanA {
		t.Errorf("manifest scan_id = %q; want %q", onDisk.ScanID, scanA)
	}
	if onDisk.Dir != res.Dir {
		t.Errorf("manifest dir = %q; want %q", onDisk.Dir, res.Dir)
	}
	if len(onDisk.Files) != len(res.Files) {
		t.Errorf("manifest lists %d files; the call returned %d", len(onDisk.Files), len(res.Files))
	}
}

// TestLatestPointerFollowsTheMostRecentRender proves the compatibility pointer
// works: a consumer that cannot know the scan id still has one stable path.
func TestLatestPointerFollowsTheMostRecentRender(t *testing.T) {
	const target = "latest.example"
	dataDir, scanA, scanB := seedTwoScans(t, target)

	resA := renderOne(t, dataDir, target, scanA, nil)
	ident, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	pointerPath := filepath.Join(dataDir, "reports", ident.Slug, report.LatestPointerName)

	readPointer := func() report.LatestPointer {
		t.Helper()
		data, rErr := os.ReadFile(pointerPath)
		if rErr != nil {
			t.Fatalf("read latest pointer: %v", rErr)
		}
		var p report.LatestPointer
		if uErr := json.Unmarshal(data, &p); uErr != nil {
			t.Fatalf("latest pointer is not valid JSON: %v", uErr)
		}
		return p
	}

	if p := readPointer(); p.Dir != resA.Dir || p.ScanID != scanA {
		t.Errorf("after render A the pointer is %+v; want scan %s at %s", p, scanA, resA.Dir)
	}

	resB := renderOne(t, dataDir, target, scanB, nil)
	p := readPointer()
	if p.Dir != resB.Dir || p.ScanID != scanB {
		t.Errorf("after render B the pointer is %+v; want scan %s at %s", p, scanB, resB.Dir)
	}
	if _, statErr := os.Stat(filepath.Join(p.Dir, report.RenderManifestName)); statErr != nil {
		t.Errorf("the pointer names a directory with no manifest: %v", statErr)
	}
}
