// manifest.go — what ONE render call actually wrote.
//
// The MCP report tool used to answer by listing the reports directory, so it
// returned every file that happened to be there: a previous run's Faraday
// export, an AI report written when AI was still enabled, and — on a shared
// data dir — another engagement's export (T-15-11-02, T-15-11-03). A directory
// listing answers "what is here", which is not the question. RenderResult
// answers "what did this call produce".
//
// The shape deliberately mirrors internal/core/output/manifest.go
// (Manifest / WriteManifest): same json.MarshalIndent + atomic output.WriteFile
// pipeline, so there is one manifest concept in the codebase, written one way.
package report

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/six2dez/reconftw/internal/core/output"
)

// RenderManifestName is the per-render manifest written inside the scan's
// report directory. It is NOT listed in RenderResult.Files: Files enumerates
// the report itself, and a manifest that listed itself could never be written
// (its own hash would change as it was written).
const RenderManifestName = "manifest.json"

// LatestPointerName is the stable per-target path a consumer can follow to the
// most recent render. internal/core/output/atomic.go has no symlink primitive,
// so the pointer is a small JSON file written through the same atomic writer
// rather than a symlink — one fewer platform-specific behaviour, and it carries
// the scan id as well as the path.
const LatestPointerName = "latest.json"

// HistoricalMarkerName is written into the render directory when a report was
// widened past the scan it names. The marker is a file as well as an HTML
// banner so the widening survives a consumer that only reads the machine
// formats.
const HistoricalMarkerName = "HISTORICAL-SCOPE.txt"

// RenderResult is the manifest of one RenderAll call.
type RenderResult struct {
	// ScanID is the scan this report describes.
	ScanID string `json:"scan_id"`
	// TargetID is the target the scan belongs to (the scan's own target, not
	// necessarily the one the caller passed).
	TargetID string `json:"target_id"`
	// Dir is the directory this render wrote into:
	// <dataDir>/reports/<target-slug>/<scan-id>/.
	Dir string `json:"dir"`
	// Files are the absolute paths this call wrote, sorted. RenderManifestName
	// is excluded.
	Files []string `json:"files"`
	// RenderedAt is when the render completed (UTC).
	RenderedAt time.Time `json:"rendered_at"`
	// IncludeHistorical records whether the asset lists were widened beyond the
	// scan's own observations.
	IncludeHistorical bool `json:"include_historical"`
	// Notice carries HistoricalNotice when IncludeHistorical is set.
	Notice string `json:"notice,omitempty"`
}

// add records a file this render wrote.
func (res *RenderResult) add(path string) {
	res.Files = append(res.Files, path)
}

// finalise sorts Files and stamps RenderedAt.
func (res *RenderResult) finalise() {
	sort.Strings(res.Files)
	res.RenderedAt = time.Now().UTC()
}

// WriteRenderManifest serialises res to <res.Dir>/manifest.json through the
// atomic writer.
func WriteRenderManifest(res *RenderResult) error {
	if res == nil {
		return fmt.Errorf("report: WriteRenderManifest: nil result")
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return fmt.Errorf("report: WriteRenderManifest marshal: %w", err)
	}
	return output.WriteFile(filepath.Join(res.Dir, RenderManifestName), data, 0o644)
}

// LatestPointer is the content of <dataDir>/reports/<target-slug>/latest.json.
//
// It exists because moving reports into per-scan directories changes a
// documented output path (T-15-11-07): a consumer hard-coded to a fixed
// location needs one that still resolves after the change.
type LatestPointer struct {
	ScanID     string    `json:"scan_id"`
	Dir        string    `json:"dir"`
	RenderedAt time.Time `json:"rendered_at"`
}

// WriteLatestPointer refreshes targetDir/latest.json to point at res.Dir.
func WriteLatestPointer(targetDir string, res *RenderResult) error {
	if res == nil {
		return fmt.Errorf("report: WriteLatestPointer: nil result")
	}
	data, err := json.MarshalIndent(LatestPointer{
		ScanID:     res.ScanID,
		Dir:        res.Dir,
		RenderedAt: res.RenderedAt,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("report: WriteLatestPointer marshal: %w", err)
	}
	return output.WriteFile(filepath.Join(targetDir, LatestPointerName), data, 0o644)
}
