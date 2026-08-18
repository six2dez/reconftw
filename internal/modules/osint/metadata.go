// metadata.go — MetadataTask: doc-metadata fold-in via exiftool (D-O10 / D-O2).
//
// MetadataTask is the D-O10 metadata fold-in: it extracts document metadata
// (authors, software, internal file paths) from public documents already
// downloaded/indexed into the workspace (v1 modules/osint.sh:368 metadata →
// metafinder/exiftool over discovered docs). Each surfaced metadata datum becomes
// an informational OSINTFindingRecord (D-O4, Category doc-metadata).
//
// PURELY OPPORTUNISTIC (D-O2): this is the canonical D-O2 enrichment Task. It reads
// indexed/downloaded docs from the workspace artefacts IF present. When NO
// workspace docs exist it logs:
//
//	"osint.metadata: no workspace docs — skipping enrichment"
//
// and returns StatusSkipped — NO fail, NO bootstrap, NO coupling. The run COMPLETES
// over the root-domain baseline (ARCH-09 best_effort + D-V6 logged-never-silent).
//
// SEEDING (D-O1/D-O2): no DependsOn edges — the workspace-doc enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// THREAT MODEL (T-07-05-02 accept / T-07-05-03 mitigate): doc metadata (authors,
// internal paths) is the intended OSINT output (informational; no live
// credentials). exiftool reads ONLY already-discovered, bounded workspace docs;
// per-doc invocation keeps any single malicious/huge file isolated.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 2.
package osint

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// metadataMaxDocs bounds the per-doc exiftool loop (T-07-05-03 — bound the parse
// volume against a flood of workspace docs).
const metadataMaxDocs = 200

// metadataDocExtensions are the document file types worth metadata extraction
// (v1 osint.sh:398 grep filter — pdf/office/image formats carry author/software/
// path metadata).
var metadataDocExtensions = map[string]struct{}{
	".pdf": {}, ".doc": {}, ".docx": {}, ".xls": {}, ".xlsx": {},
	".ppt": {}, ".pptx": {}, ".odt": {}, ".ods": {}, ".odp": {},
	".jpg": {}, ".jpeg": {}, ".png": {}, ".gif": {}, ".tif": {},
	".tiff": {}, ".svg": {}, ".webp": {}, ".mp3": {},
}

// MetadataTask runs exiftool over workspace docs (D-O10 fold-in, D-O2 opportunistic).
type MetadataTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *MetadataTask) Name() string { return "osint.metadata" }

// Module returns the owning module group.
func (t *MetadataTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *MetadataTask) Description() string {
	return "Document metadata extraction (exiftool fold-in, D-O10 / D-O2 opportunistic)"
}

// Enabled reports whether the metadata fold-in is configured.
func (t *MetadataTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Metadata.Enabled
}

// DependsOn returns nil — the workspace-doc enrichment (D-O2) is OPPORTUNISTIC,
// not a DAG edge.
func (t *MetadataTask) DependsOn() []string { return nil }

// Run extracts metadata from already-discovered workspace docs (D-O2 opportunistic).
//
// Steps:
//  1. D-O2: discover indexed/downloaded docs in the workspace IF present; absent →
//     log the canonical skip note + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Loop exiftool per doc (v1 osint.sh:368 metafinder/exiftool over docs).
//  3. Parse metadata (authors, software, paths) into informational records.
//  4. Write inputs/findings.metadata.jsonl (multi-writer staging).
func (t *MetadataTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: D-O2 opportunistic doc discovery.
	docs := discoverWorkspaceDocs(app.Target.WorkDir)
	if len(docs) == 0 {
		// D-O2 canonical log-skip — best_effort, NO fail/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.metadata: no workspace docs — skipping enrichment")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.metadata: mkdir inputs/: %w", err)
	}

	if len(docs) > metadataMaxDocs {
		docs = docs[:metadataMaxDocs] // bound the parse volume (T-07-05-03)
	}

	var records []OSINTFindingRecord
	// exiftoolRan records whether AT LEAST ONE document was actually processed,
	// and cancelled records an interrupted loop. Neither an absent exiftool nor a
	// cancelled run observed the corpus, so neither may clear a previous run's
	// staging (F3 did-not-run — see writeOSINTStaging).
	exiftoolRan := false
	cancelled := false
	for _, doc := range docs {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		// v1 metadata extraction (osint.sh:368): exiftool over each doc. Use -S
		// (short tag names) + -Author/-Creator/-Producer/-Software to extract the
		// high-value author/software/path metadata.
		res, err := app.Tools.Run(ctx, "exiftool",
			[]string{"-S", "-Author", "-Creator", "-Producer", "-Software", "-Company", doc})
		if err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.metadata: exiftool run failed (best_effort)", "doc", doc, "err", err)
			}
			continue
		}
		exiftoolRan = true
		records = append(records, parseMetadataOutput(res.Stdout, doc)...)
	}

	// Step 4: write staging JSONL (multi-writer contract).
	// F3: a run in which exiftool extracted no author/software metadata REMOVES
	// the staging file rather than republishing the previous run's metadata.
	if exiftoolRan && !cancelled {
		writeOSINTStaging(app, inputsDir, "findings.metadata.jsonl", records)
	} else if app.Log != nil {
		app.Log.Debug("osint.metadata: exiftool did not process the corpus — staging preserved (F3 did-not-run)")
	}

	if app.Log != nil {
		app.Log.Info("osint.metadata: completed", "findings", len(records), "docs_scanned", len(docs))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "docs_scanned": len(docs)},
	}, nil
}

// discoverWorkspaceDocs walks the workspace osint/ and artefacts/ doc directories
// for already-downloaded documents (D-O2: opportunistic — reads IF present). It
// returns the absolute paths of files whose extension is in metadataDocExtensions.
// Returns nil when no doc directory or no matching docs exist (the log-skip path).
func discoverWorkspaceDocs(workDir string) []string {
	var out []string
	// Candidate doc roots where prior stages stash downloaded files.
	roots := []string{
		filepath.Join(workDir, "osint", "metadata_docs"),
		filepath.Join(workDir, "osint", "docs"),
		filepath.Join(workDir, "artefacts", "docs"),
	}
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.Walk(root, func(path string, fi os.FileInfo, wErr error) error { //nolint:errcheck
			if wErr != nil || fi == nil || fi.IsDir() {
				return nil //nolint:nilerr // best_effort walk
			}
			ext := strings.ToLower(filepath.Ext(path))
			if _, ok := metadataDocExtensions[ext]; ok {
				out = append(out, path)
			}
			return nil
		})
	}
	return out
}

// parseMetadataOutput parses exiftool -S key/value output for a single doc into
// informational doc-metadata records. Each non-empty "Tag: Value" line yields one
// record carrying the doc basename + tag + value (non-secret OSINT data,
// T-07-05-02 accept). Lines without a value are skipped.
func parseMetadataOutput(data []byte, doc string) []OSINTFindingRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	base := filepath.Base(doc)
	var records []OSINTFindingRecord
	for _, line := range splitNonEmptyLines(data) {
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		if val == "" {
			continue
		}
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "metadata",
			Category:    "doc-metadata",
			PoCRedacted: base + " | " + strings.TrimSpace(line),
		})
	}
	return records
}

// init self-registers MetadataTask with the Default task registry.
func init() { task.Register(&MetadataTask{}) }
