// buckets.go — SubBucketsTask: cloud bucket discovery via s3scanner.
//
// SINGLE-WRITER CONTRACT: SubBucketsTask is the ONLY writer for the "buckets"
// artefact. Since no concurrent Task writes to "buckets", direct
// app.Tree.Append is safe (no REPLACE-overwrite race).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md Task 1.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SubBucketsTask scans for cloud storage bucket misconfigurations (S3, GCS,
// Azure Blob) using s3scanner against the resolved subdomain list.
// Writes BucketRecord JSONL to artefacts/buckets.jsonl via single direct Append.
type SubBucketsTask struct{}

// Name returns the task identifier.
func (SubBucketsTask) Name() string { return "subdomains.buckets" }

// Module returns the owning module.
func (SubBucketsTask) Module() string { return "subdomains" }

// Description returns a short description.
func (SubBucketsTask) Description() string {
	return "Cloud bucket misconfiguration discovery via s3scanner"
}

// Enabled returns true when cfg.Subdomains.S3Buckets.Enabled is set.
func (SubBucketsTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.S3Buckets.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (SubBucketsTask) DependsOn() []string { return nil }

// Run executes s3scanner with --bucket-file resolved.merged.txt, parses the
// output into BucketRecord JSON lines, and appends them directly to the
// "buckets" artefact. This is safe because SubBucketsTask is the sole writer.
func (SubBucketsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "s3scanner"

	resolvedFile := filepath.Join(app.Target.WorkDir, "inputs", "resolved.merged.txt")

	// --bucket-file is the InputFlag declared in tools.lock (plan-00).
	args := []string{"scan", "--bucket-file", resolvedFile}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("s3scanner run failed or tool not registered",
				"tool", toolName, "err", err.Error())
		}
		// Non-fatal: emit empty result.
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"buckets_found": 0},
		}, nil
	}

	// Parse s3scanner output. s3scanner emits JSON lines with fields:
	// bucket, region, found, acl, provider, etc.
	var records [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		// Accept any JSON line — try to extract known fields.
		var entry struct {
			Bucket   string `json:"bucket"`
			Name     string `json:"name"`
			Region   string `json:"region"`
			Found    bool   `json:"found"`
			Exists   bool   `json:"exists"`
			ACL      string `json:"acl"`
			Access   string `json:"access"`
			Provider string `json:"provider"`
			URL      string `json:"url"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		// Normalise field variants.
		name := entry.Bucket
		if name == "" {
			name = entry.Name
		}
		acl := entry.ACL
		if acl == "" {
			acl = entry.Access
		}
		provider := entry.Provider
		if provider == "" {
			provider = "unknown"
		}
		url := entry.URL
		if url == "" && name != "" {
			url = fmt.Sprintf("https://%s.s3.amazonaws.com", name)
		}

		// Only record buckets that s3scanner reports as existing/found.
		if !entry.Found && !entry.Exists {
			continue
		}

		rec := BucketRecord{
			Provider: provider,
			Name:     name,
			URL:      url,
			Access:   acl,
		}
		encoded, encErr := json.Marshal(rec)
		if encErr != nil {
			continue
		}
		records = append(records, encoded)
	}

	if len(records) > 0 {
		if err := app.Tree.Append("buckets", records); err != nil {
			if app.Log != nil {
				app.Log.Debug("s3scanner: Tree.Append(buckets) failed",
					"err", err.Error(), "records", len(records))
			}
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("s3scanner: Tree.Append(buckets): %w", err)
		}
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"buckets_found": len(records)},
	}, nil
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(SubBucketsTask{}) }
