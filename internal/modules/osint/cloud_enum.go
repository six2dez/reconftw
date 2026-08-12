// cloud_enum.go — CloudEnumTask: S3/GCP/Azure bucket enumeration (OSINT-07).
//
// CloudEnumTask runs cloud_enum (v1 modules/osint.sh:714 cloud_enum_scan, seeded
// by company name + root domain) to discover exposed S3, GCP, and Azure storage
// buckets. Exposed/public buckets are genuine security findings, so they become
// OSINTFindingRecords with a security severity (medium/high), NOT informational
// records — a public bucket is an exploitable misconfiguration.
//
// CONSERVATIVE V1 CAPS (D-O8): cloud_enum is a noisy source. It ships with the
// conservative v1 thread cap (CLOUD_ENUM_S3_THREADS=20, core.sh:309) and the
// "optimized" profile (CLOUD_ENUM_S3_PROFILE, core.sh:308 → quickscan). These
// bound probe volume against attacker-influenced hosts (T-07-04-03).
//
// SEEDING (D-O1): company + root-domain-seeded — no DependsOn edges. The company
// label (companyName) and the registrable root cross into cloud_enum's []string
// argv via the -k keyword flags (never a shell string — T-07-04-04).
//
// HEARTBEAT (XCUT-09): cloud_enum can run long; it is invoked via app.Tools.Stream
// and the event channel is drained so the scheduler heartbeat keeps ticking
// (T-07-04-05). Bucket lines surface on stdout and are collected for parsing.
//
// HIGH-VALUE LIST (D-O5): the discovered bucket list is preserved as the
// single-writer human file osint/cloud_enum.txt (v1 osint.sh:725 anew target).
//
// FAILURE POLICY (D-O8): best_effort — tool failure / empty output logs Debug and
// returns StatusDone with findings:0.
//
// Source: .planning/phases/07-osint-e2e/07-04-PLAN.md Task 1.
package osint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// cloudEnumDefaultThreads is the conservative v1 thread cap (D-O8,
// CLOUD_ENUM_S3_THREADS=20, core.sh:309) used when config carries no override.
const cloudEnumDefaultThreads = 20

// cloudEnumProfile is the conservative v1 default profile (CLOUD_ENUM_S3_PROFILE,
// core.sh:308). "optimized" maps to cloud_enum quickscan (-qs).

// CloudEnumTask runs cloud_enum for OSINT-07 (S3/GCP/Azure bucket enumeration).
type CloudEnumTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *CloudEnumTask) Name() string { return "osint.cloud_enum" }

// Module returns the owning module group.
func (t *CloudEnumTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *CloudEnumTask) Description() string {
	return "Cloud storage enumeration — S3/GCP/Azure buckets (cloud_enum, OSINT-07)"
}

// Enabled reports whether cloud enumeration is configured.
func (t *CloudEnumTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.Cloud.Enabled
}

// DependsOn returns nil — cloud_enum is company/root-domain-seeded (D-O1).
func (t *CloudEnumTask) DependsOn() []string { return nil }

// Run executes cloud_enum across S3/GCP/Azure with the conservative v1 caps.
//
// Steps:
//  1. Derive + validate the root domain → company name (T-07-04-04).
//  2. Build the cloud_enum arg vector with conservative threads + quickscan.
//  3. Stream cloud_enum (XCUT-09 heartbeat); collect stdout bucket lines.
//  4. Preserve osint/cloud_enum.txt (D-O5 single-writer).
//  5. Parse exposed buckets into security-severity OSINTFindingRecords.
//  6. Write inputs/findings.cloud_enum.jsonl (multi-writer staging).
func (t *CloudEnumTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.cloud_enum: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	company := companyName(root)

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.cloud_enum: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	threads := cloudEnumDefaultThreads // conservative v1 cap (D-O8)

	// v1 arg vector (core.sh:380-399): -k <company> -k <domain> -k <label>
	//                                  -t <threads> -qs (optimized/quickscan).
	// S3/GCP/Azure are all scanned by default — cloud_enum probes every provider
	// unless explicitly disabled, so no per-provider flag is needed here.
	args := []string{
		"-k", company,
		"-k", root,
		"-k", labelOf(root),
		"-t", fmt.Sprintf("%d", threads),
		"-qs", // optimized profile (cloudEnumProfile) → quickscan
	}

	// Step 3: Stream (XCUT-09 heartbeat). Bucket findings surface on stdout.
	var bucketLines []string
	if ev, sErr := app.Tools.Stream(ctx, "cloud_enum", args); sErr != nil {
		if app.Log != nil {
			app.Log.Debug("osint.cloud_enum: stream error (best_effort)", "err", sErr)
		}
	} else {
		for e := range ev {
			if e.IsErr {
				continue
			}
			line := strings.TrimSpace(string(e.Line))
			if line == "" {
				continue
			}
			bucketLines = append(bucketLines, line)
		}
	}

	// Step 4: preserve the high-value bucket list (D-O5 single-writer).
	if len(bucketLines) > 0 {
		listPath := filepath.Join(osintDir, "cloud_enum.txt")
		if wErr := os.WriteFile(listPath,
			[]byte(strings.Join(bucketLines, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.cloud_enum: write cloud_enum.txt failed", "err", wErr)
		}
	}

	// Step 5: parse exposed buckets into security-severity records.
	records := parseCloudEnumLines(bucketLines)

	// Step 6: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.cloud_enum.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.cloud_enum: completed", "buckets", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"buckets": len(records)},
	}, nil
}

// labelOf returns the leftmost label of a domain (the v1 ${domain%%.*} seed,
// core.sh:385) — e.g. "example.com" → "example".
func labelOf(domain string) string {
	if idx := strings.IndexByte(domain, '.'); idx >= 0 {
		return domain[:idx]
	}
	return domain
}

// parseCloudEnumLines maps cloud_enum stdout lines to OSINTFindingRecords. Each
// reported bucket is classified by provider (cloud-bucket-{s3,gcp,azure}) and
// assigned a security severity: a PUBLIC/OPEN bucket is high (an exploitable
// exposure); any other reported (existing/protected) bucket is medium. Bucket
// names are the intended OSINT finding, NOT a credential (T-07-04-02 accept), so
// the bucket locator is carried in PoCRedacted.
func parseCloudEnumLines(lines []string) []OSINTFindingRecord {
	var records []OSINTFindingRecord
	for _, line := range lines {
		category := classifyCloudProvider(line)
		if category == "" {
			continue // not a bucket-bearing line (banner, progress, etc.)
		}
		severity := "medium"
		lower := strings.ToLower(line)
		if strings.Contains(lower, "public") || strings.Contains(lower, "open") ||
			strings.Contains(lower, "authenticated") {
			severity = "high"
		}
		records = append(records, OSINTFindingRecord{
			Severity:    severity,
			Confidence:  "medium",
			Class:       "osint",
			Source:      "cloud_enum",
			Category:    category,
			PoCRedacted: line, // bucket locator — non-secret OSINT finding (T-07-04-02)
		})
	}
	return records
}

// classifyCloudProvider inspects a cloud_enum line and returns the per-provider
// finding Category (cloud-bucket-s3 / -gcp / -azure) when the line names a
// bucket/storage resource, or "" when it is not a bucket finding. cloud_enum
// emits provider-tagged lines (e.g. "[+] OPEN S3 BUCKET: ...",
// "Google Storage Bucket: ...", "Azure Blob Container: ...").
func classifyCloudProvider(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "s3") ||
		strings.Contains(lower, "amazonaws") ||
		strings.Contains(lower, "aws bucket"):
		return "cloud-bucket-s3"
	case strings.Contains(lower, "gcp") ||
		strings.Contains(lower, "google storage") ||
		strings.Contains(lower, "googleapis") ||
		strings.Contains(lower, "storage.googleapis"):
		return "cloud-bucket-gcp"
	case strings.Contains(lower, "azure") ||
		strings.Contains(lower, "blob.core.windows") ||
		strings.Contains(lower, "windows.net"):
		return "cloud-bucket-azure"
	default:
		return ""
	}
}

// init self-registers CloudEnumTask with the Default task registry.
func init() { task.Register(&CloudEnumTask{}) }
