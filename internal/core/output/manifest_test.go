// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 2 (Manifest).
package output_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/output"
)

// Test 12: WriteManifest writes JSON with the ADR §3.3 schema.
func TestManifestSchema(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	started := time.Date(2026, 5, 28, 9, 0, 0, 0, time.UTC)
	m := &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "hackerone.com",
		StartedAt:        started,
		ConfigHash:       "sha256:abcd1234",
		ToolVersions: map[string]string{
			"subfinder": "v2.6.6",
			"httpx":     "v1.6.7",
		},
	}
	if err := output.WriteManifest(path, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	// Spot-check the required fields per ADR §3.3.
	for _, k := range []string{"workspace_version", "target", "started_at", "config_hash", "tool_versions"} {
		if _, ok := decoded[k]; !ok {
			t.Errorf("manifest missing key %q", k)
		}
	}
	if decoded["workspace_version"] != "2.0" {
		t.Errorf("workspace_version = %v; want 2.0", decoded["workspace_version"])
	}
	if decoded["target"] != "hackerone.com" {
		t.Errorf("target = %v; want hackerone.com", decoded["target"])
	}
}

// Test 13: WriteManifest uses atomic.WriteFile (atomicity guarantee).
// We verify by sanity-checking there is no .tmp.* leftover after a write.
func TestManifestAtomicWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := output.WriteManifest(path, &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "x",
		StartedAt:        time.Now().UTC(),
		ConfigHash:       "sha256:0",
	}); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover tempfile: %s", e.Name())
		}
	}
}

// Idempotent writes — two identical writes produce byte-equal output.
func TestManifestIdempotent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "x.com",
		StartedAt:        time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC),
		ConfigHash:       "sha256:0",
	}
	if err := output.WriteManifest(path, m); err != nil {
		t.Fatalf("first: %v", err)
	}
	first, _ := os.ReadFile(path)
	if err := output.WriteManifest(path, m); err != nil {
		t.Fatalf("second: %v", err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatalf("non-idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
}

// FinishedAt: writes when set; omits/leaves null when nil.
func TestManifestFinishedAtOmittedWhenNil(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	m := &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "x.com",
		StartedAt:        time.Now().UTC(),
		ConfigHash:       "sha256:0",
	}
	if err := output.WriteManifest(path, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"finished_at":`) {
		t.Fatalf("expected finished_at omitted when nil; got %s", data)
	}
}

// FinishedAt: included when set.
func TestManifestFinishedAtIncluded(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	finished := time.Date(2026, 5, 28, 12, 34, 56, 0, time.UTC)
	m := &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "x.com",
		StartedAt:        time.Now().UTC(),
		FinishedAt:       &finished,
		ConfigHash:       "sha256:0",
	}
	if err := output.WriteManifest(path, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"finished_at":`) {
		t.Fatalf("expected finished_at present; got %s", data)
	}
}

// Test 15: WorkspaceFinalize updates finished_at and writes atomically.
func TestWorkspaceFinalize(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	m := &output.Manifest{
		WorkspaceVersion: "2.0",
		Target:           "example.com",
		StartedAt:        time.Now().UTC().Add(-10 * time.Second),
		ConfigHash:       "sha256:0",
	}
	manifestPath := filepath.Join(ws, "manifest.json")
	if err := output.WriteManifest(manifestPath, m); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if err := output.WorkspaceFinalize(ws, m); err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := got["finished_at"]; !ok {
		t.Fatalf("Finalize did not stamp finished_at: %s", data)
	}
}
