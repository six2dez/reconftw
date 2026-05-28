// Source: ADR §3.3 lines 1254-1290 — manifest.json schema (BINDING).
//
// The manifest is written via WriteFile (4-step atomic per ADR §3.5).
// Tool versions are populated at startup by the ToolRegistry (Plan 04);
// config_hash is the SHA-256 of inputs/config.snapshot.toml computed by
// AppContext.Boot (Plan 05).
package output

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"
)

// Manifest is the workspace metadata record at workspaces/<target-id>/manifest.json.
// Schema fields mirror ADR §3.3 exactly.
type Manifest struct {
	// WorkspaceVersion identifies the schema. v2.0 ships "2.0".
	WorkspaceVersion string `json:"workspace_version"`
	// Target is the exact input as provided by the user.
	Target string `json:"target"`
	// TargetID is the slugged target — result of sanitize equivalent.
	TargetID string `json:"target_id,omitempty"`
	// StartedAt is set by WorkspaceInit.
	StartedAt time.Time `json:"started_at"`
	// FinishedAt is set by WorkspaceFinalize. Omitted (null) until then.
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// ConfigHash is sha256 hex of inputs/config.snapshot.toml.
	ConfigHash string `json:"config_hash"`
	// ToolVersions is name → version string. Populated by ToolRegistry.
	ToolVersions map[string]string `json:"tool_versions,omitempty"`
}

// WriteManifest serializes m as indented JSON and writes path via the
// 4-step AtomicWriter.
func WriteManifest(path string, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("output: WriteManifest: nil manifest")
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("output: WriteManifest marshal: %w", err)
	}
	return WriteFile(path, data, 0o644)
}

// WorkspaceFinalize stamps the current UTC time into m.FinishedAt and
// writes the manifest atomically under workspaceRoot/manifest.json.
// Safe to call multiple times — each call updates finished_at.
func WorkspaceFinalize(workspaceRoot string, m *Manifest) error {
	if m == nil {
		return fmt.Errorf("output: WorkspaceFinalize: nil manifest")
	}
	now := time.Now().UTC()
	m.FinishedAt = &now
	return WriteManifest(filepath.Join(workspaceRoot, "manifest.json"), m)
}
