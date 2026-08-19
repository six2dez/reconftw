// Tests for WorkspaceInit — the STABLE per-target workspace (INTEG-03).
//
// The central property under test is stability + persistence: two calls for the
// same (rootDir, target) MUST return the identical path and MUST NOT destroy a
// file written between them. That persistence is exactly what lets
// <workspace>/checkpoints.db survive across runs so the scheduler can resume.
//
// External test package — WorkspaceInit is exercised through its exported API;
// sanitization is asserted via the returned path (no internal coupling).
package output_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

// TestWorkspaceInitStablePath: two calls with the same target return the SAME
// path (no timestamp component) and it equals filepath.Join(root, slug).
func TestWorkspaceInitStablePath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	first, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("first WorkspaceInit: %v", err)
	}
	second, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("second WorkspaceInit: %v", err)
	}

	if first != second {
		t.Errorf("workspace not stable: first=%q second=%q (timestamp suffix not removed?)", first, second)
	}
	// F2: the directory name is now the canonical identity slug
	// ("<readable>-<hash8>"), not the bare sanitized hostname. The fixture is
	// derived from CanonicalTargetID rather than hardcoded so the assertion
	// keeps testing STABILITY, which is what checkpoints.db resume depends on.
	id, err := output.CanonicalTargetID("example.com")
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	want := filepath.Join(root, id.Slug)
	if first != want {
		t.Errorf("workspace path = %q, want %q (no timestamp suffix)", first, want)
	}
	if !strings.HasPrefix(filepath.Base(first), "example.com-") {
		t.Errorf("workspace name %q lost its readable component", filepath.Base(first))
	}
}

// TestWorkspaceInitSubdirs: the five standard subdirs exist after the call and a
// second call does not error (idempotent MkdirAll).
func TestWorkspaceInitSubdirs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		info, statErr := os.Stat(filepath.Join(ws, sub))
		if statErr != nil {
			t.Errorf("subdir %q missing: %v", sub, statErr)
			continue
		}
		if !info.IsDir() {
			t.Errorf("subdir %q is not a directory", sub)
		}
	}
	// Idempotent: second call must not error.
	if _, err := output.WorkspaceInit(root, "example.com"); err != nil {
		t.Errorf("second WorkspaceInit errored (not idempotent): %v", err)
	}
}

// TestWorkspaceInitPersistsFiles: a file written into the workspace after the
// first call is STILL present after the second call. This proves the dir is not
// recreated fresh — the exact property that lets checkpoints.db persist so the
// scheduler resumes across runs (INTEG-03).
func TestWorkspaceInitPersistsFiles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws1, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("first WorkspaceInit: %v", err)
	}
	// Simulate the checkpoints.db (or any run artefact) landing in the workspace.
	marker := filepath.Join(ws1, "checkpoints.db")
	if err := os.WriteFile(marker, []byte("run-1-state"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	ws2, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("second WorkspaceInit: %v", err)
	}
	if ws1 != ws2 {
		t.Fatalf("second run used a different workspace: %q vs %q", ws1, ws2)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("marker did not survive the second WorkspaceInit: %v", err)
	}
	if string(data) != "run-1-state" {
		t.Errorf("marker content changed across runs: got %q", string(data))
	}
}

// TestWorkspaceInitSanitizes: scheme is stripped, path dropped, and the host is
// lowercased — the URL form and the bare hostname must address the SAME
// workspace. Asserted against the plain-hostname workspace rather than a
// hardcoded name, because the directory is now the canonical identity slug
// (F2) and the property under test is the fold, not the spelling.
func TestWorkspaceInitSanitizes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "https://Example.COM/some/path")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	plain, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit(example.com): %v", err)
	}
	if ws != plain {
		t.Errorf("sanitized workspace = %q, want %q (scheme strip + path drop + lowercase)", ws, plain)
	}
}

// TestWorkspaceInitDistinctPrefixes is ACCEPTANCE GATE 2 asserted at the
// workspace layer: /24, /16 and the bare IP must be three directories.
func TestWorkspaceInitDistinctPrefixes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	seen := make(map[string]string, 3)
	for _, tgt := range []string{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0"} {
		ws, err := output.WorkspaceInit(root, tgt)
		if err != nil {
			t.Fatalf("WorkspaceInit(%q): %v", tgt, err)
		}
		if prev, dup := seen[ws]; dup {
			t.Errorf("workspace collision: %q and %q both use %q", prev, tgt, ws)
		}
		seen[ws] = tgt
	}
	if len(seen) != 3 {
		t.Fatalf("gate 2 FAILED: got %d workspaces for 3 targets: %v", len(seen), seen)
	}
}

// TestWorkspaceInitValidation: empty rootDir, empty target, and sanitize-to-empty
// targets are all rejected (existing validation preserved).
func TestWorkspaceInitValidation(t *testing.T) {
	t.Parallel()

	if _, err := output.WorkspaceInit("", "example.com"); err == nil {
		t.Error("empty rootDir did not error")
	}
	if _, err := output.WorkspaceInit(t.TempDir(), "   "); err == nil {
		t.Error("empty target did not error")
	}
	if _, err := output.WorkspaceInit(t.TempDir(), "///"); err == nil {
		t.Error("sanitize-to-empty target did not error")
	}
}

// ---------------------------------------------------------------------------
// Legacy-workspace adoption (the migration this plan owns).
//
// NOTE ON t.Parallel(): the adoption tests below deliberately do NOT call
// t.Parallel(). The barriered concurrency test in init_internal_test.go swaps a
// package-level test hook, and `go test` resumes parallel tests only after
// every sequential test has finished — keeping these sequential is what stops
// them from tripping that hook.
// ---------------------------------------------------------------------------

// seedLegacyWorkspace materialises a populated pre-upgrade workspace: the four
// things an operator would lose if adoption silently did nothing.
func seedLegacyWorkspace(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	for _, sub := range []string{"inputs", "artefacts", "_compat"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatalf("seed mkdir %s: %v", sub, err)
		}
	}
	files := map[string]string{
		"checkpoints.db":                 "run-1-checkpoints",
		"inputs/x.jsonl":                 `{"staged":true}`,
		"artefacts/findings.jsonl":       `{"finding":"critical"}`,
		"_compat/subdomains_dnsregs.txt": "x.example.com",
	}
	for rel, content := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("seed write %s: %v", rel, err)
		}
	}
	return dir
}

// dirFingerprint is a stable content checksum of every regular file under dir.
// Used to prove a declined adoption left the legacy tree byte-identical.
func dirFingerprint(t *testing.T, dir string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		if d.IsDir() {
			_, _ = fmt.Fprintf(h, "D:%s\n", rel) // hash.Hash.Write never errors
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // test fixture
		if readErr != nil {
			return readErr
		}
		_, _ = fmt.Fprintf(h, "F:%s:%x\n", rel, sha256.Sum256(data)) // hash.Hash.Write never errors
		return nil
	})
	if err != nil {
		t.Fatalf("fingerprint %s: %v", dir, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func readMarker(t *testing.T, workspace string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workspace, output.IdentityMarkerName))
	if err != nil {
		t.Fatalf("read identity marker: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("parse identity marker: %v", err)
	}
	return m
}

// TestWorkspaceInitAdoptsUnambiguousLegacy: the happy migration path. A
// pre-upgrade domain workspace is RENAMED onto the new slug, carrying its
// checkpoints, staging, artefacts and _compat/ tree with it.
func TestWorkspaceInitAdoptsUnambiguousLegacy(t *testing.T) {
	root := t.TempDir()
	legacy := seedLegacyWorkspace(t, root, "example.com")

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}

	id, err := output.CanonicalTargetID("example.com")
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	if want := filepath.Join(root, id.Slug); ws != want {
		t.Errorf("workspace = %q, want the new identity slug %q", ws, want)
	}
	for _, rel := range []string{
		"checkpoints.db", "inputs/x.jsonl",
		"artefacts/findings.jsonl", "_compat/subdomains_dnsregs.txt",
	} {
		if _, statErr := os.Stat(filepath.Join(ws, filepath.FromSlash(rel))); statErr != nil {
			t.Errorf("adopted workspace lost %s: %v", rel, statErr)
		}
	}
	if _, statErr := os.Stat(legacy); !os.IsNotExist(statErr) {
		t.Errorf("legacy directory %q still exists after adoption (stat err = %v)", legacy, statErr)
	}
	if got := readMarker(t, ws)["adopted_from"]; got != "example.com" {
		t.Errorf("adopted_from = %v, want %q", got, "example.com")
	}
}

// TestWorkspaceInitRefusesAmbiguousLegacyOnUpgrade is THE UPGRADE-PATH REFUSAL
// and the single most important assertion in this plan.
//
// A pre-upgrade <root>/10.0.0.0 carries NO identity marker — the marker is
// introduced by this change — and LegacyTargetSlug collapses /24, /16 and the
// bare IP onto that one name. Adopting it would import up to three engagements
// under whichever target happens to run first, re-materialising F2 through the
// fix for F2.
func TestWorkspaceInitRefusesAmbiguousLegacyOnUpgrade(t *testing.T) {
	for _, target := range []string{"10.0.0.0/24", "10.0.0.0"} {
		t.Run(target, func(t *testing.T) {
			root := t.TempDir()
			legacy := seedLegacyWorkspace(t, root, "10.0.0.0")
			if _, statErr := os.Stat(filepath.Join(legacy, output.IdentityMarkerName)); !os.IsNotExist(statErr) {
				t.Fatalf("fixture invalid: legacy workspace must have NO identity marker")
			}
			before := dirFingerprint(t, legacy)

			ws, err := output.WorkspaceInit(root, target)
			if err != nil {
				t.Fatalf("WorkspaceInit(%q): %v", target, err)
			}

			if ws == legacy {
				t.Fatalf("WorkspaceInit(%q) returned the legacy directory", target)
			}
			if after := dirFingerprint(t, legacy); after != before {
				t.Errorf("legacy workspace was modified: %s -> %s", before, after)
			}
			// The fresh workspace must contain NONE of the legacy engagement.
			for _, rel := range []string{
				"checkpoints.db", "inputs/x.jsonl",
				"artefacts/findings.jsonl", "_compat/subdomains_dnsregs.txt",
			} {
				if _, statErr := os.Stat(filepath.Join(ws, filepath.FromSlash(rel))); statErr == nil {
					t.Errorf("fresh workspace inherited %s from the ambiguous legacy directory", rel)
				}
			}
			if got := readMarker(t, ws)["adopted_from"]; got != "" {
				t.Errorf("adopted_from = %v, want empty (nothing was adopted)", got)
			}
		})
	}
}

// TestWorkspaceInitRefusesAdoptionWhenNewSlugExists: never merge two trees.
func TestWorkspaceInitRefusesAdoptionWhenNewSlugExists(t *testing.T) {
	root := t.TempDir()
	legacy := seedLegacyWorkspace(t, root, "example.com")

	id, err := output.CanonicalTargetID("example.com")
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	newPath := filepath.Join(root, id.Slug)
	if mkErr := os.MkdirAll(filepath.Join(newPath, "artefacts"), 0o755); mkErr != nil {
		t.Fatalf("pre-create new workspace: %v", mkErr)
	}
	before := dirFingerprint(t, legacy)

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	if ws != newPath {
		t.Errorf("workspace = %q, want %q", ws, newPath)
	}
	if _, statErr := os.Stat(legacy); statErr != nil {
		t.Errorf("legacy directory was consumed despite the new workspace existing: %v", statErr)
	}
	if after := dirFingerprint(t, legacy); after != before {
		t.Errorf("legacy workspace was modified: %s -> %s", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "checkpoints.db")); statErr == nil {
		t.Error("new workspace absorbed the legacy checkpoints.db (trees were merged)")
	}
}

// TestWorkspaceInitRefusesAdoptionOnMarkerMismatch: a legacy directory already
// claimed by a DIFFERENT canonical identity is left alone.
func TestWorkspaceInitRefusesAdoptionOnMarkerMismatch(t *testing.T) {
	root := t.TempDir()
	legacy := seedLegacyWorkspace(t, root, "10.0.0.0")

	claim := `{"raw":"10.0.0.0/24","canonical":"10.0.0.0/24","kind":"cidr","slug":"10.0.0.0_24-deadbeef","adopted_from":""}`
	if err := os.WriteFile(filepath.Join(legacy, output.IdentityMarkerName), []byte(claim), 0o644); err != nil {
		t.Fatalf("write claim marker: %v", err)
	}
	before := dirFingerprint(t, legacy)

	ws, err := output.WorkspaceInit(root, "10.0.0.0/16")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	if ws == legacy {
		t.Fatal("adopted a workspace claimed by a different identity")
	}
	if after := dirFingerprint(t, legacy); after != before {
		t.Errorf("legacy workspace was modified: %s -> %s", before, after)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "checkpoints.db")); statErr == nil {
		t.Error("fresh /16 workspace inherited the /24 engagement's checkpoints.db")
	}
}

// TestWorkspaceInitAdoptsOnMarkerMatch: the marker branch also has a positive
// case — a directory this identity already claimed is adopted after a rename.
func TestWorkspaceInitAdoptsOnMarkerMatch(t *testing.T) {
	root := t.TempDir()
	legacy := seedLegacyWorkspace(t, root, "10.0.0.0")

	claim := `{"raw":"10.0.0.0/24","canonical":"10.0.0.0/24","kind":"cidr","slug":"stale","adopted_from":""}`
	if err := os.WriteFile(filepath.Join(legacy, output.IdentityMarkerName), []byte(claim), 0o644); err != nil {
		t.Fatalf("write claim marker: %v", err)
	}

	ws, err := output.WorkspaceInit(root, "10.0.0.0/24")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(ws, "checkpoints.db")); statErr != nil {
		t.Errorf("matching-marker adoption lost checkpoints.db: %v", statErr)
	}
	if _, statErr := os.Stat(legacy); !os.IsNotExist(statErr) {
		t.Errorf("legacy directory still present after a matching-marker adoption")
	}
}

// TestWorkspaceInitFreshInstallIsANoOp: with no legacy directory, adoption does
// nothing and the data dir holds exactly one workspace.
func TestWorkspaceInitFreshInstallIsANoOp(t *testing.T) {
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) != 1 || filepath.Join(root, dirs[0]) != ws {
		t.Errorf("expected exactly one workspace directory, got %v (ws=%q)", dirs, ws)
	}
	if got := readMarker(t, ws)["adopted_from"]; got != "" {
		t.Errorf("adopted_from = %v, want empty on a fresh install", got)
	}
}

// TestWorkspaceInitWritesIdentityMarker: every call leaves an auditable marker
// matching CanonicalTargetID for the same input.
func TestWorkspaceInitWritesIdentityMarker(t *testing.T) {
	root := t.TempDir()

	for _, target := range []string{"example.com", "10.0.0.0/24", "2001:db8::1"} {
		ws, err := output.WorkspaceInit(root, target)
		if err != nil {
			t.Fatalf("WorkspaceInit(%q): %v", target, err)
		}
		id, err := output.CanonicalTargetID(target)
		if err != nil {
			t.Fatalf("CanonicalTargetID(%q): %v", target, err)
		}
		m := readMarker(t, ws)
		if m["canonical"] != id.Canonical {
			t.Errorf("%q marker canonical = %v, want %q", target, m["canonical"], id.Canonical)
		}
		if m["slug"] != id.Slug {
			t.Errorf("%q marker slug = %v, want %q", target, m["slug"], id.Slug)
		}
		if m["kind"] != id.Kind {
			t.Errorf("%q marker kind = %v, want %q", target, m["kind"], id.Kind)
		}
		if m["raw"] != target {
			t.Errorf("%q marker raw = %v, want the input verbatim", target, m["raw"])
		}
	}
}

// TestWorkspaceInitMarkerWriteIsFatal: a swallowed marker-write failure would
// disarm the adoption safety check for every later run, so it must abort.
func TestWorkspaceInitMarkerWriteIsFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := t.TempDir()

	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("first WorkspaceInit: %v", err)
	}
	if chErr := os.Chmod(ws, 0o500); chErr != nil {
		t.Fatalf("chmod workspace: %v", chErr)
	}
	t.Cleanup(func() { _ = os.Chmod(ws, 0o755) })

	_, err = output.WorkspaceInit(root, "example.com")
	if err == nil {
		t.Fatal("WorkspaceInit succeeded with an unwritable workspace; the marker write was swallowed")
	}
	if !strings.Contains(err.Error(), "identity marker") {
		t.Errorf("error %q does not identify the marker write", err)
	}
}

// TestWorkspaceInitRenameFailureIsFatal: a half-adopted state must be loud. A
// non-ENOENT rename failure surfaces instead of being swallowed.
func TestWorkspaceInitRenameFailureIsFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits are not enforced")
	}
	root := t.TempDir()
	seedLegacyWorkspace(t, root, "example.com")

	if err := os.Chmod(root, 0o500); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

	_, err := output.WorkspaceInit(root, "example.com")
	if err == nil {
		t.Fatal("WorkspaceInit succeeded despite an unrenameable legacy workspace")
	}
	if !strings.Contains(err.Error(), "adopt legacy workspace") {
		t.Errorf("error %q does not identify the failed adoption", err)
	}
}
