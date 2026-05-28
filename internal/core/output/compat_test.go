// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 4
// Plus ADR §4 (Compat Symlink Layer — BINDING, lines 1366-1507).
// Phase 3 ships the skeleton; the real V1→V2 symlink farm lifecycle
// ties in at Phase 12 cutover.
package output_test

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

// Test 1: AtomicSymlink creates link → target.
func TestAtomicSymlinkBasic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "real-file")
	if err := os.WriteFile(target, []byte("ok"), 0o644); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	link := filepath.Join(dir, "alias")
	if err := output.AtomicSymlink(target, link); err != nil {
		t.Fatalf("AtomicSymlink: %v", err)
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != target {
		t.Fatalf("readlink = %q; want %q", got, target)
	}
}

// Test 2: Calling AtomicSymlink twice atomically overwrites the previous
// symlink.
func TestAtomicSymlinkOverwrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := filepath.Join(dir, "target-1")
	second := filepath.Join(dir, "target-2")
	if err := os.WriteFile(first, []byte("a"), 0o644); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	if err := os.WriteFile(second, []byte("b"), 0o644); err != nil {
		t.Fatalf("seed second: %v", err)
	}
	link := filepath.Join(dir, "alias")

	if err := output.AtomicSymlink(first, link); err != nil {
		t.Fatalf("first symlink: %v", err)
	}
	if err := output.AtomicSymlink(second, link); err != nil {
		t.Fatalf("second symlink: %v", err)
	}
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != second {
		t.Fatalf("readlink = %q; want %q after overwrite", got, second)
	}
}

// Test 3: AtomicSymlink puts the tempfile in the same dir as the link
// (same filesystem ⇒ atomic rename). Concurrent calls produce no stranded
// .symlink-tmp.* files.
func TestAtomicSymlinkConcurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("ok"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	link := filepath.Join(dir, "link")
	const N = 8
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = output.AtomicSymlink(target, link)
		}()
	}
	wg.Wait()
	// Final symlink resolves correctly.
	if got, err := os.Readlink(link); err != nil || got != target {
		t.Fatalf("readlink = %q err=%v; want %q nil", got, err, target)
	}
	// No leftover .symlink-tmp.* files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".symlink-tmp.") {
			t.Fatalf("leftover tempfile: %s", e.Name())
		}
	}
}

// Test 4: CompatWriter.WriteCompat is no-op-ish skeleton — creates the
// _compat/<sub> directories but does NOT generate symlinks. Phase 12
// fills this in.
func TestCompatWriterSkeletonCreatesCompatDirs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cw := &output.CompatWriter{WorkspaceRoot: dir}
	if err := cw.WriteCompat(nil); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	for _, sub := range []string{"subdomains", "webs", "vulns", "osint"} {
		path := filepath.Join(dir, "_compat", sub)
		stat, err := os.Stat(path)
		if err != nil {
			t.Errorf("subdir %s missing: %v", path, err)
			continue
		}
		if !stat.IsDir() {
			t.Errorf("subdir %s is not a directory", path)
		}
	}
}

// Test 5: Compat directory layout is workspace-rooted, not absolute.
func TestCompatWriterRootRespected(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(nil); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	// Only one _compat directory under root.
	matches, err := filepath.Glob(filepath.Join(root, "_compat"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 _compat dir; got %d", len(matches))
	}
}

// Test 6: V1ToV2Mapping seed table contains the 3+ representative
// entries per ADR §4.3.
func TestCompatV1ToV2MappingSeed(t *testing.T) {
	t.Parallel()
	required := []string{
		"_compat/subdomains/all.txt",
		"_compat/webs/webs.txt",
		"_compat/vulns/findings.txt",
	}
	for _, key := range required {
		if _, ok := output.V1ToV2Mapping[key]; !ok {
			t.Errorf("V1ToV2Mapping missing %q", key)
		}
	}
}

// Test 7: V1ToV2Mapping values reference real artefact paths (per ADR
// §3.1 artefacts/ subtree).
func TestCompatV1ToV2MappingArtefactPaths(t *testing.T) {
	t.Parallel()
	for compat, art := range output.V1ToV2Mapping {
		if !strings.HasPrefix(art, "artefacts/") {
			t.Errorf("mapping %q → %q: target should be artefacts/<x>.jsonl", compat, art)
		}
		if !strings.HasSuffix(art, ".jsonl") {
			t.Errorf("mapping %q → %q: target should be JSONL", compat, art)
		}
	}
}
