// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 4 (AtomicSymlink)
// + .planning/phases/14-cutover-and-migration/14-02-PLAN.md (real WriteCompat).
// The AtomicSymlink tests exercise the ADR §4.1 primitive; the WriteCompat tests
// exercise the D-04 content-transform writer (JSONL artefact → bash .txt).
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

// --- WriteCompat real-extraction tests (D-04 / CUT-08) ------------------------

// writeArtefact writes JSONL lines (each a JSON object string) to path, creating
// parent dirs. Mirrors how a v2 task's OutputTree.Append lands artefacts/*.jsonl.
func writeArtefact(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// linesOf returns the set of non-empty lines in a compat .txt file.
func linesOf(t *testing.T, path string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if ln != "" {
			out[ln] = true
		}
	}
	return out
}

// assertHasLines asserts each want string is present as a whole line in path.
func assertHasLines(t *testing.T, path string, want ...string) {
	t.Helper()
	got := linesOf(t, path)
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s missing line %q (have: %v)", filepath.Base(path), w, got)
		}
	}
}

// Test 4: WriteCompat extracts sorted-unique .subdomain into BOTH subdomains.txt
// (the 116-ref v1 name) and all.txt — exact byte content, duplicate collapsed.
// This is the real-extraction proof (not the old skeleton dir-existence check).
func TestCompatWriteExtractsSortedUniqueSubdomains(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeArtefact(t, filepath.Join(root, "artefacts", "subdomains.jsonl"),
		`{"subdomain":"b.example.com","source":"subfinder"}`,
		`{"subdomain":"a.example.com","source":"crtsh"}`,
		`{"subdomain":"a.example.com","source":"subfinder"}`, // duplicate → collapsed
		`{"subdomain":"c.example.com","source":"passive"}`,
	)
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(&output.OutputTree{Root: root}); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	const want = "a.example.com\nb.example.com\nc.example.com\n"
	for _, name := range []string{"subdomains.txt", "all.txt"} {
		p := filepath.Join(root, "_compat", "subdomains", name)
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s bytes = %q; want %q (sorted-unique, dup removed)", name, string(got), want)
		}
	}
}

// Test 5: hosts.jsonl feeds three distinct v1 files by different fields:
// subdomains_alive.txt(.host), ips.txt(.ip), webs_all.txt/webs.txt(.url).
func TestCompatWriteExtractsHostsFields(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeArtefact(t, filepath.Join(root, "artefacts", "hosts.jsonl"),
		`{"host":"a.example.com","ip":"1.1.1.1","url":"https://a.example.com","scheme":"https"}`,
		`{"host":"b.example.com","ip":"2.2.2.2","url":"http://b.example.com","scheme":"http"}`,
	)
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(&output.OutputTree{Root: root}); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	assertHasLines(t, filepath.Join(root, "_compat", "subdomains", "subdomains_alive.txt"),
		"a.example.com", "b.example.com")
	assertHasLines(t, filepath.Join(root, "_compat", "hosts", "ips.txt"),
		"1.1.1.1", "2.2.2.2")
	assertHasLines(t, filepath.Join(root, "_compat", "webs", "webs_all.txt"),
		"https://a.example.com", "http://b.example.com")
	assertHasLines(t, filepath.Join(root, "_compat", "webs", "webs.txt"),
		"https://a.example.com", "http://b.example.com")
}

// Test 6: urls.jsonl → url_extract.txt; findings.jsonl → a formatted summary
// line "<severity> <host> <rule_id>".
func TestCompatWriteExtractsURLsAndFindings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeArtefact(t, filepath.Join(root, "artefacts", "urls.jsonl"),
		`{"url":"https://a.example.com/login","status":200}`,
		`{"url":"https://a.example.com/admin","status":403}`,
	)
	writeArtefact(t, filepath.Join(root, "artefacts", "findings.jsonl"),
		`{"rule_id":"nuclei:cve-2023-1234","severity":"high","host":"a.example.com","tool":"nuclei"}`,
	)
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(&output.OutputTree{Root: root}); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	assertHasLines(t, filepath.Join(root, "_compat", "webs", "url_extract.txt"),
		"https://a.example.com/login", "https://a.example.com/admin")
	assertHasLines(t, filepath.Join(root, "_compat", "vulns", "findings.txt"),
		"high a.example.com nuclei:cve-2023-1234")
}

// Test 7: error isolation (ADR §4.4) — missing/partial artefacts never crash the
// writer; it returns nil, writes the .txt for present sources, and skips absent
// sources without a stub.
func TestCompatWriteMissingArtefactsNoCrash(t *testing.T) {
	t.Parallel()

	// (a) Workspace with NO artefacts/ dir at all → nil, no panic.
	root := t.TempDir()
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(&output.OutputTree{Root: root}); err != nil {
		t.Fatalf("WriteCompat (no artefacts) = %v; want nil (error isolation)", err)
	}

	// (b) Partial: only subdomains present; hosts/urls/findings absent.
	root2 := t.TempDir()
	writeArtefact(t, filepath.Join(root2, "artefacts", "subdomains.jsonl"),
		`{"subdomain":"only.example.com"}`)
	cw2 := &output.CompatWriter{WorkspaceRoot: root2}
	if err := cw2.WriteCompat(&output.OutputTree{Root: root2}); err != nil {
		t.Fatalf("WriteCompat (partial) = %v; want nil", err)
	}
	if _, err := os.Stat(filepath.Join(root2, "_compat", "subdomains", "subdomains.txt")); err != nil {
		t.Errorf("present artefact did not yield subdomains.txt: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root2, "_compat", "vulns", "findings.txt")); !os.IsNotExist(err) {
		t.Errorf("missing findings.jsonl must skip findings.txt; stat err = %v (want not-exist)", err)
	}
}

// Test 8: idempotency — two consecutive WriteCompat calls produce byte-identical
// .txt output (deterministic sort + atomic write).
func TestCompatWriteIdempotent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeArtefact(t, filepath.Join(root, "artefacts", "subdomains.jsonl"),
		`{"subdomain":"b.example.com"}`,
		`{"subdomain":"a.example.com"}`,
		`{"subdomain":"a.example.com"}`,
	)
	writeArtefact(t, filepath.Join(root, "artefacts", "hosts.jsonl"),
		`{"host":"a.example.com","ip":"1.1.1.1","url":"https://a.example.com"}`)

	tree := &output.OutputTree{Root: root}
	cw := &output.CompatWriter{WorkspaceRoot: root}

	if err := cw.WriteCompat(tree); err != nil {
		t.Fatalf("first WriteCompat: %v", err)
	}
	first := readCompatTxt(t, root)
	if err := cw.WriteCompat(tree); err != nil {
		t.Fatalf("second WriteCompat: %v", err)
	}
	second := readCompatTxt(t, root)

	if len(first) == 0 {
		t.Fatal("no compat .txt produced")
	}
	for name, b1 := range first {
		b2, ok := second[name]
		if !ok {
			t.Errorf("%s present after first run, absent after second", name)
			continue
		}
		if string(b1) != string(b2) {
			t.Errorf("idempotency broken for %s: first=%q second=%q", name, string(b1), string(b2))
		}
	}
}

// readCompatTxt reads the known compat .txt files that exist under root.
func readCompatTxt(t *testing.T, root string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, rel := range []string{
		"_compat/subdomains/subdomains.txt",
		"_compat/subdomains/all.txt",
		"_compat/subdomains/subdomains_alive.txt",
		"_compat/webs/webs.txt",
		"_compat/webs/webs_all.txt",
		"_compat/hosts/ips.txt",
	} {
		if b, err := os.ReadFile(filepath.Join(root, rel)); err == nil {
			out[rel] = b
		}
	}
	return out
}

// Test 9: same-format directory pass-throughs are symlinks (not transforms) and
// resolve to the raw/ tool-output dirs via AtomicSymlink.
func TestCompatDirSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	nuclei := filepath.Join(root, "raw", "nuclei")
	shots := filepath.Join(root, "raw", "screenshots")
	if err := os.MkdirAll(nuclei, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(shots, 0o755); err != nil {
		t.Fatal(err)
	}
	cw := &output.CompatWriter{WorkspaceRoot: root}
	if err := cw.WriteCompat(&output.OutputTree{Root: root}); err != nil {
		t.Fatalf("WriteCompat: %v", err)
	}
	for link, target := range map[string]string{
		"_compat/nuclei_output": nuclei,
		"_compat/screenshots":   shots,
	} {
		lp := filepath.Join(root, link)
		fi, err := os.Lstat(lp)
		if err != nil {
			t.Errorf("lstat %s: %v", link, err)
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("%s is not a symlink (mode %v)", link, fi.Mode())
			continue
		}
		got, err := os.Readlink(lp)
		if err != nil {
			t.Errorf("readlink %s: %v", link, err)
			continue
		}
		if got != target {
			t.Errorf("%s -> %q; want %q", link, got, target)
		}
	}
}

// Test 10: V1ToV2Mapping covers the D-04 high-value subset (>= 7 entries) and
// every value is an artefacts/*.jsonl source path.
func TestCompatV1ToV2MappingSubset(t *testing.T) {
	t.Parallel()
	required := []string{
		"_compat/subdomains/subdomains.txt",
		"_compat/subdomains/all.txt",
		"_compat/subdomains/subdomains_alive.txt",
		"_compat/webs/webs.txt",
		"_compat/webs/webs_all.txt",
		"_compat/hosts/ips.txt",
		"_compat/webs/url_extract.txt",
		"_compat/vulns/findings.txt",
	}
	for _, key := range required {
		art, ok := output.V1ToV2Mapping[key]
		if !ok {
			t.Errorf("V1ToV2Mapping missing %q", key)
			continue
		}
		if !strings.HasPrefix(art, "artefacts/") || !strings.HasSuffix(art, ".jsonl") {
			t.Errorf("mapping %q → %q: want artefacts/<x>.jsonl", key, art)
		}
	}
	if len(output.V1ToV2Mapping) < 7 {
		t.Errorf("V1ToV2Mapping has %d entries; want >= 7", len(output.V1ToV2Mapping))
	}
}
