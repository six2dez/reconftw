// Source: .planning/phases/14-cutover-and-migration (CUT-08 compat-writer wiring).
//
// These tests prove the end-of-scan finalization WIRING — the seam every scan
// handler (composite, subs, web, vulns, osint) invokes (writeCompatTree) — turns a
// finalized workspace's artefacts/*.jsonl into the v1 bash-shape _compat/ tree.
// Driving writeCompatTree directly (rather than a full RunCompositeAsync boot,
// which would require a scheduler, backend, live tools, and DNS) exercises the
// identical production code path without network/tool execution.
package handlers

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
)

// seedArtefact writes JSONL lines (each a JSON object) to
// <root>/artefacts/<name>, creating parent dirs — mirrors how a v2 task's
// OutputTree.Append lands artefacts/*.jsonl during a real scan.
func seedArtefact(t *testing.T, root, name string, lines ...string) {
	t.Helper()
	path := filepath.Join(root, "artefacts", name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// compatLines returns the set of non-empty whole lines of a _compat/*.txt file.
func compatLines(t *testing.T, root, rel string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	out := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if ln != "" {
			out[ln] = true
		}
	}
	return out
}

// assertCompatHasLines fails if any want line is absent from root/rel.
func assertCompatHasLines(t *testing.T, root, rel string, want ...string) {
	t.Helper()
	got := compatLines(t, root, rel)
	for _, w := range want {
		if !got[w] {
			t.Errorf("%s missing line %q (have: %v)", rel, w, got)
		}
	}
}

// discardApp builds a minimal AppContext carrying only what writeCompatTree
// reads: a concrete *output.OutputTree (Root=root) and a silent logger.
func discardApp(root string) *appctx.AppContext {
	return &appctx.AppContext{
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tree: &output.OutputTree{Root: root},
	}
}

// Integration test: a finalized workspace (representative artefacts across all
// four producers) yields the full v1 bash-shape _compat/ tree with the right
// contents. This is the proof CUT-08 is no longer dormant — the wiring both
// composite and subs handlers now call produces a non-empty compat tree.
func TestWriteCompatTreeProducesBashShapeTree(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	// Representative end-of-scan artefacts (schemas mirror the real producers).
	seedArtefact(t, root, "subdomains.jsonl",
		`{"subdomain":"b.example.com","source":"subfinder"}`,
		`{"subdomain":"a.example.com","source":"crtsh"}`,
		`{"subdomain":"a.example.com","source":"passive"}`, // duplicate → collapsed
	)
	seedArtefact(t, root, "hosts.jsonl",
		`{"host":"a.example.com","ip":"1.1.1.1","url":"https://a.example.com","scheme":"https"}`,
		`{"host":"b.example.com","ip":"2.2.2.2","url":"http://b.example.com","scheme":"http"}`,
	)
	seedArtefact(t, root, "urls.jsonl",
		`{"url":"https://a.example.com/login","status":200}`,
		`{"url":"https://a.example.com/admin","status":403}`,
	)
	seedArtefact(t, root, "findings.jsonl",
		`{"rule_id":"nuclei:cve-2023-1234","severity":"high","host":"a.example.com","tool":"nuclei"}`,
	)

	// Drive the exact finalization seam the handlers call.
	writeCompatTree(discardApp(root), root, false)

	// subdomains → subdomains.txt + all.txt (sorted-unique, dup collapsed).
	const wantSubs = "a.example.com\nb.example.com\n"
	for _, name := range []string{"subdomains.txt", "all.txt"} {
		rel := filepath.Join("_compat", "subdomains", name)
		got, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if string(got) != wantSubs {
			t.Errorf("%s = %q; want %q", rel, string(got), wantSubs)
		}
	}

	// hosts.jsonl feeds alive-hosts, ips, and webs.
	assertCompatHasLines(t, root, filepath.Join("_compat", "subdomains", "subdomains_alive.txt"),
		"a.example.com", "b.example.com")
	assertCompatHasLines(t, root, filepath.Join("_compat", "hosts", "ips.txt"),
		"1.1.1.1", "2.2.2.2")
	assertCompatHasLines(t, root, filepath.Join("_compat", "webs", "webs_all.txt"),
		"https://a.example.com", "http://b.example.com")

	// urls.jsonl → url_extract.txt; findings.jsonl → formatted summary line.
	assertCompatHasLines(t, root, filepath.Join("_compat", "webs", "url_extract.txt"),
		"https://a.example.com/login", "https://a.example.com/admin")
	assertCompatHasLines(t, root, filepath.Join("_compat", "vulns", "findings.txt"),
		"high a.example.com nuclei:cve-2023-1234")
}

// Integration test: a subs-only style finalization (subdomains present; hosts/
// urls/findings absent) still yields the compat tree and NEVER crashes on the
// missing sources — the enrichment-only workspace a standalone `subs` scan
// leaves behind.
func TestWriteCompatTreeSubsOnlyMissingSourcesNoCrash(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedArtefact(t, root, "subdomains.jsonl",
		`{"subdomain":"only.example.com"}`)

	writeCompatTree(discardApp(root), root, false)

	// Present source is materialized.
	if _, err := os.Stat(filepath.Join(root, "_compat", "subdomains", "subdomains.txt")); err != nil {
		t.Errorf("present subdomains.jsonl did not yield subdomains.txt: %v", err)
	}
	// Missing source is skipped (no stub), not fatal.
	if _, err := os.Stat(filepath.Join(root, "_compat", "vulns", "findings.txt")); !os.IsNotExist(err) {
		t.Errorf("missing findings.jsonl must skip findings.txt; stat err = %v (want not-exist)", err)
	}
}

// Integration test: a workspace with NO artefacts/ at all must not crash the
// finalization (error isolation, ADR §4.4). writeCompatTree returns cleanly.
func TestWriteCompatTreeNoArtefactsNoCrash(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// No panic, no fatal — the scan's finalization survives an empty workspace.
	writeCompatTree(discardApp(root), root, false)
}

// Integration test: the WorkspaceRoot fallback. When app.Tree is not a concrete
// *output.OutputTree (nil here, as a future MockOutputTree would be), the wiring
// still produces the tree from the workspace root (boot.WorkDir), so the compat
// contract holds regardless of the tree implementation.
func TestWriteCompatTreeNilTreeUsesWorkspaceRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedArtefact(t, root, "subdomains.jsonl",
		`{"subdomain":"fallback.example.com"}`)

	app := &appctx.AppContext{
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tree: nil, // not a *output.OutputTree → WriteCompat uses WorkspaceRoot
	}
	writeCompatTree(app, root, false)

	assertCompatHasLines(t, root, filepath.Join("_compat", "subdomains", "subdomains.txt"),
		"fallback.example.com")
}

// ---- CUT-08: Recon/<domain> contract symlink wiring (MIGRATION §2.2) ----

// initEngagementWorkspace boots a workspace exactly as BootReconApp does
// (output.WorkspaceInit under <engagement>/workspaces) so the identity marker
// exists and the Recon/ link lands as a sibling of workspaces/.
func initEngagementWorkspace(t *testing.T, target string) (engagement, workdir string) {
	t.Helper()
	engagement = t.TempDir()
	workdir, err := output.WorkspaceInit(filepath.Join(engagement, "workspaces"), target)
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	return engagement, workdir
}

// With output.compat.recon_symlink = true (the default), finalization creates
// <engagement>/Recon/example.com → ../workspaces/<slug>/_compat, and a second
// call is idempotent.
func TestWriteCompatTreeCreatesReconSymlink(t *testing.T) {
	t.Parallel()
	engagement, workdir := initEngagementWorkspace(t, "example.com")
	seedArtefact(t, workdir, "subdomains.jsonl", `{"subdomain":"a.example.com"}`)

	writeCompatTree(discardApp(workdir), workdir, true)
	writeCompatTree(discardApp(workdir), workdir, true) // idempotent re-run

	link := filepath.Join(engagement, "Recon", "example.com")
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink(%s): %v", link, err)
	}
	want := filepath.Join("..", "workspaces", filepath.Base(workdir), "_compat")
	if got != want {
		t.Fatalf("symlink target = %q; want %q", got, want)
	}
	assertCompatHasLines(t, link, filepath.Join("subdomains", "subdomains.txt"), "a.example.com")
}

// With output.compat.recon_symlink = false, no Recon/ is created at all, while
// the _compat/ tree is still written.
func TestWriteCompatTreeReconSymlinkOptOut(t *testing.T) {
	t.Parallel()
	engagement, workdir := initEngagementWorkspace(t, "example.com")
	seedArtefact(t, workdir, "subdomains.jsonl", `{"subdomain":"a.example.com"}`)

	writeCompatTree(discardApp(workdir), workdir, false)

	if _, err := os.Lstat(filepath.Join(engagement, "Recon")); !os.IsNotExist(err) {
		t.Fatalf("opt-out must not create Recon/; Lstat err = %v", err)
	}
	assertCompatHasLines(t, workdir, filepath.Join("_compat", "subdomains", "subdomains.txt"), "a.example.com")
}

// Default config carries the symlink ON (MIGRATION §2.2: "default true").
func TestCompatReconSymlinkDefaultTrue(t *testing.T) {
	t.Parallel()
	if !config.Defaults().Output.Compat.ReconSymlink {
		t.Fatal("config.Defaults().Output.Compat.ReconSymlink = false; want true")
	}
}

// A workspace that was never WorkspaceInit'd (no identity marker) skips the
// symlink without failing: the compat tree is still written, nothing panics.
func TestWriteCompatTreeReconSymlinkSkipsWithoutMarker(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	seedArtefact(t, root, "subdomains.jsonl", `{"subdomain":"a.example.com"}`)

	writeCompatTree(discardApp(root), root, true)

	assertCompatHasLines(t, root, filepath.Join("_compat", "subdomains", "subdomains.txt"), "a.example.com")
	if _, err := os.Lstat(filepath.Join(filepath.Dir(filepath.Dir(root)), "Recon")); err == nil {
		t.Fatal("a marker-less workspace must not create a Recon/ link")
	}
}

// Wiring guard: every scan handler that finalizes a workspace — the composites
// AND the standalone subs/web/vulns/osint pipelines — calls writeCompatTree with
// the config knob, and does so BEFORE persistScanToStore (the finalization seam).
// A full RunWebAsync/RunVulnsAsync/RunOSINTAsync boot needs a scheduler, backend
// and live tools, so the call is asserted at the source seam itself; the
// behaviour of the call is proven by the tests above.
func TestEveryScanHandlerCallsCompatWriterBeforePersist(t *testing.T) {
	t.Parallel()
	const call = "writeCompatTree(app, workdir, cfg.Output.Compat.ReconSymlink)"
	for _, file := range []string{"composite.go", "subs.go", "web.go", "vulns.go", "osint.go"} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		s := string(src)
		ci := strings.Index(s, call)
		if ci < 0 {
			t.Errorf("%s: missing %q", file, call)
			continue
		}
		pi := strings.Index(s, "persistScanToStore(ctx, boot, opts,")
		if pi < 0 {
			t.Errorf("%s: missing persistScanToStore call", file)
			continue
		}
		if ci > pi {
			t.Errorf("%s: writeCompatTree must run before persistScanToStore (compat=%d persist=%d)", file, ci, pi)
		}
	}
}
