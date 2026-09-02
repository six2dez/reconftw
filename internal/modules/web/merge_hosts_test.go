// merge_hosts_test.go — regression guard for the 13-08 hosts-merge union fix.
//
// web.httpx writes artefacts/hosts.jsonl DIRECTLY via app.Tree.Append (REPLACE
// semantics). The portscan/nerva/wellknown producers stage host records to
// inputs/hosts.*.jsonl, which plan 13-08 consolidates via MergeStage(_, _,
// "hosts"). Without union-preservation, that merge would OVERWRITE httpx's probed
// hosts. These tests assert the merge UNIONS the existing artefact with the
// staging files instead of replacing it.
package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// newHostsMergeApp builds an AppContext with a real OutputTree rooted at a
// per-test WorkDir (nil scope → Append performs field-presence checks but skips
// the in-scope filter, keeping the fixture minimal).
func newHostsMergeApp(t *testing.T) *appctx.AppContext {
	t.Helper()
	workdir := t.TempDir()
	for _, sub := range []string{"artefacts", "inputs"} {
		if err := os.MkdirAll(filepath.Join(workdir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	tree, err := output.NewTree(workdir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workdir},
	}
}

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readArtefactHosts(t *testing.T, app *appctx.AppContext) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"))
	if err != nil {
		t.Fatalf("read hosts.jsonl: %v", err)
	}
	return string(b)
}

// TestMergeStageHostsPreservesExistingArtefact is the core anti-regression guard:
// an httpx-written artefacts/hosts.jsonl MUST survive a hosts merge that folds in
// portscan/nerva staging records.
func TestMergeStageHostsPreservesExistingArtefact(t *testing.T) {
	app := newHostsMergeApp(t)

	// httpx wrote two probed hosts directly to the artefact.
	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"),
		`{"host":"probe1.example.com","source":"httpx"}`,
		`{"host":"probe2.example.com","source":"httpx"}`)

	// portscan + nerva staged their own host records.
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"scan1.example.com","source":"portscan"}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.nerva.jsonl"),
		`{"host":"scan2.example.com","source":"nerva"}`)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}

	got := readArtefactHosts(t, app)
	for _, want := range []string{"probe1.example.com", "probe2.example.com", "scan1.example.com", "scan2.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("hosts.jsonl missing %q after merge (httpx hosts wiped by REPLACE?)\ngot:\n%s", want, got)
		}
	}
}

// TestMergeStageHostsIdempotent verifies repeated hosts merges (portscan stage +
// web-producers stage both call MergeStage("hosts")) do not duplicate records.
func TestMergeStageHostsIdempotent(t *testing.T) {
	app := newHostsMergeApp(t)

	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"),
		`{"host":"probe.example.com","source":"httpx"}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"scan.example.com","source":"portscan"}`)

	for i := 0; i < 3; i++ {
		if err := MergeStage(context.Background(), app, "hosts"); err != nil {
			t.Fatalf("MergeStage(hosts) call %d: %v", i, err)
		}
	}

	got := readArtefactHosts(t, app)
	if n := strings.Count(got, "probe.example.com"); n != 1 {
		t.Errorf("probe.example.com appears %d times after 3 merges, want 1\ngot:\n%s", n, got)
	}
	if n := strings.Count(got, "scan.example.com"); n != 1 {
		t.Errorf("scan.example.com appears %d times after 3 merges, want 1\ngot:\n%s", n, got)
	}
}

// TestMergeStageHostsNoStagingIsNoOp verifies that when no inputs/hosts.*.jsonl
// staging files exist, the merge is a no-op and never touches the httpx artefact.
func TestMergeStageHostsNoStagingIsNoOp(t *testing.T) {
	app := newHostsMergeApp(t)

	original := `{"host":"probe.example.com","source":"httpx"}`
	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"), original)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}

	got := readArtefactHosts(t, app)
	if !strings.Contains(got, "probe.example.com") {
		t.Errorf("no-staging merge wiped the httpx artefact\ngot:\n%s", got)
	}
}

// TestMergeStageHostsDedupsSameHostDifferentShape guards IN-13-03: the hosts merge
// keys by decoded host identity, so an httpx artefact record and a portscan staging
// record for the SAME host but a DIFFERENT JSON shape collapse to a single artefact
// line — a line-counting consumer must see one host, not two. Under the old raw-byte
// dedup both byte-distinct shapes survived and the host was double-counted.
func TestMergeStageHostsDedupsSameHostDifferentShape(t *testing.T) {
	app := newHostsMergeApp(t)

	// httpx wrote a rich record for host "a"; portscan staged a DIFFERENT-shape
	// record for the SAME host, plus a genuinely new host "b".
	writeLines(t, filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl"),
		`{"host":"a.example.com","tech":["nginx"],"source":"httpx"}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"a.example.com","ip":"192.0.2.1","port":"80"}`,
		`{"host":"b.example.com","ip":"192.0.2.2","port":"443"}`)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}

	got := readArtefactHosts(t, app)

	// Same host "a" must appear exactly once (httpx's first-seen record wins).
	if n := strings.Count(got, "a.example.com"); n != 1 {
		t.Errorf("a.example.com appears %d times, want 1 (same-host different-shape not deduped)\ngot:\n%s", n, got)
	}
	// The new host "b" is still admitted.
	if n := strings.Count(got, "b.example.com"); n != 1 {
		t.Errorf("b.example.com appears %d times, want 1\ngot:\n%s", n, got)
	}
	// The httpx record (seeded first) is the survivor for host "a"; the portscan
	// same-host shape is the one dropped.
	if !strings.Contains(got, `"tech":["nginx"]`) {
		t.Errorf("expected httpx record for host a to survive\ngot:\n%s", got)
	}
	if strings.Contains(got, `"port":"80"`) {
		t.Errorf("portscan same-host shape (port 80) should have been deduped away\ngot:\n%s", got)
	}
	// Exactly two lines total: one per host.
	lines := 0
	for _, ln := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.TrimSpace(ln) != "" {
			lines++
		}
	}
	if lines != 2 {
		t.Errorf("hosts.jsonl has %d lines, want 2 (one per host)\ngot:\n%s", lines, got)
	}
}

// TestMergeStageHostsKeepsCanonicalEndpoint pins the collapse WINNER, not just the
// count. artefacts/hosts.jsonl is web.nuclei's target list, so which of a host's
// endpoints survives decides what actually gets scanned.
//
// Observed on the live parity run: once the uncommon-port sweep landed, httpx
// returned several endpoints per host and first-seen order kept an arbitrary one.
// The artefact recorded http://api.example.com:2095 instead of the https :443
// endpoint, nuclei scanned a high port that does not serve the application, and
// finding classes fell 48 -> 38 — losing precisely the templates that match real
// application paths (graphql-*, oauth2-detect, oidc-detect, keycloak-openid-config,
// trust-center-detect). The host COUNT was perfect (12 of 12) throughout, which is
// why a cardinality-only assertion could never have caught this.
func TestMergeStageHostsKeepsCanonicalEndpoint(t *testing.T) {
	app := newHostsMergeApp(t)

	// One host, three real httpx endpoints, canonical one deliberately NOT first.
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.httpx.jsonl"),
		`{"host":"api.example.com","url":"http://api.example.com:2095","scheme":"http","port":"2095","status":400}`,
		`{"host":"api.example.com","url":"https://api.example.com:443","scheme":"https","port":"443","status":200}`,
		`{"host":"api.example.com","url":"http://api.example.com:80","scheme":"http","port":"80","status":301}`,
	)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}
	got := readArtefactHosts(t, app)

	// Count LINES, not substring hits: the host name also appears inside the URL
	// field of its own record, so a substring count reports 2 for a single line.
	hostLines := 0
	for _, ln := range strings.Split(strings.TrimSpace(got), "\n") {
		if strings.Contains(ln, `"host":"api.example.com"`) {
			hostLines++
		}
	}
	if hostLines != 1 {
		t.Fatalf("host appears on %d lines, want exactly 1 (IN-13-03)\ngot:\n%s", hostLines, got)
	}
	if !strings.Contains(got, `"port":"443"`) {
		t.Errorf("the https :443 endpoint did not survive the collapse — nuclei would be "+
			"pointed at a non-application port\ngot:\n%s", got)
	}
	if strings.Contains(got, `"port":"2095"`) {
		t.Errorf("an arbitrary high-port endpoint survived instead of the canonical one\ngot:\n%s", got)
	}
}

// TestMergeStageHostsProbeResultBeatsBareHost keeps the IN-13-03 guarantee explicit
// in the ranking's own terms: a rich httpx record outranks a bare portscan shape for
// the same host EVEN THOUGH the portscan record carries a standard port and the
// httpx one carries none. If the port preference ever outgrows the probe-result
// term, this fails.
func TestMergeStageHostsProbeResultBeatsBareHost(t *testing.T) {
	app := newHostsMergeApp(t)

	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.httpx.jsonl"),
		`{"host":"a.example.com","tech":["nginx"],"status":200}`)
	writeLines(t, filepath.Join(app.Target.WorkDir, "inputs", "hosts.portscan.jsonl"),
		`{"host":"a.example.com","ip":"192.0.2.1","port":"443"}`)

	if err := MergeStage(context.Background(), app, "hosts"); err != nil {
		t.Fatalf("MergeStage(hosts): %v", err)
	}
	got := readArtefactHosts(t, app)

	if !strings.Contains(got, `"tech":["nginx"]`) {
		t.Errorf("the httpx probe result lost to a bare portscan record carrying port 443\ngot:\n%s", got)
	}
}
