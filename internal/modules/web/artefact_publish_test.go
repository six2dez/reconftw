// artefact_publish_test.go — F3 (phase 15, plan 15-13 Task 3) for the FOUR
// artefacts that have a DIRECT writer: hosts, fuzz, origins and urls.
//
// WHY THESE FOUR NEED THEIR OWN TESTS. Plan 15-03 closed F3 at the MERGE layer,
// but it also had to bar the merge from truncating these four, because each is
// written directly by a producer outside the merge path
// (directArtefactWriterStages in merge.go). "fuzz" and "origins" have no staging
// producer at all, so without that guard the merge would zero the very artefact
// ffuf and hakoriginfinder had just written. The consequence is that the merge
// CANNOT be the one to empty them — their empty publish belongs to the
// authoritative direct writer, and that is what this file tests.
//
// EVERY ARTEFACT GETS A PAIR, and both halves are required:
//
//	emptied   the producer RAN and found nothing => artefact EXISTS with zero
//	          records. Without this the previous run's results are republished.
//	preserved the producer did NOT run (early skip/error) => the artefact
//	          survives byte-for-byte. Without this a skipped optional tool
//	          silently deletes a good artefact.
//
// A plan with only one half of the pair has certified the bug.
package web_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/task"
)

// artefactFile returns <workDir>/artefacts/<name>.jsonl.
func artefactFile(workDir, name string) string {
	return filepath.Join(workDir, "artefacts", name+".jsonl")
}

// assertArtefactEmptied asserts the artefact EXISTS and holds zero records.
// Absence is a failure, not a pass: downstream readers open the path.
func assertArtefactEmptied(t *testing.T, workDir, name string) {
	t.Helper()
	p := artefactFile(workDir, name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("%s.jsonl must EXIST and be empty, not be deleted: %v", name, err)
	}
	if n := countNonBlank(t, p); n != 0 {
		body, _ := os.ReadFile(p) //nolint:gosec // test-controlled temp path
		t.Errorf("the producer ran and found nothing, but %s.jsonl still holds %d records "+
			"— the previous run was republished (F3, gate 3): %q", name, n, string(body))
	}
}

// assertArtefactPreserved asserts the artefact still holds want, byte for byte.
func assertArtefactPreserved(t *testing.T, workDir, name, want string) {
	t.Helper()
	p := artefactFile(workDir, name)
	got, err := os.ReadFile(p) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("a producer that did NOT run must not delete %s.jsonl: %v", name, err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(want) {
		t.Errorf("a producer that did NOT run must leave %s.jsonl byte-for-byte intact\n"+
			" got: %q\nwant: %q", name, string(got), want)
	}
}

// ---------------------------------------------------------------------------
// fuzz — web.ffuf
// ---------------------------------------------------------------------------

// ffufApp builds a workspace with a wordlist and the given hosts, and a backend
// whose ffuf invocation writes resultsByHost[<host index>] to the -o target.
func ffufApp(t *testing.T, workDir string, hosts []string, resultsPerCall [][]string) *appctx.AppContext {
	t.Helper()
	wordlist := filepath.Join(workDir, "fuzz.txt")
	writeLinesFile(t, wordlist, "admin", "login")

	var hostLines []string
	for _, h := range hosts {
		hostLines = append(hostLines, `{"url":"`+h+`","host":"`+strings.TrimPrefix(
			strings.TrimPrefix(h, "https://"), "http://")+`"}`)
	}
	writeLinesFile(t, artefactFile(workDir, "hosts"), hostLines...)

	call := 0
	be := &webMockBackend{onInvoke: func(args []string) {
		var out string
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				out = args[i+1]
			}
		}
		idx := call
		call++
		if out == "" || idx >= len(resultsPerCall) || len(resultsPerCall[idx]) == 0 {
			return // ffuf writes no file when it finds nothing
		}
		var body strings.Builder
		body.WriteString(`{"results":[`)
		for i, u := range resultsPerCall[idx] {
			if i > 0 {
				body.WriteString(",")
			}
			body.WriteString(`{"url":"` + u + `","status":200,"length":10,"words":2,"lines":1}`)
		}
		body.WriteString(`]}`)
		writeLinesFile(t, out, body.String())
	}}

	app := newWebApp(t, workDir, be, "ffuf")
	app.Cfg.Web.Fuzz.Enabled = true
	app.Cfg.Paths.FuzzWordlist = wordlist
	return app
}

// TestFuzzArtefactEmptiedWhenProducerFindsNothing is gate 3 for "fuzz".
func TestFuzzArtefactEmptiedWhenProducerFindsNothing(t *testing.T) {
	workDir := t.TempDir()

	// Run A — ffuf finds one path.
	appA := ffufApp(t, workDir, []string{"https://api.example.com"},
		[][]string{{"https://api.example.com/admin"}})
	if _, err := lookupWebTask(t, "web.ffuf").Run(context.Background(), appA); err != nil {
		t.Fatalf("run A: %v", err)
	}
	if n := countNonBlank(t, artefactFile(workDir, "fuzz")); n != 1 {
		t.Fatalf("run A: fuzz.jsonl holds %d records, want 1", n)
	}

	// Run B — SAME workspace, ffuf finds nothing on the same host.
	appB := ffufApp(t, workDir, []string{"https://api.example.com"}, [][]string{nil})
	if _, err := lookupWebTask(t, "web.ffuf").Run(context.Background(), appB); err != nil {
		t.Fatalf("run B: %v", err)
	}
	assertArtefactEmptied(t, workDir, "fuzz")
}

// TestFuzzArtefactPreservedWhenProducerDidNotRun uses the cleanest early skip:
// no fuzz wordlist configured (ffuf.go's first StatusSkipped return).
func TestFuzzArtefactPreservedWhenProducerDidNotRun(t *testing.T) {
	workDir := t.TempDir()
	seed := `{"url":"https://api.example.com/admin","status":200,"length":10,"words":2,"lines":1}`
	writeLinesFile(t, artefactFile(workDir, "fuzz"), seed)
	writeLinesFile(t, artefactFile(workDir, "hosts"),
		`{"url":"https://api.example.com","host":"api.example.com"}`)

	app := newWebApp(t, workDir, &webMockBackend{}, "ffuf")
	app.Cfg.Web.Fuzz.Enabled = true
	app.Cfg.Paths.FuzzWordlist = "" // ffuf.go:"no fuzz wordlist configured — skipping"

	res, err := lookupWebTask(t, "web.ffuf").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %q, want skipped (no wordlist configured)", res.Status)
	}
	assertArtefactPreserved(t, workDir, "fuzz", seed)
}

// TestFuzzArtefactAccumulatesAcrossHosts is what proves the loop HOIST landed.
//
// Three hosts; host 1 and host 3 return results, host 2 returns none. Under the
// pre-hoist code the Append lived INSIDE the per-host loop and Tree.Append
// REPLACES, so the artefact ended up holding only the last host with results —
// this test failed with 1 record instead of 2. It is also why the empty publish
// had to be hoisted out: an in-loop empty publish for barren host 2 would have
// erased host 1.
func TestFuzzArtefactAccumulatesAcrossHosts(t *testing.T) {
	workDir := t.TempDir()
	app := ffufApp(t, workDir,
		[]string{"https://a.example.com", "https://b.example.com", "https://c.example.com"},
		[][]string{
			{"https://a.example.com/admin"},
			nil, // barren middle host
			{"https://c.example.com/login"},
		})
	if _, err := lookupWebTask(t, "web.ffuf").Run(context.Background(), app); err != nil {
		t.Fatalf("run: %v", err)
	}

	body, err := os.ReadFile(artefactFile(workDir, "fuzz")) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read fuzz.jsonl: %v", err)
	}
	if n := countNonBlank(t, artefactFile(workDir, "fuzz")); n != 2 {
		t.Fatalf("fuzz.jsonl holds %d records, want 2 (host 1 + host 3) — the publish is "+
			"still inside the per-host loop, so each host REPLACES the last: %q", n, string(body))
	}
	for _, want := range []string{"a.example.com/admin", "c.example.com/login"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("fuzz.jsonl is missing %s — cross-host accumulation is broken: %q",
				want, string(body))
		}
	}
}

// ---------------------------------------------------------------------------
// origins — web.hakoriginfinder
// ---------------------------------------------------------------------------

// TestOriginsArtefactEmptiedWhenProducerFindsNothing is gate 3 for "origins":
// the producer RAN over host/IP pairs, found no origin, and must empty the
// artefact rather than republish the previous run's origins. An origin IP that
// has since been fixed must stop being reported as exposed.
func TestOriginsArtefactEmptiedWhenProducerFindsNothing(t *testing.T) {
	workDir := t.TempDir()
	writeLinesFile(t, artefactFile(workDir, "origins"),
		`{"host":"api.example.com","origin_ip":"9.9.9.9","method":"hakoriginfinder","confidence":"low"}`)
	writeLinesFile(t, artefactFile(workDir, "hosts"),
		`{"host":"api.example.com","ip":"1.2.3.4"}`)

	app := newWebApp(t, workDir, &webMockBackend{}, "hakoriginfinder")
	res, err := lookupWebTask(t, "web.hakoriginfinder").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done — the stub is on PATH so the tool RAN", res.Status)
	}
	assertArtefactEmptied(t, workDir, "origins")
}

// TestOriginsArtefactPreservedWhenProducerDidNotRun is the did-not-run half,
// driven through the no-host/IP-pairs StatusSkipped return.
//
// The path is reached by having NO hosts.jsonl at all: a record carrying a host
// but no ip still produces a pair (readHostIPPairsFromJSONL keeps it with an
// empty ip), so the task would RUN and correctly empty-publish — which is the
// other test's case, not this one.
func TestOriginsArtefactPreservedWhenProducerDidNotRun(t *testing.T) {
	workDir := t.TempDir()
	seed := `{"host":"api.example.com","origin_ip":"9.9.9.9","method":"hakoriginfinder","confidence":"low"}`
	writeLinesFile(t, artefactFile(workDir, "origins"), seed)
	// No artefacts/hosts.jsonl: nothing was probed, so hakoriginfinder is never
	// invoked and must leave the previous run's origins alone.

	app := newWebApp(t, workDir, &webMockBackend{}, "hakoriginfinder")
	res, err := lookupWebTask(t, "web.hakoriginfinder").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %q, want skipped (no host/IP pairs)", res.Status)
	}
	assertArtefactPreserved(t, workDir, "origins", seed)
}

// ---------------------------------------------------------------------------
// urls — web.urldedup
// ---------------------------------------------------------------------------

func urldedupApp(t *testing.T, workDir string) *appctx.AppContext {
	t.Helper()
	app := newWebApp(t, workDir, &webMockBackend{})
	app.Cfg.Web.URLs.Enabled = true
	return app
}

// TestUrlsArtefactEmptiedOnAllThreeProducerPaths is gate 3 for "urls", asserted
// SEPARATELY on each of the three distinct states that all mean "urldedup ran
// and the corpus is empty". One combined assertion would let two of them rot.
func TestUrlsArtefactEmptiedOnAllThreeProducerPaths(t *testing.T) {
	seed := `{"url":"https://api.example.com/old","source":"katana","host":"api.example.com"}`

	t.Run("path1_empty_staging_glob", func(t *testing.T) {
		// Every URL producer ran and cleared its staging (Task 1's contract), so
		// inputs/urls.*.jsonl matches nothing.
		workDir := t.TempDir()
		writeLinesFile(t, artefactFile(workDir, "urls"), seed)
		if _, err := lookupWebTask(t, "web.urldedup").Run(
			context.Background(), urldedupApp(t, workDir)); err != nil {
			t.Fatalf("run: %v", err)
		}
		assertArtefactEmptied(t, workDir, "urls")
	})

	t.Run("path2_staging_holds_no_url_records", func(t *testing.T) {
		workDir := t.TempDir()
		writeLinesFile(t, artefactFile(workDir, "urls"), seed)
		// A staging file that exists but carries no url field.
		writeLinesFile(t, filepath.Join(workDir, "inputs", "urls.katana.jsonl"),
			`{"note":"no url field here"}`)
		if _, err := lookupWebTask(t, "web.urldedup").Run(
			context.Background(), urldedupApp(t, workDir)); err != nil {
			t.Fatalf("run: %v", err)
		}
		assertArtefactEmptied(t, workDir, "urls")
	})

	t.Run("path3_all_urls_dropped_by_scope_gate", func(t *testing.T) {
		workDir := t.TempDir()
		writeLinesFile(t, artefactFile(workDir, "urls"), seed)
		// Real URL records, but every host is out of scope for example.com.
		writeLinesFile(t, filepath.Join(workDir, "inputs", "urls.katana.jsonl"),
			`{"url":"https://evil.invalid/a","source":"katana","host":"evil.invalid"}`,
			`{"url":"https://other.invalid/b","source":"katana","host":"other.invalid"}`)
		if _, err := lookupWebTask(t, "web.urldedup").Run(
			context.Background(), urldedupApp(t, workDir)); err != nil {
			t.Fatalf("run: %v", err)
		}
		assertArtefactEmptied(t, workDir, "urls")
	})
}

// TestUrlsArtefactPreservedWhenProducerDidNotRun covers the did-not-run half.
// The empty-glob path is NOT usable for this: it now publishes empty BY DESIGN.
// A task never invoked is the honest model of a checkpoint skip.
func TestUrlsArtefactPreservedWhenProducerDidNotRun(t *testing.T) {
	workDir := t.TempDir()
	seed := `{"url":"https://api.example.com/keep","source":"katana","host":"api.example.com"}`
	writeLinesFile(t, artefactFile(workDir, "urls"), seed)

	app := urldedupApp(t, workDir)
	app.Cfg.Web.URLs.Enabled = false
	if lookupWebTask(t, "web.urldedup").Enabled(app.Cfg) {
		t.Fatal("web.urldedup must report Enabled()==false when cfg.Web.URLs.Enabled is false")
	}
	// Enabled()==false means task.FilterByModuleAndEnabled drops the task and Run
	// is never called. Model that literally by not invoking it: the artefact must
	// still be there for the next run.
	assertArtefactPreserved(t, workDir, "urls", seed)
}

// ---------------------------------------------------------------------------
// hosts — web.httpx (the empty-publish owner) and subdomains/geo.go (NOT).
// ---------------------------------------------------------------------------

// TestHostsArtefactEmptiedByHTTPXOverGeoRecords encodes the ordering decision:
// httpx owns the empty publish, and geo's records do not block it.
func TestHostsArtefactEmptiedByHTTPXOverGeoRecords(t *testing.T) {
	workDir := t.TempDir()
	// Seed the artefact with geo-shaped records, as subdomains.geo leaves them.
	writeLinesFile(t, artefactFile(workDir, "hosts"),
		`{"host":"api.example.com","ip":"1.2.3.4","asn":"AS64500","country":"US","city":"Denver"}`,
		`{"host":"mail.example.com","ip":"1.2.3.5","asn":"AS64500","country":"US","city":"Denver"}`)
	writeLinesFile(t, filepath.Join(workDir, "subdomains", "subdomains.txt"), "api.example.com")

	be := &webMockBackend{execStdout: nil, onInvoke: func(args []string) {
		// httpx writes nothing to its -o target: it probed and nothing responded.
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				if err := os.Remove(args[i+1]); err != nil && !os.IsNotExist(err) {
					t.Fatalf("clear httpx -o target: %v", err)
				}
			}
		}
	}}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	// PRECONDITION, not the subject: this test is about the F3 empty publish, and
	// the status check only exists to confirm the probe actually HAPPENED (as
	// opposed to the did-not-run error path covered by the next test).
	//
	// Updated deliberately in phase 16: "the probe ran and produced nothing" is
	// now StatusSkipped with a Reason rather than StatusDone, because reporting OK
	// for a task that consumed 1 host and produced 0 is the exact silent success
	// that emptied the web layer on 2026-08-21. Errored still means did-not-run,
	// so the distinction this test relies on is intact.
	if err != nil || res.Status == task.StatusErrored {
		t.Fatalf("httpx must RUN here (status %q, err %v) — the empty publish only "+
			"applies on a path where the probe actually happened", res.Status, err)
	}
	if res.Status == task.StatusSkipped && res.Reason == "" {
		t.Error("a skipped result must carry a Reason — an operator reading [SKIP] " +
			"with no reason learns nothing")
	}
	assertArtefactEmptied(t, workDir, "hosts")
}

// TestHostsArtefactPreservedWhenHTTPXDidNotRun covers the did-not-run half via
// httpx's StatusErrored input-resolution path: no subdomains input exists at
// all, so the probe never happens and the previous run's hosts must survive.
//
// This is the case that makes the httpx assignment safe. If the empty publish
// ran on an error path, a single missing input file would wipe a good artefact.
func TestHostsArtefactPreservedWhenHTTPXDidNotRun(t *testing.T) {
	workDir := t.TempDir()
	seed := `{"host":"api.example.com","ip":"1.2.3.4","asn":"AS64500"}`
	writeLinesFile(t, artefactFile(workDir, "hosts"), seed)
	// No subdomains/subdomains.txt and no other host input: resolveHostInput or
	// checkHostsFileReadable fails and httpx returns StatusErrored before Step 2.

	be := &webMockBackend{execErr: errors.New("httpx: executable file not found in $PATH")}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Fatalf("status = %q (err %v), want errored — this test must exercise a path "+
			"where httpx never probed", res.Status, err)
	}
	assertArtefactPreserved(t, workDir, "hosts", seed)
}
