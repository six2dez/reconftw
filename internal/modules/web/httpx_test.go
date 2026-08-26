// httpx_test.go — CR-02: httpx must never be handed one path as both its input
// list and its output file.
//
// WHAT THIS FILE IS FOR, stated once so a later reader does not retire the wrong
// test:
//
//   - TestHTTPXPriorArtefactInput drives the REACHABILITY claim. It seeds the
//     workspace in exactly the state subdomains.geo leaves it (a non-empty
//     artefacts/hosts.jsonl, written by Tree.Append("hosts") in the LAST
//     subdomains stage group) and asserts what actually lands on httpx's -l.
//     Before the fix, -l carried the artefact itself.
//
//   - TestHTTPXInputIsNeverTheOutputPath is the GUARD. It covers the route the
//     derivation cannot remove: an operator who passes --hosts
//     artefacts/hosts.jsonl. Priority 1 returns that path verbatim, so the only
//     thing standing between httpx and its own -o target is the assertion in
//     HTTPXTask.Run. Delete the assertion and this test fails.
//
// REAL-TOOL EVIDENCE behind the claim (httpx v1.9.0, this box, localhost only):
//
//	$ printf '127.0.0.1:18099\n' | httpx -silent -duc -no-color
//	http://127.0.0.1:18099
//	$ printf '{"host":"127.0.0.1:18099","url":"http://127.0.0.1:18099",…}\n' | httpx -silent -duc -no-color
//	(no output)
//
// Same live target, same binary: as a bare host it is found, wrapped in a
// hosts.jsonl record it is not. That is the whole defect — the run reports
// "probed N host(s), no live host survived probing", which is indistinguishable
// from a dead target.
package web_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/modules/web"
)

// argAfter returns the value following flag in argv, or "" when absent.
func argAfter(argv []string, flag string) string {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// seedPriorHostsArtefact writes artefacts/hosts.jsonl in the shape
// subdomains/geo.go leaves it: enriched host records, one JSON object per line.
func seedPriorHostsArtefact(t *testing.T, workDir string) string {
	t.Helper()
	p := filepath.Join(workDir, "artefacts", "hosts.jsonl")
	writeLinesFile(t, p,
		`{"host":"api.example.com","url":"https://api.example.com","ip":"93.184.216.34","asn":"AS15133","country":"US"}`,
		`{"host":"www.example.com","url":"https://www.example.com","ip":"93.184.216.34","asn":"AS15133","country":"US"}`,
	)
	return p
}

// TestHTTPXPriorArtefactInput — the reachability claim, driven end to end:
// geo's artefact on disk -> resolveHostInput -> the dispatched argv.
func TestHTTPXPriorArtefactInput(t *testing.T) {
	workDir := t.TempDir()
	artefact := seedPriorHostsArtefact(t, workDir)

	var argv []string
	be := &webMockBackend{onInvoke: func(a []string) { argv = append([]string(nil), a...) }}
	app := newWebApp(t, workDir, be, "httpx")

	if _, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app); err != nil {
		t.Fatalf("web.httpx returned an error: %v", err)
	}
	if len(argv) == 0 {
		t.Fatalf("httpx was never dispatched — the reachability test proves nothing")
	}

	in := argAfter(argv, "-l")
	out := argAfter(argv, "-o")
	t.Logf("CR-02 REACHABILITY: -l %s", in)
	t.Logf("CR-02 REACHABILITY: -o %s", out)

	if in == artefact {
		t.Errorf("httpx -l carries the hosts ARTEFACT itself (%s).\n"+
			"      artefacts/hosts.jsonl holds JSON objects, not hostnames. httpx finds\n"+
			"      nothing in them (verified against httpx v1.9.0 — see the file header),\n"+
			"      and the run then reports \"no live host survived probing\", which reads\n"+
			"      exactly like a dead target.", in)
	}
	if in == out {
		t.Errorf("httpx is handed the same path as -l and -o: %s", in)
	}

	// The derived list must actually carry the hostnames, or the fix has only
	// moved the emptiness somewhere quieter.
	body, err := os.ReadFile(in) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read derived host list %s: %v", in, err)
	}
	for _, want := range []string{"api.example.com", "www.example.com"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("derived host list is missing %q; got:\n%s", want, body)
		}
	}
	if strings.Contains(string(body), `{"host"`) {
		t.Errorf("derived host list still contains JSON objects:\n%s", body)
	}
}

// TestHTTPXInputIsNeverTheOutputPath — the guard. --hosts <the artefact> is the
// one route derivation cannot close, because priority 1 returns the operator's
// path verbatim.
func TestHTTPXInputIsNeverTheOutputPath(t *testing.T) {
	t.Run("input path equal to the output path", func(t *testing.T) {
		workDir := t.TempDir()
		// The one path an operator can still collide with the -o target: the raw
		// staging file httpx itself writes. It exists after any prior run, it
		// holds probe results, and pointing --hosts at it is an ordinary mistake.
		collide := filepath.Join(workDir, "inputs", "hosts.httpx.raw.jsonl")
		writeLinesFile(t, collide, "api.example.com", "www.example.com")

		var argv []string
		be := &webMockBackend{onInvoke: func(a []string) { argv = append([]string(nil), a...) }}
		app := newWebApp(t, workDir, be, "httpx")

		ctx := web.CtxWithHostsFile(context.Background(), collide)
		res, err := lookupWebTask(t, "web.httpx").Run(ctx, app)
		if err == nil {
			t.Errorf("web.httpx accepted %s as BOTH its input list and its output file, and returned %v.\n"+
				"      httpx creates and truncates its -o file even on a run that finds nothing\n"+
				"      (httpx v1.9.0: a no-result run still left a 0-byte -o, exit 0), so this\n"+
				"      dispatch destroys the list while reading it. It must fail LOUDLY — a silent\n"+
				"      skip here is indistinguishable from a dead target.\n"+
				"      dispatched argv: %v", collide, res.Status, argv)
		}
		if len(argv) != 0 {
			t.Errorf("httpx was DISPATCHED with input == output; the assertion must fire BEFORE dispatch.\n"+
				"      argv: %v", argv)
		}
		if err != nil && !strings.Contains(err.Error(), "same path") {
			t.Errorf("the failure must name the problem; got %q", err)
		}
	})

	t.Run("operator passes the hosts artefact as --hosts", func(t *testing.T) {
		workDir := t.TempDir()
		artefact := seedPriorHostsArtefact(t, workDir)

		var argv []string
		be := &webMockBackend{onInvoke: func(a []string) { argv = append([]string(nil), a...) }}
		app := newWebApp(t, workDir, be, "httpx")

		ctx := web.CtxWithHostsFile(context.Background(), artefact)
		if _, err := lookupWebTask(t, "web.httpx").Run(ctx, app); err != nil {
			t.Fatalf("web.httpx returned an error: %v", err)
		}
		in := argAfter(argv, "-l")
		if in == artefact {
			t.Errorf("--hosts <a JSONL artefact> reached httpx -l verbatim (%s).\n"+
				"      httpx cannot use a JSON object as a target, so the run probes nothing\n"+
				"      and then calls the target dead.", in)
		}
		body, err := os.ReadFile(in) //nolint:gosec // test-controlled temp path
		if err != nil {
			t.Fatalf("read derived host list %s: %v", in, err)
		}
		if !strings.Contains(string(body), "api.example.com") {
			t.Errorf("derived host list lost the hostnames; got:\n%s", body)
		}
	})

	t.Run("repeat web run on a populated workspace", func(t *testing.T) {
		workDir := t.TempDir()
		seedPriorHostsArtefact(t, workDir)

		var argv []string
		be := &webMockBackend{onInvoke: func(a []string) { argv = append([]string(nil), a...) }}
		app := newWebApp(t, workDir, be, "httpx")

		if _, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app); err != nil {
			t.Fatalf("web.httpx returned an error: %v", err)
		}
		if in, out := argAfter(argv, "-l"), argAfter(argv, "-o"); in == out {
			t.Errorf("repeat `web` run dispatches httpx with -l == -o == %s", in)
		}
	})
}
