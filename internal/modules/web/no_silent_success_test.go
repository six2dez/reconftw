// no_silent_success_test.go — a task that consumed input and produced nothing
// must say so.
//
// THE FAILURE BEING PREVENTED, verbatim from the first live v2 run:
//   [OK   ] web.httpx ................. 31s
// httpx had returned 20 perfectly good records; the parser rejected every one of
// them because httpxRaw.Port was an int against httpx's string "port". records=0,
// the artefact was truncated to 0 bytes, every downstream web task skipped
// correctly, and the run produced 0 live hosts against v1's 12 — reporting OK
// throughout.

package web_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"
)

// TestHTTPXTotalParseFailureIsNotOK is the 2026-08-21 root cause replayed.
func TestHTTPXTotalParseFailureIsNotOK(t *testing.T) {
	workDir := t.TempDir()
	seedSubdomainsArtefact(t, workDir, "api.example.com", "www.example.com", "mail.example.com")

	// httpx "succeeds" and writes output NO line of which parses.
	be := &webMockBackend{onInvoke: func(args []string) {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				if err := os.WriteFile(args[i+1], []byte("{not json at all}\n{neither is this}\n"), 0o600); err != nil {
					t.Fatalf("seed unparseable output: %v", err)
				}
			}
		}
	}}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status == task.StatusDone {
		t.Fatal("a TOTAL parse failure reported OK — this is precisely the state that " +
			"emptied the web layer and produced 0 live hosts against v1's 12")
	}
	if res.Reason == "" {
		t.Fatal("no Reason on a non-Done result — the operator cannot tell what went wrong")
	}
	if !strings.Contains(res.Reason, "failed to parse") {
		t.Errorf("Reason %q does not carry parseHTTPXOutput's own diagnosis", res.Reason)
	}
	// The F3 contract survives: an empty run still publishes an EMPTY artefact.
	assertArtefactEmptied(t, workDir, "hosts")
}

// TestHTTPXNoHostsFromNonEmptyInputIsNotOK covers rule B2 with a tool that ran
// cleanly and simply returned nothing.
func TestHTTPXNoHostsFromNonEmptyInputIsNotOK(t *testing.T) {
	workDir := t.TempDir()
	seedSubdomainsArtefact(t, workDir, "api.example.com", "www.example.com", "mail.example.com")

	be := &webMockBackend{onInvoke: func(args []string) {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.Remove(args[i+1]) // nothing responded
			}
		}
	}}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status == task.StatusDone {
		t.Error("probing 3 hosts and producing 0 reported OK")
	}
	if !strings.Contains(res.Reason, "3") {
		t.Errorf("Reason %q does not name the input count — the number is what makes "+
			"the result answerable", res.Reason)
	}
}

// TestHTTPXNoInputAtAllIsAnActionableError distinguishes the third case from the
// two above, and it is the pre-existing behaviour: with NO host list resolvable
// at all, httpx errors with a message telling the operator what to do. That is
// correct and must not be softened into a skip — "run `subs` first" is a real
// instruction, not a silent success.
//
// The inputCount == 0 branch added in phase 16 covers a DIFFERENT state: an input
// file that resolves but is empty. Keeping the two apart is the point; collapsing
// them would make a first-run web-only invocation look either broken or fine, and
// both readings would be wrong.
func TestHTTPXNoInputAtAllIsAnActionableError(t *testing.T) {
	workDir := t.TempDir()
	seedSubdomainsArtefact(t, workDir) // present but empty → no hosts resolvable

	be := &webMockBackend{}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Fatalf("Status = %q, want errored when no host list resolves at all", res.Status)
	}
	if err == nil || !strings.Contains(err.Error(), "subs") {
		t.Errorf("error %v does not tell the operator how to fix it", err)
	}
}

// TestHTTPXProducingHostsIsStillDone: the rule must not fire on the happy path.
func TestHTTPXProducingHostsIsStillDone(t *testing.T) {
	workDir := t.TempDir()
	seedSubdomainsArtefact(t, workDir, "api.example.com", "www.example.com")

	be := &webMockBackend{onInvoke: func(args []string) {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				body := `{"host":"api.example.com","url":"https://api.example.com","scheme":"https","port":"443","status_code":200}` + "\n" +
					`{"host":"www.example.com","url":"https://www.example.com","scheme":"https","port":"443","status_code":200}` + "\n"
				if err := os.WriteFile(args[i+1], []byte(body), 0o600); err != nil {
					t.Fatalf("seed output: %v", err)
				}
			}
		}
	}}
	app := newWebApp(t, workDir, be, "httpx")

	res, err := lookupWebTask(t, "web.httpx").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("a run that produced 2 hosts reported %q (%s)", res.Status, res.Reason)
	}
	if res.Reason != "" {
		t.Errorf("a Done result carries Reason %q — Done needs no explanation", res.Reason)
	}
	if res.Stats["hosts_found"] != 2 {
		t.Errorf("hosts_found = %d, want 2", res.Stats["hosts_found"])
	}
}

// seedSubdomainsArtefact writes artefacts/subdomains.jsonl, which is priority 3
// of resolveHostInput and the path a real `web` run after `subs` takes.
func seedSubdomainsArtefact(t *testing.T, workDir string, hosts ...string) {
	t.Helper()
	dir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	var b strings.Builder
	for _, h := range hosts {
		b.WriteString(`{"subdomain":"` + h + `","source":"test","first_seen":"2026-08-21"}` + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "subdomains.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatalf("seed subdomains.jsonl: %v", err)
	}
}
