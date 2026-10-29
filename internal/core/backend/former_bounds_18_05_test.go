// former_bounds_18_05_test.go — the manifest deadline pin for the one 18-05
// tool whose bound must be ZERO.
//
// This file used to hold five pins of the form "the tools.lock timeout_seconds
// for <tool> equals the constant the module applied before 18-05 moved its
// dispatch onto backend.Runner" (JSA, nomore403, roboxtractor, git here, and
// brutus in brutus_deadline_test.go). Each compared a TOML number against a
// literal copied from it; the two can only disagree when someone edits one of
// them, and the failure message then told them to edit the other. 21-04 deleted
// them as self-assertions — see internal/modules/DELETED_TESTS.md. The
// derivations stay where they belong: in the tools.lock rows themselves.
//
// What remains is the one pin that asserts a PROPERTY rather than a copied
// value: interactsh-client must carry NO manifest deadline, for the reason
// written on the test.
//
// tools.lock is read from disk rather than off backend.Default: this package's
// Blocker-7 audit gate forbids *_test.go references to that singleton, and
// parsing the file is what the census helpers already do.
package backend_test

import (
	"os"
	"testing"

	tomlv2 "github.com/pelletier/go-toml/v2"
)

// lockTimeoutSeconds returns the timeout_seconds declared for name, and whether
// the row exists at all. An ABSENT row is reported separately because it is a
// different and worse failure: Runner.Run returns "tool not registered" for an
// unlisted name, so the tool would silently never run.
func lockTimeoutSeconds(t *testing.T, name string) (int, bool) {
	t.Helper()
	data, err := os.ReadFile("tools.lock")
	if err != nil {
		t.Fatalf("read tools.lock: %v", err)
	}
	var lock struct {
		Tools []struct {
			Name           string `toml:"name"`
			TimeoutSeconds int    `toml:"timeout_seconds"`
		} `toml:"tools"`
	}
	if err := tomlv2.Unmarshal(data, &lock); err != nil {
		t.Fatalf("parse tools.lock: %v", err)
	}
	for _, tool := range lock.Tools {
		if tool.Name == name {
			return tool.TimeoutSeconds, true
		}
	}
	return 0, false
}

// TestInteractshHasNoManifestDeadline asserts a ZERO — the opposite of every
// other 18-04/18-05 deadline, which must be bounded.
//
// interactsh-client is a long-lived OOB callback server, not a request/response
// dispatch. Its lifetime IS the SSRF task's lifetime, owned by
// cfg.Vulns.SSRF.TimeoutSeconds — which an operator can raise. 18-05 routed
// vulns/ssrf.go onto Runner.StreamOpts, so a non-zero row here would become the
// sole owner of a deadline it has no business owning, and would silently kill the
// session mid-task for anyone who raised the task timeout.
//
// "No manifest bound" is NOT "unbounded": startInteractshClient derives its
// session context from the task ctx, so the task's own WithTimeout still tears
// the process group down. If that ever stops being true, this test's comment is
// the thing that has gone stale, and the row must be revisited rather than the
// test relaxed.
func TestInteractshHasNoManifestDeadline(t *testing.T) {
	got, ok := lockTimeoutSeconds(t, "interactsh-client")
	if !ok {
		t.Fatal("no interactsh-client row in tools.lock — vulns/ssrf.go dispatches it " +
			"through backend.Runner, which returns \"tool not registered\" for an unlisted " +
			"name, so OOB SSRF detection would silently never start")
	}
	if got != 0 {
		t.Fatalf("interactsh-client timeout_seconds = %d, want 0.\n"+
			"  A non-zero value makes applyToolContract the sole owner of the OOB session's\n"+
			"  deadline. The session must live as long as the SSRF task, whose bound is\n"+
			"  cfg.Vulns.SSRF.TimeoutSeconds and is operator-configurable. At %d the session\n"+
			"  dies mid-task for any operator who raises that value, and the only symptom is\n"+
			"  that SSRF stops reporting OOB callbacks — nothing fails.", got, got)
	}
}
