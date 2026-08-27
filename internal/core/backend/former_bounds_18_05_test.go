// former_bounds_18_05_test.go — the pins that keep 18-05's moved tools from
// silently changing how long they may run.
//
// THE RULE, inherited from 18-04's brutus trap: the moment a dispatch moves onto
// backend.Runner, applyToolContract becomes the SOLE owner of that tool's
// deadline. Whatever the module used to apply itself stops applying. So every
// move must reconcile the two values IN WRITING, and pin the result — otherwise
// a bound changes by tenfold, or disappears, and nothing fails.
//
// 18-05 moved four tools. Two of them disagreed with their manifest row in
// neither direction (nomore403 300 == 300) or in a direction that mattered:
//
//	nomore403     file 300s, row 300 — AGREE. Nothing to reconcile; pinned below
//	              anyway, because "they happen to agree today" is exactly the
//	              state that drifts.
//	roboxtractor  file 120s, row 120 — AGREE. Same treatment.
//	JSA           file  30s, row 300 — DISAGREE, and in the expensive direction:
//	              the dispatch is PER JS URL, so adopting the row unchanged would
//	              have multiplied every per-URL bound tenfold. The row was
//	              lowered to 30 with a derivation in tools.lock itself.
//
// Each pin fails in BOTH directions. Shortening is as much a change as
// lengthening, and 0 — which means NO BOUND — is called out by name, because
// that is the value that looks harmless in a diff and removes the bound
// entirely.
//
// tools.lock is read from disk rather than off backend.Default: this package's
// Blocker-7 audit gate forbids *_test.go references to that singleton, and
// parsing the file is what the census helpers already do.
package backend_test

import (
	"os"
	"testing"
	"time"

	tomlv2 "github.com/pelletier/go-toml/v2"
)

// The bounds each module file applied itself before 18-05, duplicated here as
// literals ON PURPOSE (the brutus precedent): importing the module constants
// would couple these pins to the very files whose change they exist to catch,
// so deleting one would make the test compile against nothing rather than fail.
const (
	jsaFormerBound          = 30 * time.Second  // web/jsa.go runJSAForURL, per URL
	nomore403FormerBound    = 300 * time.Second // web/nomore403.go and vulns/bypass4xx.go
	roboxtractorFormerBound = 120 * time.Second // web/wordlistgen.go roboxtractor leg
	gitCloneFormerBound     = 300 * time.Second // osint/github_repos.go githubReposGitClone
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

// assertFormerBound is the shared body: row present, non-zero, and exactly the
// bound the module used to apply.
func assertFormerBound(t *testing.T, name string, former time.Duration, dispatcher string) {
	t.Helper()
	got, ok := lockTimeoutSeconds(t, name)
	if !ok {
		t.Fatalf("no %q row in tools.lock — %s dispatches it through backend.Runner, "+
			"which returns \"tool not registered\" for an unlisted name, so the tool would "+
			"silently never run", name, dispatcher)
	}
	want := int(former / time.Second)
	if got == 0 {
		t.Fatalf("%s timeout_seconds = 0, which means NO BOUND.\n"+
			"  %s used to apply %s with its own context.WithTimeout; 18-05 moved that dispatch\n"+
			"  onto backend.Runner, so tools.lock is now the ONLY owner of the deadline.\n"+
			"  Set timeout_seconds = %d.", name, dispatcher, former, want)
	}
	if got != want {
		t.Fatalf("%s timeout_seconds = %d, want %d (%s — the exact bound %s used to apply\n"+
			"  before 18-05 moved it onto backend.Runner). A change here changes how long the\n"+
			"  tool may run; it needs a written derivation in the tools.lock row, not a silent edit.",
			name, got, want, former, dispatcher)
	}
}

// TestJSADeadlineMatchesItsFormerBound is the one that actually moved a value.
//
// web/jsa.go carried `const toolTimeout = 30 * time.Second` under a comment
// asserting there was "no JSA entry in tools.lock for per-URL cap". The row
// existed and said 300. Routing the dispatch through the Runner would have
// adopted 300 SILENTLY, per JS URL, across a whole corpus. The row is now 30.
func TestJSADeadlineMatchesItsFormerBound(t *testing.T) {
	assertFormerBound(t, "JSA", jsaFormerBound, "web/jsa.go runJSAForURL")
}

// TestNomore403DeadlineMatchesItsFormerBound pins an AGREEMENT.
//
// Both dispatchers applied 300s and the row said 300, so removing the local
// context.WithTimeout changed nothing today. This pin exists for tomorrow: two
// files and one manifest row agreeing by coincidence is precisely the state
// that drifts the first time someone edits one of them.
func TestNomore403DeadlineMatchesItsFormerBound(t *testing.T) {
	assertFormerBound(t, "nomore403", nomore403FormerBound,
		"web/nomore403.go and vulns/bypass4xx.go")
}

// TestInteractshHasNoManifestDeadline is the ONE pin in this file that asserts a
// ZERO, and it is the opposite of TestBrutusDeadlineMatchesItsFormerBound.
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

// TestGitCloneDeadlineMatchesItsFormerBound pins the bound Verdict 2 MOVED.
//
// osint/github_repos.go applied githubReposCloneTimeout = 300s with its own
// context.WithTimeout because it dispatched git directly. 18-05 registered git
// as a kind="system" row and routed the clone onto backend.Runner, so the row is
// now the sole owner. The value is the module's former one, verbatim, and the
// derivation stayed with it ("company repos can be large ... a hung/auth-
// prompting clone is still killed").
//
// A 0 here would leave a clone of an UNTRUSTED third-party repository unbounded,
// which is the brutus failure shape on a different tool.
func TestGitCloneDeadlineMatchesItsFormerBound(t *testing.T) {
	assertFormerBound(t, "git", gitCloneFormerBound, "osint/github_repos.go githubReposGitClone")
}

// TestRoboxtractorDeadlineMatchesItsFormerBound pins the other agreement.
//
// Measured on 2026-08-26, the real roboxtractor takes well over 30 seconds
// against a live host before exiting 0, so this bound is not decorative: it is
// the one path on which the tool's collected words are discarded.
func TestRoboxtractorDeadlineMatchesItsFormerBound(t *testing.T) {
	assertFormerBound(t, "roboxtractor", roboxtractorFormerBound,
		"web/wordlistgen.go wordlistgenRoboxtractorRunner")
}
