// brutus_deadline_test.go — the pin that keeps brutus's process deadline from
// silently disappearing (18-04, T-18-04-01).
//
// THE DEFECT THIS PREVENTS, stated as it actually stood:
//
//	vulns/spray.go applied `brutusTimeout = 30 * time.Minute` with its own
//	context.WithTimeout, because it dispatched brutus directly. The brutus row in
//	tools.lock declared `timeout_seconds = 0`, which means NO BOUND — harmless
//	only for as long as nothing read it.
//
//	18-04 routed that dispatch onto backend.Runner, which makes applyToolContract
//	the SOLE owner of the deadline. Removing the file's constant WITHOUT setting
//	the manifest's would have converted a bounded credential-spraying run into an
//	unbounded one against a third-party host — invisibly, because nothing would
//	have failed.
//
// This is 17-07's "the manifest silently wins" finding pointing the other way:
// there a too-SHORT manifest bound overrode a longer configured budget; here an
// ABSENT manifest bound would have overridden a shorter real one. Both are the
// same class — a deadline that lives in two places and is owned by neither.
//
// The test reads tools.lock, not backend.Default: this package's Blocker-7 audit
// gate forbids *_test.go references to that singleton, and parsing the file is
// what the census helpers already do.
package backend_test

import (
	"os"
	"testing"
	"time"

	tomlv2 "github.com/pelletier/go-toml/v2"
)

// brutusFormerBound is the bound vulns/spray.go used to apply, duplicated here
// as a literal ON PURPOSE. Importing the module constant would couple this pin
// to the very file whose change it exists to catch: deleting
// brutusFormerTimeout would then make this test compile against nothing rather
// than fail loudly.
const brutusFormerBound = 30 * time.Minute

// TestBrutusDeadlineMatchesItsFormerBound asserts the tools.lock brutus row
// declares exactly the deadline spray.go used to apply itself.
//
// It fails in BOTH directions. Setting the row back to 0 (no bound) fails, and
// so does quietly shortening or lengthening it — either is a change to how long
// a credential-spraying run may hammer a third party, and neither should be
// possible without a visible diff and a written derivation.
func TestBrutusDeadlineMatchesItsFormerBound(t *testing.T) {
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

	var found bool
	var got int
	for _, tool := range lock.Tools {
		if tool.Name == "brutus" {
			found, got = true, tool.TimeoutSeconds
			break
		}
	}
	if !found {
		t.Fatal("no brutus row in tools.lock — vulns/spray.go dispatches it through " +
			"backend.Runner, which returns \"tool not registered\" for an unlisted name, so " +
			"spraying would silently never run")
	}

	want := int(brutusFormerBound / time.Second)
	if got == 0 {
		t.Fatalf("brutus timeout_seconds = 0, which means NO BOUND (T-18-04-01).\n"+
			"  vulns/spray.go used to apply %s with its own context.WithTimeout; 18-04 moved that\n"+
			"  dispatch onto backend.Runner, so tools.lock is now the ONLY owner of the deadline.\n"+
			"  Leaving it at 0 converts a bounded credential-spraying run into an unbounded one\n"+
			"  against a third-party host. Set timeout_seconds = %d.", brutusFormerBound, want)
	}
	if got != want {
		t.Fatalf("brutus timeout_seconds = %d, want %d (%s — the exact bound vulns/spray.go used to\n"+
			"  apply). A change here changes how long a credential-spraying run may hammer a third\n"+
			"  party; it needs a written derivation in the tools.lock row, not a silent edit.",
			got, want, brutusFormerBound)
	}
}
