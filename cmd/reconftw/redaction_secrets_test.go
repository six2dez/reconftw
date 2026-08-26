// redaction_secrets_test.go — the split-brain guard.
//
// Before this plan there were TWO redactors in a run and they knew different
// things. newRunRedactor() built a bare *log.Redactor with nothing registered,
// and that instance is what the tool recorder holds and what therefore protects
// logs/tools.jsonl. A DIFFERENT instance, built inside the afterBoot closures and
// seeded by registerSecrets, protected run.log. A Shodan key echoed back by a
// tool was scrubbed from one file and written verbatim to the other, and adding
// a tenth secret to registerSecrets would have protected one sink and missed the
// other with nothing failing.
//
// This file asserts the two properties that make that impossible to reintroduce:
// the run redactor and the log redactor are the SAME OBJECT, and the set of
// values they know is derived from registerSecrets rather than copied beside it.
//
// It is package main (not main_test) because newRunRedactor, wireRunSecrets and
// registerSecrets are unexported. The end-to-end proof that production actually
// takes this path lives in redaction_e2e_test.go, which is package main_test —
// one file cannot be both, which is why the two guards are two files.

package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
)

// secretFieldType is the marker: every operator-supplied secret in the config
// tree is declared as log.Secret, and config.go's SECRET FIELD ENUMERATION block
// is the list registerSecrets is written against.
var secretFieldType = reflect.TypeOf(log.Secret(""))

// seedEverySecretField walks cfg by REFLECTION and gives every log.Secret-typed
// field a distinct, unmistakable value. It returns fieldPath -> value.
//
// Reflection rather than a hand-written list is the whole point of this guard.
// A literal list would be a copy of registerSecrets sitting next to it, and the
// first time someone adds a tenth secret field the copy would go stale silently
// — the test would keep passing while the new field reached no sink. Walking the
// struct means a field added to config.Config is picked up here with no test
// edit, and if registerSecrets was not updated to match, this test FAILS.
func seedEverySecretField(t *testing.T, cfg *config.Config) map[string]string {
	t.Helper()
	seeded := map[string]string{}
	var walk func(v reflect.Value, path string)
	walk = func(v reflect.Value, path string) {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return
			}
			walk(v.Elem(), path)
			return
		}
		if v.Kind() != reflect.Struct {
			return
		}
		tp := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f, ft := v.Field(i), tp.Field(i)
			if ft.PkgPath != "" { // unexported
				continue
			}
			name := path + ft.Name
			if ft.Type == secretFieldType {
				if !f.CanSet() {
					t.Fatalf("secret field %s is not settable", name)
				}
				val := fmt.Sprintf("SEEDED-%s-Qx2Wv9Zb4Nm6Tj", strings.ToUpper(
					strings.NewReplacer(".", "-", "_", "-").Replace(name)))
				f.SetString(val)
				seeded[name] = val
				continue
			}
			switch f.Kind() {
			case reflect.Struct, reflect.Pointer:
				walk(f, name+".")
			}
		}
	}
	walk(reflect.ValueOf(cfg), "")
	return seeded
}

// TestRunRedactorAndLogRedactorShareRegisteredSecrets is the guard named in the
// plan's acceptance criteria.
func TestRunRedactorAndLogRedactorShareRegisteredSecrets(t *testing.T) {
	cfg := config.Defaults()
	seeded := seedEverySecretField(t, cfg)

	// config.go's SECRET FIELD ENUMERATION documents nine fields. A lower count
	// means the reflection walk stopped finding them (a renamed type, a field
	// moved behind an unexported struct) and every assertion below would then be
	// vacuously true — the classic false green.
	if len(seeded) < 9 {
		t.Fatalf("the reflection walk found only %d log.Secret fields (%v); "+
			"config.go enumerates nine. The walk is broken, not the code under test.",
			len(seeded), seeded)
	}

	// The production sequence, in production order: the redactor is built at the
	// RunOptions site (cfg unavailable), then seeded from the afterBoot closure
	// once cfg has been resolved by BootReconApp.
	runSecrets := newRunRedactor()
	logRedactor := wireRunSecrets(runSecrets, cfg)

	// PROPERTY 1 — one identity. The redactor protecting run.log IS the redactor
	// the tool recorder holds. Two instances is the defect, not an implementation
	// detail: they would drift the moment either seeding path changed.
	if logRedactor != runSecrets {
		t.Fatalf("wireRunSecrets returned a DIFFERENT redactor (%p) from the run's "+
			"(%p) — run.log and logs/tools.jsonl are two security postures again",
			logRedactor, runSecrets)
	}

	// PROPERTY 2 — the run redactor (logs/tools.jsonl, and the terminal sink via
	// StageProgress.SetRedactor) knows every config secret.
	for name, val := range seeded {
		line := "tool rejected credential " + val + " for host example.com"
		got := runSecrets.Redact(line)
		if strings.Contains(got, val) {
			t.Errorf("run redactor does not know config field %s — its value would "+
				"reach logs/tools.jsonl and the terminal verbatim.\n  got: %s", name, got)
		}
	}

	// PROPERTY 3 — the log sink knows exactly the same set. Asserted separately
	// from property 1 so that a future refactor which legitimately splits the
	// instances still has to keep the SETS equal, rather than silently reverting
	// to the split brain.
	for name, val := range seeded {
		if strings.Contains(logRedactor.Redact("x "+val+" y"), val) {
			t.Errorf("log redactor does not know config field %s", name)
		}
	}
}

// TestRegisterSecretsCoversEveryConfigSecretField pins the drift this plan's
// acceptance criteria ask about: "state how a newly added config secret is
// picked up automatically".
//
// The answer is that it is not picked up by magic — it is picked up by this
// test FAILING. seedEverySecretField finds the new field by reflection; if
// registerSecrets was not extended to register it, the run redactor will not
// know its value and this test names the field that was missed.
func TestRegisterSecretsCoversEveryConfigSecretField(t *testing.T) {
	cfg := config.Defaults()
	seeded := seedEverySecretField(t, cfg)

	r := &log.Redactor{}
	registerSecrets(cfg, r)

	var missed []string
	for name, val := range seeded {
		if strings.Contains(r.Redact(val), val) {
			missed = append(missed, name)
		}
	}
	if len(missed) > 0 {
		t.Errorf("registerSecrets does not register %d log.Secret config field(s): %v\n"+
			"Add them to registerSecrets in cmd/reconftw/main.go — every sink in the "+
			"run is seeded from that one function.", len(missed), missed)
	}
}

// TestNewRunRedactorStartsEmptyByDesign documents WHY the seeding is a second
// step rather than a constructor argument, so a later reader does not "simplify"
// wireRunSecrets away and silently restore the empty-instance defect.
//
// cfg does not exist at any of the eleven RunOptions call sites: config.Load runs
// inside handlers.BootReconApp, which is called by handlers.Run*Async, which
// receives the already-constructed RunOptions literal.
func TestNewRunRedactorStartsEmptyByDesign(t *testing.T) {
	r := newRunRedactor()
	if r == nil {
		t.Fatal("newRunRedactor returned nil; the tool recorder would then have no redactor at all")
	}
	const notYetKnown = "SEEDED-APIKEYS-SHODAN-Qx2Wv9Zb4Nm6Tj"
	if !strings.Contains(r.Redact(notYetKnown), notYetKnown) {
		t.Error("newRunRedactor already knows a config value — if cfg IS reachable " +
			"there, seed it there and delete wireRunSecrets rather than keeping two steps")
	}
}
