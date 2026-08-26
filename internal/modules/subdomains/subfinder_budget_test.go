// subfinder_budget_test.go — CR-07: subfinder's time budget must be expressed in
// the unit subfinder documents.
//
// subfinder v2.14.0, `subfinder -h`:
//
//	-timeout int   seconds to wait before timing out (default 30)
//	-max-time int  minutes to wait for enumeration results (default 10)
//
// Both flags exist and their units differ, which is exactly how a
// minutes-times-sixty slipped through: `-max-time 10800` is a legal, accepted
// value, so nothing failed. It asks for 7.5 days, which removes subfinder's own
// budget entirely and leaves the process deadline in tools.lock as the only
// bound — a bound that was three MINUTES where v1 allows 180.
//
// v1 for comparison (reconftw.cfg:384, modules/subdomains.sh:515):
//
//	SUBFINDER_ENUM_TIMEOUT=180          # Minutes
//	subfinder -all -d "$domain" -max-time "$SUBFINDER_ENUM_TIMEOUT" -silent -o …
//
// The value is passed straight through, with no multiplication and no `timeout`
// wrapper.

package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/task"

	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// maxTimeValue returns the argument following -max-time in argv, or "" when the
// flag is absent.
func maxTimeValue(argv []string) string {
	for i, a := range argv {
		if a == "-max-time" && i+1 < len(argv) {
			return argv[i+1]
		}
	}
	return ""
}

// TestSubfinderMaxTimeIsInMinutesAtBothCallSites pins the unit at every place
// v2 dispatches subfinder. Both are asserted in one test on purpose: the two
// call sites carried an identical copy of the same arithmetic, so a fix applied
// to one and not the other is the realistic regression, not a hypothetical one.
func TestSubfinderMaxTimeIsInMinutesAtBothCallSites(t *testing.T) {
	const configuredMinutes = 45

	t.Run("subdomains.passive.subfinder", func(t *testing.T) {
		workDir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
			t.Fatalf("mkdir inputs: %v", err)
		}
		tracker := &argCapturingBackend{}
		reg := backend.NewToolRegistry()
		reg.Register(&backend.Tool{Name: "subfinder"})
		app := newTestApp(workDir, backend.NewRunner(tracker, reg, nil), &mockTree{})
		app.Cfg.Advanced.Tools.Subfinder.TimeoutMinutes = configuredMinutes

		tsk, ok := task.Default.Lookup("subdomains.passive.subfinder")
		if !ok {
			t.Fatal("subdomains.passive.subfinder not registered")
		}
		if _, err := tsk.Run(context.Background(), app); err != nil {
			t.Fatalf("run: %v", err)
		}
		assertMaxTimeMinutes(t, "subdomains.passive.subfinder (passive.go)", tracker.args, configuredMinutes)
	})

	t.Run("subdomains.recursive.passive", func(t *testing.T) {
		workDir := t.TempDir()
		inputsDir := filepath.Join(workDir, "inputs")
		if err := os.MkdirAll(inputsDir, 0o755); err != nil {
			t.Fatalf("mkdir inputs: %v", err)
		}
		if err := os.WriteFile(filepath.Join(inputsDir, "resolved.merged.txt"),
			[]byte("api.example.com\n"), 0o644); err != nil {
			t.Fatalf("seed merged file: %v", err)
		}
		tracker := &argCapturingBackend{}
		reg := backend.NewToolRegistry()
		reg.Register(&backend.Tool{Name: "subfinder"})
		app := buildRecursiveApp(workDir, backend.NewRunner(tracker, reg, nil))
		app.Cfg.Advanced.Tools.Subfinder.TimeoutMinutes = configuredMinutes

		tsk, ok := task.Default.Lookup("subdomains.recursive.passive")
		if !ok {
			t.Fatal("subdomains.recursive.passive not registered")
		}
		if _, err := tsk.Run(context.Background(), app); err != nil {
			t.Fatalf("run: %v", err)
		}
		assertMaxTimeMinutes(t, "subdomains.recursive.passive (recursive.go)", tracker.args, configuredMinutes)
	})
}

func assertMaxTimeMinutes(t *testing.T, callSite string, argv []string, wantMinutes int) {
	t.Helper()
	got := maxTimeValue(argv)
	if got == "" {
		t.Fatalf("%s: no -max-time in the captured argv %v", callSite, argv)
	}
	want := strconv.Itoa(wantMinutes)
	if got != want {
		gotN, _ := strconv.Atoi(got)
		t.Fatalf("%s: -max-time = %s, want %s.\n"+
			"  subfinder documents -max-time in MINUTES. %s asks subfinder for %d minutes,\n"+
			"  i.e. about %d days, which removes subfinder's own budget and leaves the\n"+
			"  tools.lock process deadline as the only bound.\n"+
			"  captured argv: %v",
			callSite, got, want, callSite, gotN, gotN/1440, argv)
	}
}
