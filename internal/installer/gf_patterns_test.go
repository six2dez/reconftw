// SPDX-License-Identifier: MIT
//
// Tests for the gf pattern provisioning step. The condition under test is the
// one that used to pass silently: a gf binary on PATH with an empty ~/.gf,
// which classifies nothing and empties seven vuln classes without raising
// anything above Debug.

package installer

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// swapGFPatternDir points gfPatternDir at a temp dir for the duration of a test
// so nothing here can touch the developer's real ~/.gf.
func swapGFPatternDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := gfPatternDir
	gfPatternDir = func() string { return dir }
	t.Cleanup(func() { gfPatternDir = orig })
	return dir
}

// fakeClone stubs runCmd so a `git clone` writes the given files into the
// destination directory instead of hitting the network.
func fakeClone(t *testing.T, perRepo map[string]map[string]string) {
	t.Helper()
	swapRunCmd(t, func(_ context.Context, name string, args, _ []string) error {
		if name != "git" || len(args) < 4 || args[0] != "clone" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		// args == ["clone", "--depth", "1", <url>, <dir>]
		url, dir := args[3], args[4]
		files, ok := perRepo[url]
		if !ok {
			return os.ErrNotExist // simulate an unreachable repo
		}
		for rel, content := range files {
			full := filepath.Join(dir, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
				return err
			}
		}
		return nil
	})
}

// allPatternsFor builds a file map covering every required class, so a test can
// stand up a "complete" source without listing them by hand.
func allPatternsFor(prefix, marker string) map[string]string {
	m := make(map[string]string, len(GFRequiredPatterns))
	for _, c := range GFRequiredPatterns {
		m[filepath.Join(prefix, c+".json")] = marker
	}
	return m
}

func TestProvisionGFPatternsPopulatesEveryRequiredClass(t *testing.T) {
	dir := swapGFPatternDir(t)
	fakeClone(t, map[string]map[string]string{
		"https://github.com/tomnomnom/gf": allPatternsFor("examples", `{"src":"gf"}`),
	})

	if err := provisionGFPatterns(context.Background(), nil); err != nil {
		t.Fatalf("provisionGFPatterns returned %v, want nil", err)
	}
	if missing := MissingGFPatterns(); len(missing) > 0 {
		t.Errorf("after provisioning, still missing %v in %s", missing, dir)
	}
}

// The silent-zero condition: every source unreachable, nothing provisioned.
// This MUST be an error, because gf is critical and a successful install that
// leaves ~/.gf empty is precisely the false green being fixed.
func TestProvisionGFPatternsErrorsWhenNothingProvisioned(t *testing.T) {
	swapGFPatternDir(t)
	fakeClone(t, map[string]map[string]string{}) // every clone fails

	err := provisionGFPatterns(context.Background(), nil)
	if err == nil {
		t.Fatal("provisionGFPatterns returned nil with an empty ~/.gf — " +
			"this is the silent zero the step exists to prevent")
	}
	if !strings.Contains(err.Error(), "no patterns provisioned") {
		t.Errorf("error did not name the condition: %v", err)
	}
}

// A partial provision is a warning, not a failure: some classes still work.
func TestProvisionGFPatternsToleratesPartialSources(t *testing.T) {
	swapGFPatternDir(t)
	fakeClone(t, map[string]map[string]string{
		"https://github.com/tomnomnom/gf": {"examples/xss.json": `{"src":"gf"}`},
	})

	if err := provisionGFPatterns(context.Background(), nil); err != nil {
		t.Fatalf("a partial provision must not fail the install, got %v", err)
	}
	missing := MissingGFPatterns()
	if len(missing) == 0 {
		t.Fatal("expected the un-provisioned classes to be reported missing")
	}
	for _, c := range missing {
		if c == "xss" {
			t.Errorf("xss was provisioned but reported missing")
		}
	}
}

// First source wins — never merge two JSON documents into one file.
func TestProvisionGFPatternsFirstSourceWins(t *testing.T) {
	dir := swapGFPatternDir(t)
	fakeClone(t, map[string]map[string]string{
		"https://github.com/tomnomnom/gf":              allPatternsFor("examples", `{"src":"first"}`),
		"https://github.com/1ndianl33t/Gf-Patterns":    {"xss.json": `{"src":"second"}`},
		"https://github.com/g0ldencybersec/sus_params": {"gf-patterns/xss.json": `{"src":"third"}`},
	})

	if err := provisionGFPatterns(context.Background(), nil); err != nil {
		t.Fatalf("provisionGFPatterns returned %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "xss.json"))
	if err != nil {
		t.Fatalf("read provisioned xss.json: %v", err)
	}
	if string(got) != `{"src":"first"}` {
		t.Errorf("xss.json = %q, want the FIRST source's content unmodified — "+
			"a later source overwrote or appended to it", got)
	}
}

// HealthCheck must fail on a gf that resolves but cannot classify. Before this,
// lookPath("gf") succeeding was the whole check.
func TestHealthCheckFailsOnResolvableGFWithNoPatterns(t *testing.T) {
	swapGFPatternDir(t) // empty temp dir — no patterns

	swapLookPath(t, func(string) (string, error) { return "/usr/bin/gf", nil })

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gf", Kind: "go", Critical: true})

	i := New(Options{Registry: reg, NonInteractive: true})
	err := i.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("HealthCheck passed with gf on PATH and ~/.gf empty — " +
			"the install cannot produce a single vuln-class candidate")
	}
	if !strings.Contains(err.Error(), "pattern") {
		t.Errorf("error did not name the pattern gap: %v", err)
	}
}
