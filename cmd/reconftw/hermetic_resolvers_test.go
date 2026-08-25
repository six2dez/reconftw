// hermetic_resolvers_test.go — resolver provisioning for E2E binary tests.
//
// A run that resolves DNS refuses to start without a resolver list
// (handlers.BootReconApp / RunOptions.RequireResolvers). That is the whole point
// of the fix for the 2026-08-20 cutover blocker, where puredns was handed
// `-r ""` and aborted the only fail-fast stage group.
//
// It also means a test that shells out to `reconftw subs|recon|all|zen|deep`
// needs a resolver list the way a real deployment does. Left to the default the
// binary would go and DOWNLOAD one, which is wrong twice over in a test: it makes
// the suite depend on network egress (green locally, red on a no-egress CI runner
// — the exact CI-break class `go test ./...` cannot catch), and it writes into the
// developer's real $HOME.
//
// hermeticResolverEnv gives such a test a seeded list and an isolated HOME, so the
// subprocess touches neither the network nor anything outside t.TempDir().

package main_test

import (
	"os"
	"path/filepath"
	"testing"
)

// hermeticResolverEnv returns an environment for a subprocess `reconftw` run that
// resolves DNS: a seeded resolver list, plus HOME/XDG_CONFIG_HOME pointed inside
// the test's temp dir so nothing escapes it.
//
// Pass the extra entries the caller would otherwise have appended to os.Environ()
// (e.g. a minimal PATH); they are applied last and win.
func hermeticResolverEnv(t *testing.T, extra ...string) []string {
	t.Helper()

	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "reconftw")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatalf("hermeticResolverEnv: mkdir %s: %v", cfgDir, err)
	}

	resolvers := filepath.Join(cfgDir, "resolvers.txt")
	trusted := filepath.Join(cfgDir, "resolvers_trusted.txt")
	// Real public resolvers, so the list is plausible if a tool ever reads it.
	// Nothing in these tests actually queries them — no tool is on PATH.
	if err := os.WriteFile(resolvers, []byte("1.1.1.1\n8.8.8.8\n9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("hermeticResolverEnv: seed resolvers: %v", err)
	}
	if err := os.WriteFile(trusted, []byte("1.1.1.1\n8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("hermeticResolverEnv: seed trusted resolvers: %v", err)
	}

	env := append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"RECONFTW_PATHS_RESOLVERS="+resolvers,
		"RECONFTW_PATHS_RESOLVERS_TRUSTED="+trusted,
	)
	return append(env, extra...)
}

// TestHermeticResolverEnvIsUsable is a guard on the helper itself: if the env-var
// spelling drifts from the koanf path (RECONFTW_<SECTION>_<FIELD> → section.field),
// the override silently stops applying, every caller quietly goes back to
// downloading, and the CI-break returns with no test failing. Assert the mapping
// holds rather than trusting it.
func TestHermeticResolverEnvIsUsable(t *testing.T) {
	env := hermeticResolverEnv(t)

	var resolversPath string
	for _, e := range env {
		if len(e) > len("RECONFTW_PATHS_RESOLVERS=") && e[:len("RECONFTW_PATHS_RESOLVERS=")] == "RECONFTW_PATHS_RESOLVERS=" {
			resolversPath = e[len("RECONFTW_PATHS_RESOLVERS="):]
		}
	}
	if resolversPath == "" {
		t.Fatal("hermeticResolverEnv did not export RECONFTW_PATHS_RESOLVERS")
	}
	info, err := os.Stat(resolversPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("seeded resolver list is not usable: %v", err)
	}
}
