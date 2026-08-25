// resolver_paths_test.go — paths.resolvers / paths.resolvers_trusted defaults.
//
// These fields were "" for the whole of v2's life and nothing downstream treated
// that as an error: puredns got `-r "" -rt ""`, exited 1, and aborted the only
// fail-fast stage group. A default `recon` could not complete a scan. The default
// is applied in Load (not Defaults) so an explicit config still wins.

package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// isolatedLoad runs config.Load against an empty XDG root so no file on the
// developer's machine can influence the result.
func isolatedLoad(t *testing.T) (*config.Config, string) {
	t.Helper()
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	cfg, err := config.Load(config.LoadOptions{
		SystemPath:  filepath.Join(t.TempDir(), "absent-system.toml"),
		ProjectPath: filepath.Join(t.TempDir(), "absent-project.toml"),
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg, xdg
}

// TestLoadFillsResolverPaths is the regression guard for the cutover blocker.
func TestLoadFillsResolverPaths(t *testing.T) {
	cfg, xdg := isolatedLoad(t)

	wantMain := filepath.Join(xdg, "reconftw", "resolvers.txt")
	wantTrusted := filepath.Join(xdg, "reconftw", "resolvers_trusted.txt")

	if cfg.Paths.Resolvers != wantMain {
		t.Errorf("paths.resolvers = %q, want %q — an empty value means puredns is invoked as `-r \"\"`",
			cfg.Paths.Resolvers, wantMain)
	}
	if cfg.Paths.ResolversTrusted != wantTrusted {
		t.Errorf("paths.resolvers_trusted = %q, want %q", cfg.Paths.ResolversTrusted, wantTrusted)
	}
}

// TestLoadResolverPathMatchesGenResolvers pins the convergence that makes the
// boot-time acquisition and the manual `reconftw gen-resolvers` subcommand write
// the SAME file. cmd/reconftw/stateful_subcommands.go:genResolversOutputPath
// hardcodes this same fallback; if the two drift, an operator who runs
// gen-resolvers by hand fixes a file the scan never reads.
func TestLoadResolverPathMatchesGenResolvers(t *testing.T) {
	cfg, xdg := isolatedLoad(t)
	genResolversFallback := filepath.Join(xdg, "reconftw", "resolvers.txt")
	if cfg.Paths.Resolvers != genResolversFallback {
		t.Errorf("config default %q diverges from the gen-resolvers output path %q",
			cfg.Paths.Resolvers, genResolversFallback)
	}
}

// TestLoadFillsNucleiTemplatesPath guards the second instance of the same hole.
// paths.nuclei_templates defaulted to "" and switched off web.nuclei,
// web.screenshot and vulns.nuclei_dast at once. The first live parity run scored
// 2 finding classes against v1's 50 — and essentially all fifty were nuclei
// template IDs — while the templates sat installed on the box, unlooked-at.
func TestLoadFillsNucleiTemplatesPath(t *testing.T) {
	cfg, _ := isolatedLoad(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory in this environment")
	}
	want := filepath.Join(home, "nuclei-templates")
	if cfg.Paths.NucleiTemplates != want {
		t.Errorf("paths.nuclei_templates = %q, want %q — an empty value silently "+
			"disables nuclei, screenshots and DAST", cfg.Paths.NucleiTemplates, want)
	}
}

// TestExplicitNucleiTemplatesPathWins: an explicit config still beats the default.
func TestExplicitNucleiTemplatesPathWins(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("RECONFTW_PATHS_NUCLEI_TEMPLATES", "/custom/templates")

	cfg, err := config.Load(config.LoadOptions{
		SystemPath:  filepath.Join(t.TempDir(), "absent-system.toml"),
		ProjectPath: filepath.Join(t.TempDir(), "absent-project.toml"),
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Paths.NucleiTemplates != "/custom/templates" {
		t.Errorf("paths.nuclei_templates = %q, want the configured /custom/templates",
			cfg.Paths.NucleiTemplates)
	}
}

// TestExplicitResolverPathWins: only a genuinely empty field is filled.
func TestExplicitResolverPathWins(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	t.Setenv("RECONFTW_PATHS_RESOLVERS", "/custom/resolvers.txt")

	cfg, err := config.Load(config.LoadOptions{
		SystemPath:  filepath.Join(t.TempDir(), "absent-system.toml"),
		ProjectPath: filepath.Join(t.TempDir(), "absent-project.toml"),
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.Paths.Resolvers != "/custom/resolvers.txt" {
		t.Errorf("paths.resolvers = %q, want the configured /custom/resolvers.txt", cfg.Paths.Resolvers)
	}
}
