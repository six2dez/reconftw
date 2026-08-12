// autodiscovery_test.go — regression guard for the dead config layers.
//
// Layers 2 (system), 3 (user) and 4 (project) of the documented 8-source chain were
// never populated: LoadOptions promised "Empty = use the platform default", the ADR
// and the loader header both listed the paths, and nothing resolved them. No
// production caller set them either, so `/etc/reconftw/config.toml`,
// `~/.config/reconftw/config.toml` and — worst — **`./reconftw.toml`** were never read.
// Only `--config FILE` had any effect.
//
// That is the exact file `reconftw migrate` writes by default, so the documented
// v1→v2 quick start produced a config the binary silently ignored.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// chdir moves into dir for the duration of the test.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if cerr := os.Chdir(dir); cerr != nil {
		t.Fatalf("chdir: %v", cerr)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}

// A reconftw.toml in the working directory must be loaded WITHOUT --config.
func TestProjectConfigIsAutoDiscovered(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "reconftw.toml"),
		[]byte("[output]\nlog_level = \"debug\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdir(t, dir)

	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.LogLevel != "debug" {
		t.Errorf("cfg.Output.LogLevel = %q, want %q from ./reconftw.toml\n"+
			"(the project layer was never resolved, so a config in the working directory "+
			"— the one `reconftw migrate` writes — was silently ignored)",
			cfg.Output.LogLevel, "debug")
	}
}

// The user layer resolves to the DOCUMENTED ~/.config path on every platform,
// honouring XDG_CONFIG_HOME. os.UserConfigDir would relocate it on macOS.
func TestUserConfigLayerUsesXDGPath(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	userCfg := filepath.Join(xdg, "reconftw", "config.toml")
	if err := os.MkdirAll(filepath.Dir(userCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userCfg, []byte("[output]\nlog_level = \"warn\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdir(t, t.TempDir()) // no project config in the way

	var opts config.LoadOptions
	config.ResolveDefaultPaths(&opts)
	if opts.UserPath != userCfg {
		t.Fatalf("user layer resolved to %q, want %q", opts.UserPath, userCfg)
	}

	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.LogLevel != "warn" {
		t.Errorf("cfg.Output.LogLevel = %q, want %q from the user layer", cfg.Output.LogLevel, "warn")
	}
}

// Precedence must hold: project (4) beats user (3), and --config (5) beats project.
func TestConfigLayerPrecedence(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)
	userCfg := filepath.Join(xdg, "reconftw", "config.toml")
	if err := os.MkdirAll(filepath.Dir(userCfg), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userCfg, []byte("[output]\nlog_level = \"warn\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	proj := t.TempDir()
	if err := os.WriteFile(filepath.Join(proj, "reconftw.toml"),
		[]byte("[output]\nlog_level = \"info\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	chdir(t, proj)

	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.LogLevel != "info" {
		t.Errorf("project layer should beat user layer: got %q, want \"info\"", cfg.Output.LogLevel)
	}

	explicit := filepath.Join(t.TempDir(), "explicit.toml")
	if err := os.WriteFile(explicit, []byte("[output]\nlog_level = \"error\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(config.LoadOptions{ExplicitConfigPath: explicit})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Output.LogLevel != "error" {
		t.Errorf("--config should beat the project layer: got %q, want \"error\"", cfg.Output.LogLevel)
	}
}

// An explicitly-supplied path must never be overwritten by auto-discovery —
// that is how tests isolate themselves from the host filesystem.
func TestResolveDefaultPathsRespectsExplicitValues(t *testing.T) {
	opts := config.LoadOptions{
		SystemPath:  "/custom/system.toml",
		UserPath:    "/custom/user.toml",
		ProjectPath: "/custom/project.toml",
	}
	config.ResolveDefaultPaths(&opts)
	if opts.SystemPath != "/custom/system.toml" ||
		opts.UserPath != "/custom/user.toml" ||
		opts.ProjectPath != "/custom/project.toml" {
		t.Errorf("explicit paths were overwritten: %+v", opts)
	}
}
