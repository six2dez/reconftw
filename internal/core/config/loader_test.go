// Tests for the 8-source layered loader (ADR §2.3).
// External test package.
package config_test

import (
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// helper: copy a fixture TOML into a temp file so the loader can read it
func copyFixtureTo(t *testing.T, src, dst string) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write fixture to %s: %v", dst, err)
	}
}

// --- Test 1: 8-source precedence — each later source overrides earlier ---
//
// Step through each source level, asserting the resolved Concurrency.MaxJobs
// matches the highest-priority source that has set it.
func TestEightSourcePrecedence(t *testing.T) {
	// Cannot use t.Parallel here — sub-cases call t.Setenv.
	tmp := t.TempDir()
	fixtures := "testdata"

	// Layer 2: system. Defaults() max_jobs=4 → system.toml says 8.
	systemPath := filepath.Join(tmp, "system.toml")
	copyFixtureTo(t, filepath.Join(fixtures, "system.toml"), systemPath)

	// Layer 3: user.
	userPath := filepath.Join(tmp, "user.toml")
	copyFixtureTo(t, filepath.Join(fixtures, "user.toml"), userPath)

	// Layer 4: project (./reconftw.toml).
	projectPath := filepath.Join(tmp, "project.toml")
	copyFixtureTo(t, filepath.Join(fixtures, "project.toml"), projectPath)

	// Layer 5: --config FILE (cli explicit).
	cliPath := filepath.Join(tmp, "cli.toml")
	copyFixtureTo(t, filepath.Join(fixtures, "cli.toml"), cliPath)

	// Layer 6: secrets.toml (different keys; preserves max_jobs from layer 5)
	secretsPath := filepath.Join(tmp, "secrets.toml")
	copyFixtureTo(t, filepath.Join(fixtures, "secrets.toml"), secretsPath)

	tests := []struct {
		name    string
		opts    config.LoadOptions
		env     map[string]string
		wantMax int
	}{
		{
			name:    "defaults only",
			opts:    config.LoadOptions{},
			wantMax: 4,
		},
		{
			name:    "system overrides defaults",
			opts:    config.LoadOptions{SystemPath: systemPath},
			wantMax: 8,
		},
		{
			name:    "user overrides system",
			opts:    config.LoadOptions{SystemPath: systemPath, UserPath: userPath},
			wantMax: 9,
		},
		{
			name:    "project overrides user",
			opts:    config.LoadOptions{SystemPath: systemPath, UserPath: userPath, ProjectPath: projectPath},
			wantMax: 10,
		},
		{
			name:    "cli --config overrides project",
			opts:    config.LoadOptions{SystemPath: systemPath, UserPath: userPath, ProjectPath: projectPath, ExplicitConfigPath: cliPath},
			wantMax: 11,
		},
		{
			name:    "secrets does not touch max_jobs",
			opts:    config.LoadOptions{SystemPath: systemPath, UserPath: userPath, ProjectPath: projectPath, ExplicitConfigPath: cliPath, SecretsPath: secretsPath},
			wantMax: 11,
		},
		{
			name: "RECONFTW_CONCURRENCY_MAX_JOBS env var overrides secrets",
			opts: config.LoadOptions{SystemPath: systemPath, UserPath: userPath, ProjectPath: projectPath, ExplicitConfigPath: cliPath, SecretsPath: secretsPath},
			env:  map[string]string{"RECONFTW_CONCURRENCY_MAX_JOBS": "12"},
			wantMax: 12,
		},
		{
			name: "CLI override wins over env",
			opts: config.LoadOptions{
				SystemPath:         systemPath,
				UserPath:           userPath,
				ProjectPath:        projectPath,
				ExplicitConfigPath: cliPath,
				SecretsPath:        secretsPath,
				CLIOverrides:       map[string]any{"concurrency.max_jobs": 16},
			},
			env:     map[string]string{"RECONFTW_CONCURRENCY_MAX_JOBS": "12"},
			wantMax: 16,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg, err := config.Load(tc.opts)
			if err != nil {
				t.Fatalf("Load() err = %v", err)
			}
			if cfg.Concurrency.MaxJobs != tc.wantMax {
				t.Errorf("Concurrency.MaxJobs = %d; want %d", cfg.Concurrency.MaxJobs, tc.wantMax)
			}
		})
	}
}

// --- Test 2: Load returns *ConfigError on validation failure ---

func TestLoadReturnsConfigErrorOnValidation(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "invalid_url.toml")
	copyFixtureTo(t, filepath.Join("testdata", "invalid_url.toml"), bad)

	cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: bad})
	if err == nil {
		t.Fatalf("Load() err = nil; want validation failure; cfg = %+v", cfg)
	}
	var ce *coreerrors.ConfigError
	if !stderrors.As(err, &ce) {
		t.Fatalf("err is not *ConfigError: %T %v", err, err)
	}
	if !stderrors.Is(err, coreerrors.ErrConfig) {
		t.Errorf("errors.Is(err, ErrConfig) = false; want true")
	}
}

// --- Test 3: ConfigError message does NOT leak the raw secret value ---
// This is the PITFALL §2 / ADR §6 SECURITY NOTE gate.

func TestSecretRedactionInError(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "invalid_url.toml")
	copyFixtureTo(t, filepath.Join("testdata", "invalid_url.toml"), bad)

	_, err := config.Load(config.LoadOptions{ExplicitConfigPath: bad})
	if err == nil {
		t.Fatal("Load() err = nil; want validation failure")
	}
	const sentinel = "REDACT_THIS_SENTINEL_VALUE_abcdef123"
	msg := err.Error()
	if strings.Contains(msg, sentinel) {
		t.Errorf("error message leaked raw secret value: %q\nfull: %s", sentinel, msg)
	}
	// And the error MUST identify the key.
	if !strings.Contains(msg, "webhook_url") && !strings.Contains(msg, "WebhookURL") {
		t.Errorf("error does not identify the offending key in any form: %s", msg)
	}
}

// --- Test 7: [legacy] table aliases map to v2-native keys ---

func TestLegacyAliasResolution(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	leg := filepath.Join(tmp, "legacy_alias.toml")
	copyFixtureTo(t, filepath.Join("testdata", "legacy_alias.toml"), leg)

	cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: leg})
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	// PARALLEL_MAX_JOBS=8 → concurrency.max_jobs (legacyAliasMap mechanism)
	if cfg.Concurrency.MaxJobs != 8 {
		t.Errorf("legacy PARALLEL_MAX_JOBS=8 did not map to concurrency.max_jobs; got %d", cfg.Concurrency.MaxJobs)
	}
	// OSINT=true → osint.enabled
	if !cfg.OSINT.Enabled {
		t.Errorf("legacy OSINT=true did not map to osint.enabled")
	}
	// SUBDOMAINS_GENERAL=false → subdomains.enabled=false
	if cfg.Subdomains.Enabled {
		t.Errorf("legacy SUBDOMAINS_GENERAL=false did not map to subdomains.enabled=false")
	}
	// AXIOM_FLEET_COUNT=20 → axiom.fleet_count
	if cfg.Axiom.FleetCount != 20 {
		t.Errorf("legacy AXIOM_FLEET_COUNT=20 did not map to axiom.fleet_count; got %d", cfg.Axiom.FleetCount)
	}
	// SHODAN_API_KEY → api_keys.shodan (Secret-typed)
	if string(cfg.APIKeys.Shodan) != "test-legacy-shodan-key-aaa-12345" {
		t.Errorf("legacy SHODAN_API_KEY did not map to api_keys.shodan; got %q", string(cfg.APIKeys.Shodan))
	}
}

// --- Test: [legacy] vs v2-native collision — v2-native wins, WARN emitted ---

func TestLegacyAliasCollision(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	leg := filepath.Join(tmp, "legacy_collision.toml")
	copyFixtureTo(t, filepath.Join("testdata", "legacy_collision.toml"), leg)

	// Capture WARN log output via a buffer + LoadOptions.WarnSink.
	var sink strings.Builder
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: leg,
		WarnSink:           &sink,
	})
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	// v2-native max_jobs=12 must win over legacy PARALLEL_MAX_JOBS=8.
	if cfg.Concurrency.MaxJobs != 12 {
		t.Errorf("v2-native did not win collision: max_jobs = %d; want 12", cfg.Concurrency.MaxJobs)
	}
	// WARN must reference both keys.
	out := sink.String()
	if !strings.Contains(out, "PARALLEL_MAX_JOBS") || !strings.Contains(out, "concurrency.max_jobs") {
		t.Errorf("WARN sink does not name both colliding keys: %q", out)
	}
}

// --- Test 9: RECONFTW_* env vars override defaults ---
// (Covered as a sub-case of TestEightSourcePrecedence above; kept as a focused test for clarity.)

func TestEnvVarOverridesDefault(t *testing.T) {
	// Cannot use t.Parallel — t.Setenv requires sequential execution.
	t.Setenv("RECONFTW_CONCURRENCY_MAX_JOBS", "13")
	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	if cfg.Concurrency.MaxJobs != 13 {
		t.Errorf("env var did not override default; got %d; want 13", cfg.Concurrency.MaxJobs)
	}
}

// --- Test: Load succeeds on a valid minimal file ---

func TestLoadValidMinimal(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	dst := filepath.Join(tmp, "valid_minimal.toml")
	copyFixtureTo(t, filepath.Join("testdata", "valid_minimal.toml"), dst)

	cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: dst})
	if err != nil {
		t.Fatalf("Load() err = %v", err)
	}
	if cfg.Concurrency.MaxJobs != 5 {
		t.Errorf("Concurrency.MaxJobs = %d; want 5", cfg.Concurrency.MaxJobs)
	}
}
