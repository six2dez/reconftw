// 8-source layered config loader (ADR §2.3).
//
// Source precedence (later wins):
//   1. Defaults() — canonical defaults from ADR §2.2
//   2. /etc/reconftw/config.toml — system-wide
//   3. ~/.config/reconftw/config.toml — user
//   4. ./reconftw.toml — project
//   5. --config FILE — explicit override
//   6. secrets.toml — opaque secret material
//   7. RECONFTW_* env vars — RECONFTW_CONCURRENCY_MAX_JOBS=12
//   8. CLI overrides — flag-driven map (Plan 03-05 will populate)
//
// All files are loaded with knadh/koanf/v2 + TOML parser. The competing
// config library banned in ADR §2.1 lines 279-282 is FORBIDDEN here (key
// lowercasing breaks [legacy] table).
//
// Legacy table mechanism: after merge, iterate cfg.Legacy and translate each
// UPPER_CASE key to its v2-native equivalent via legacyAliasMap. If the
// v2-native key is already set non-default, emit a WARN and keep v2-native
// (per ADR §2.3 lines 1039-1055). Plan 02 ships a 5-entry corpus per W18;
// Phase 11 migrator ships the full ~290-entry enumeration.

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/knadh/koanf/parsers/toml/v2"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// LoadOptions controls the 8-source precedence chain. Tests inject explicit
// paths (no env discovery from $HOME or $XDG_CONFIG_HOME); production code
// fills these from CLI flags via Plan 03-05.
type LoadOptions struct {
	// SystemPath is layer 2 (/etc/reconftw/config.toml). Empty = use the
	// platform default; pass an explicit value in tests for isolation.
	SystemPath string
	// UserPath is layer 3 (~/.config/reconftw/config.toml).
	UserPath string
	// ProjectPath is layer 4 (./reconftw.toml).
	ProjectPath string
	// ExplicitConfigPath is layer 5 (--config FILE).
	ExplicitConfigPath string
	// SecretsPath is layer 6 (secrets.toml).
	SecretsPath string
	// CLIOverrides is layer 8 — a sparse map of fully-qualified koanf keys
	// (e.g. "concurrency.max_jobs"). Plan 05 populates from cobra flags.
	CLIOverrides map[string]any
	// WarnSink receives human-readable WARN lines (one per dropped or
	// colliding key). Defaults to os.Stderr if nil. Tests inject a buffer.
	WarnSink io.Writer
	// EnvironFunc is the env-var source. Default os.Environ. Tests can
	// inject deterministic input. (Plumbing for future use; current
	// implementation defers to t.Setenv which is sufficient.)
	EnvironFunc func() []string
}

// ResolveDefaultPaths fills in the auto-discovered config layers (2 system,
// 3 user, 4 project) that the caller left empty.
//
// These three layers were documented in the header, in LoadOptions ("Empty = use
// the platform default"), and in the ADR — but nothing ever resolved them, and no
// production caller set them. So `/etc/reconftw/config.toml`,
// `~/.config/reconftw/config.toml` and, worst of all, **`./reconftw.toml` were
// never read**: a config dropped in the working directory was silently ignored and
// only `--config FILE` had any effect. That is precisely the file `reconftw migrate`
// writes by default, so the documented v1→v2 quick start produced a config nothing
// loaded.
//
// Exported so `reconftw config` can report the same paths the loader will use.
// A caller that wants isolation (tests) passes explicit paths, which are respected
// as-is; only empty fields are filled.
func ResolveDefaultPaths(opts *LoadOptions) {
	if opts == nil {
		return
	}
	if opts.SystemPath == "" {
		opts.SystemPath = filepath.Join(string(filepath.Separator), "etc", "reconftw", "config.toml")
	}
	if opts.UserPath == "" {
		// XDG semantics on EVERY platform, deliberately not os.UserConfigDir: the
		// documented path is ~/.config/reconftw/config.toml, and os.UserConfigDir
		// would silently relocate it to ~/Library/Application Support on macOS —
		// a different path from the one the docs, the Docker image and every Linux
		// install use. An unset HOME leaves the layer empty and it is skipped.
		if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
			opts.UserPath = filepath.Join(dir, "reconftw", "config.toml")
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			opts.UserPath = filepath.Join(home, ".config", "reconftw", "config.toml")
		}
	}
	if opts.ProjectPath == "" {
		opts.ProjectPath = "reconftw.toml"
	}
}

// Load runs the 8-source merge chain and returns a fully-validated *Config.
// On validation failure, the returned error wraps *errors.ConfigError so
// callers can use errors.As / errors.Is(err, ErrConfig).
//
// SECURITY: the returned error NEVER contains raw secret values. See
// translateValidationError below.
func Load(opts LoadOptions) (*Config, error) {
	if opts.WarnSink == nil {
		opts.WarnSink = os.Stderr
	}
	ResolveDefaultPaths(&opts)

	k := koanf.New(".")

	// Layer 1: defaults from Defaults() → flatten via struct provider.
	defaultsK := koanf.New(".")
	if err := defaultsK.Load(structsProvider(Defaults()), nil); err != nil {
		return nil, fmt.Errorf("config: load defaults: %w", err)
	}
	if err := k.Merge(defaultsK); err != nil {
		return nil, fmt.Errorf("config: merge defaults: %w", err)
	}

	// Layers 2-6: TOML files.
	//
	// A missing file is never fatal — the silent-skip→nil contract holds at
	// every layer (a missing /etc/reconftw/config.toml is the normal case).
	// But the two explicit layers (--config / --secrets) are named by the
	// operator, so a missing one is almost certainly a typo: emit a WARN to the
	// sink before skipping. The auto-discovered layers (system/user/project)
	// stay silent. Because parseEarlyFlags leaves the --config/--secrets paths
	// empty when the flag is absent (cmd/reconftw/main_test.go), the p=="" guard
	// already separates "flag not passed" (silent) from "flag passed but file
	// missing" (warn) — no extra LoadOptions field is needed.
	fileLayers := []struct {
		path string
		flag string // non-empty ⇒ explicit (operator-named --config/--secrets) layer
	}{
		{opts.SystemPath, ""},
		{opts.UserPath, ""},
		{opts.ProjectPath, ""},
		{opts.ExplicitConfigPath, "--config"},
		{opts.SecretsPath, "--secrets"},
	}
	for _, layer := range fileLayers {
		p := layer.path
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); os.IsNotExist(err) {
			if layer.flag != "" {
				fmt.Fprintf(opts.WarnSink, "WARN config: %s file %q not found — skipped\n", layer.flag, p)
			}
			// Silent skip — file may legitimately not exist (auto-discovered layer).
			continue
		} else if err != nil {
			return nil, fmt.Errorf("config: stat %s: %w", p, err)
		}
		if err := k.Load(file.Provider(p), toml.Parser()); err != nil {
			return nil, fmt.Errorf("config: parse %s: %w", p, err)
		}
	}

	// Layer 7: RECONFTW_* env vars.
	//   RECONFTW_CONCURRENCY_MAX_JOBS=12 → concurrency.max_jobs = 12
	envOpt := env.Opt{
		Prefix:        "RECONFTW_",
		EnvironFunc:   opts.EnvironFunc,
		TransformFunc: envKeyToKoanfKey,
	}
	if err := k.Load(env.Provider(".", envOpt), nil); err != nil {
		return nil, fmt.Errorf("config: load env: %w", err)
	}

	// Layer 8: CLI overrides.
	if len(opts.CLIOverrides) > 0 {
		if err := k.Load(confmap.Provider(opts.CLIOverrides, "."), nil); err != nil {
			return nil, fmt.Errorf("config: load CLI overrides: %w", err)
		}
	}

	// Unmarshal koanf state into a fresh *Config.
	cfg := Defaults() // start from defaults so any unset nested sub-struct keeps its default values
	unmarshalOpts := koanf.UnmarshalConf{
		Tag:           "koanf",
		DecoderConfig: nil,
	}
	if err := k.UnmarshalWithConf("", cfg, unmarshalOpts); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	// Apply [legacy] table — translate UPPER_CASE keys to v2-native keys.
	applyLegacyAliases(cfg, opts.WarnSink)

	// Validate post-merge.
	if err := Validate(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// envKeyToKoanfKey converts RECONFTW_CONCURRENCY_MAX_JOBS → concurrency.max_jobs.
// Strips the prefix, lowercases, then converts the first underscore (top-level
// section separator) by leaving underscores alone within names — koanf's
// flat-key convention uses '.' as a delimiter, not '_'.
//
// Strategy: strip "RECONFTW_" prefix, lowercase, then split by underscores and
// walk the Config struct's koanf-tag tree to determine the right "." insertion
// points. Implementation here uses a simpler rule: replace every underscore
// with "." unless the resulting key collides with a known nested field name.
// For Phase 3 we use the most common shape — the first underscore after a
// known section name (concurrency, web, vulns, etc.) becomes ".". All
// subsequent underscores stay literal.
//
// This is intentionally restrictive — env-var-based overrides are a power-user
// feature and the documented form is RECONFTW_<SECTION>_<FIELD_NAME>. Phase 5
// (CLI) may add a smarter mapping if needed.
func envKeyToKoanfKey(k, v string) (string, any) {
	if !strings.HasPrefix(k, "RECONFTW_") {
		return "", nil
	}
	rest := strings.TrimPrefix(k, "RECONFTW_")
	if rest == "" {
		return "", nil
	}
	rest = strings.ToLower(rest)
	// Known top-level section names — the first underscore after one of these
	// becomes a "." (section separator). All later underscores stay literal,
	// matching koanf-tag names like "max_jobs", "rate_limit", etc.
	sections := []string{
		"concurrency", "subdomains", "web", "vulns", "osint", "notifications",
		"axiom", "mcp", "scheduler", "output", "ai", "integrations",
		"incremental", "monitor", "adaptive_rate", "cache", "paths",
		"api_keys", "advanced",
	}
	for _, s := range sections {
		prefix := s + "_"
		if strings.HasPrefix(rest, prefix) {
			return s + "." + rest[len(prefix):], v
		}
		if rest == s {
			return s, v
		}
	}
	// Unrecognised — drop (do not pollute koanf with arbitrary env vars).
	return "", nil
}

// applyLegacyAliases walks cfg.Legacy and merges each entry into the v2-native
// equivalent via legacyAliasMap. On collision (v2-native key already set to a
// non-default value), v2-native wins and a WARN line is written to sink.
//
// Plan 02 ships a 5-entry corpus per W18 (the test fixture exercises all
// five). Phase 11 migrator ships the full ~290-entry table.
func applyLegacyAliases(cfg *Config, sink io.Writer) {
	if len(cfg.Legacy) == 0 {
		return
	}
	defaults := Defaults()
	for legacyKey, value := range cfg.Legacy {
		nativePath, ok := legacyAliasMap[legacyKey]
		if !ok {
			fmt.Fprintf(sink, "WARN config: legacy.%s has no v2-native mapping (drop)\n", legacyKey)
			continue
		}
		currentNative, defaultNative := readByPath(cfg, nativePath), readByPath(defaults, nativePath)
		// Collision: v2-native already set to non-default → v2-native wins.
		if currentNative != nil && !sameValue(currentNative, defaultNative) {
			fmt.Fprintf(sink,
				"WARN config: legacy.%s=%v and %s=%v both set — using %s=%v (v2-native wins per ADR §2.3)\n",
				legacyKey, value, nativePath, currentNative, nativePath, currentNative)
			continue
		}
		// No collision — apply the legacy value to the native path.
		if err := writeByPath(cfg, nativePath, value); err != nil {
			fmt.Fprintf(sink, "WARN config: legacy.%s: cannot set %s: %v\n", legacyKey, nativePath, err)
		}
	}
}

// sameValue returns true if a and b are scalar-equal. Used by the collision
// detector to distinguish "user wrote v2-native key X = default value" (no
// collision) from "user wrote v2-native key X = non-default value" (collision).
func sameValue(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// DefaultConfigDir resolves the platform-default user config file location.
// Returns "" when neither XDG_CONFIG_HOME nor $HOME is resolvable. Plan 05
// wires this into the CLI as the UserPath default; Plan 02 exposes it so
// callers (and tests) can rely on a single definition.
//
// SECURITY: never logs the home directory at INFO level — would leak the
// operator's username into shipped reports.
func DefaultConfigDir() string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "reconftw", "config.toml")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".config", "reconftw", "config.toml")
	}
	return ""
}
