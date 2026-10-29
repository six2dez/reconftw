package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreerrors "github.com/six2dez/reconftw/v5/internal/core/errors"
)

// TestValidateScopeFilesReadableWhenSet: subdomains.scope.include_file /
// exclude_file must name readable regular files when set; the error names the
// key and never the path.
func TestValidateScopeFilesReadableWhenSet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ok := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(ok, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretish := filepath.Join(dir, "missing-hunter2.txt")

	cfg := Defaults()
	if err := Validate(cfg); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}

	cfg.Subdomains.Scope.IncludeFile = ok
	cfg.Subdomains.Scope.ExcludeFile = ok
	if err := Validate(cfg); err != nil {
		t.Fatalf("readable lists must validate: %v", err)
	}

	cfg.Subdomains.Scope.ExcludeFile = secretish
	err := Validate(cfg)
	if err == nil {
		t.Fatal("missing exclude_file must fail validation")
	}
	var ce *coreerrors.ConfigError
	if !stdAs(err, &ce) {
		t.Fatalf("want *ConfigError, got %T: %v", err, err)
	}
	if ce.Key != "subdomains.scope.exclude_file" {
		t.Errorf("Key = %q, want subdomains.scope.exclude_file", ce.Key)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks the path value: %q", err.Error())
	}

	cfg.Subdomains.Scope.ExcludeFile = ""
	cfg.Subdomains.Scope.IncludeFile = dir // a directory is not a scope list
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "include_file") {
		t.Fatalf("directory as include_file must fail naming the key, got %v", err)
	}
}

// TestMigratorSupersedesUnwiredToolKnobs pins Problem A's migrator side: the v1
// keys whose advanced.tools.* targets were deleted must be superseded (Case B)
// rather than mapped to a key that no longer exists, and HTTPX/puredns/gf/dalfox
// keep (or gain) a first-class home.
func TestMigratorSupersedesUnwiredToolKnobs(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"XNLINKFINDER_DEPTH", "INTERLACE_THREADS", "AXIOM_POST_START", "DALFOX_THREADS"} {
		if _, mapped := legacyAliasMap[k]; mapped {
			t.Errorf("%s still in legacyAliasMap", k)
		}
		if _, ok := supersededKeys[k]; !ok {
			t.Errorf("%s missing from supersededKeys", k)
		}
	}
	if supersededKeys["DALFOX_THREADS"].pin != "vulns.xss.threads" {
		t.Errorf("DALFOX_THREADS pin = %q, want vulns.xss.threads (what dalfox -w reads)", supersededKeys["DALFOX_THREADS"].pin)
	}
	for k, want := range map[string]string{
		"HTTPX_RATELIMIT": "web.probe.rate_limit",
		"HTTPX_TIMEOUT":   "web.probe.timeout_seconds",
		"PATTERNS_DIR":    "paths.patterns_dir",
		"resolvers":       "paths.resolvers",
		"GOTATOR_FLAGS":   "advanced.tools.gotator.flags",
		"TLSX_THREADS":    "advanced.tools.tlsx.threads",
	} {
		if got := legacyAliasMap[k]; got != want {
			t.Errorf("legacyAliasMap[%s] = %q, want %q", k, got, want)
		}
	}
	for _, path := range []string{
		"advanced.tools.nuclei", "advanced.tools.puredns", "advanced.tools.gf", "advanced.tools.dalfox",
		"advanced.tools.xnlinkfinder", "advanced.tools.interlace", "advanced.tools.axiom.post_start",
		"advanced.tools.httpx.rate_limit", "advanced.tools.httpx.threads", "advanced.tools.httpx.timeout_seconds",
	} {
		for k, v := range legacyAliasMap {
			if strings.HasPrefix(v, path) {
				t.Errorf("legacyAliasMap[%s] = %q targets a deleted field", k, v)
			}
		}
	}
}
