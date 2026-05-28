// Tests for Validate() and the 3 custom validators.
// External test package.
package config_test

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// --- Test 4: nopath_traversal — rejects ".." sequences ---

func TestNoPathTraversal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty string is ok", "", false},
		{"absolute path with no traversal", "/etc/reconftw/resolvers.txt", false},
		{"relative path with no traversal", "resolvers.txt", false},
		{"obvious traversal", "../../etc/passwd", true},
		{"embedded ..", "/etc/../etc/passwd", true},
		{"trailing /..", "/var/data/..", true},
		{"path with dots that are not traversal", "/a/.hidden", false},
		{"path with single .", "/a/./b", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Paths.Resolvers = tc.path
			err := config.Validate(cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(paths.resolvers=%q) err=%v; wantErr=%v", tc.path, err, tc.wantErr)
			}
		})
	}
}

// --- Test 5: nuclei_severity — CSV of {info,low,medium,high,critical} ---

func TestNucleiSeverity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity string
		wantErr  bool
	}{
		{"single info", "info", false},
		{"all five", "info,low,medium,high,critical", false},
		{"single critical", "critical", false},
		{"with spaces", "info, low, medium", false},
		{"bad severity word", "info,low,xxx", true},
		{"capital case rejected", "Info,Low", true},
		{"empty allowed (omitempty pairing in tag)", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Web.Nuclei.Severity = tc.severity
			err := config.Validate(cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(web.nuclei.severity=%q) err=%v; wantErr=%v", tc.severity, err, tc.wantErr)
			}
		})
	}
}

// --- Test 6: oneof_scheme=http https ---

func TestOneofScheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"http allowed", "http://127.0.0.1:8080/", false},
		{"https allowed", "https://proxy.example.com:8443/", false},
		{"file:// rejected", "file:///etc/passwd", true},
		{"gopher:// rejected", "gopher://attacker.example.com/", true},
		{"javascript: rejected", "javascript:alert(1)", true},
		{"no scheme rejected", "127.0.0.1:8080/", true},
		{"empty ok (omitempty)", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Integrations.Proxy.URL = tc.url
			err := config.Validate(cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(integrations.proxy.url=%q) err=%v; wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}
}

// --- Test: Validate succeeds on canonical Defaults() ---

func TestValidateDefaults(t *testing.T) {
	t.Parallel()
	if err := config.Validate(config.Defaults()); err != nil {
		t.Fatalf("Validate(Defaults()) = %v; want nil", err)
	}
}

// --- Test: Validation error messages have stable shape ---

func TestValidateErrorShape(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Concurrency.MaxJobs = 0 // min=1
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("Validate(max_jobs=0) returned nil; want error")
	}
	// Must include the key path.
	if !strings.Contains(err.Error(), "max_jobs") && !strings.Contains(err.Error(), "MaxJobs") {
		t.Errorf("error does not identify the key: %s", err.Error())
	}
	// Must NOT include "value 0 too small" or other phrasing that leaks the raw value;
	// this is a small validation gate that applies primarily to secret fields, but we
	// still want the message to be human-readable.
	if !strings.Contains(strings.ToLower(err.Error()), "min") && !strings.Contains(strings.ToLower(err.Error()), "validation") {
		t.Errorf("error is not informative: %s", err.Error())
	}
}
