// Property-based loader test (Ring 4 — ADR §9.1).
// Uses pgregory.net/rapid to fuzz the validator with thousands of structured
// inputs; the invariant is "Validate never panics, and either passes or
// returns *ConfigError — never an arbitrary error type."
//
// External test package.
package config_test

import (
	stderrors "errors"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"pgregory.net/rapid"
)

// TestValidate_PropertyNoPanic is the Ring 4 fuzz: for any structurally
// well-typed Config, Validate must not panic and must return either nil or
// an *errors.ConfigError. This catches reflect-driven crashes inside the
// validator translation layer.
func TestValidate_PropertyNoPanic(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cfg := config.Defaults()
		// Fuzz a handful of constrained numeric/string fields. We deliberately
		// stay within Go-type boundaries (no float-NaN injection — the validator
		// has no float fields exposed to TOML at the leaves we touch). The
		// invariant is structural, not value-correctness.
		cfg.Concurrency.MaxJobs = rapid.IntRange(-10, 200).Draw(t, "MaxJobs")
		cfg.Concurrency.HeartbeatSeconds = rapid.IntRange(-10, 5000).Draw(t, "Heartbeat")
		cfg.Concurrency.LogMode = rapid.SampledFrom([]string{"summary", "tail", "full", "", "garbage"}).Draw(t, "LogMode")
		cfg.Web.Probe.RateLimit = rapid.IntRange(-1, 50000).Draw(t, "RateLimit")
		cfg.Web.Probe.TimeoutSeconds = rapid.IntRange(0, 1000).Draw(t, "TimeoutSeconds")
		cfg.Web.Nuclei.Severity = rapid.SampledFrom([]string{
			"info", "info,low", "low,medium,high", "info,low,medium,high,critical",
			"", "BAD", "info,unknown",
		}).Draw(t, "Severity")
		cfg.MCP.Port = rapid.IntRange(0, 70000).Draw(t, "Port")
		cfg.MCP.Transport = rapid.SampledFrom([]string{"stdio", "http", "", "tcp"}).Draw(t, "Transport")
		cfg.Notifications.Slack.WebhookURL = rapid.SampledFrom([]string{
			"", "https://hooks.slack.com/services/aaa/bbb/ccc",
			"http://not-https.example.com/", "not-a-url",
		}).Draw(t, "Webhook")
		cfg.Paths.Resolvers = rapid.SampledFrom([]string{
			"", "/etc/resolvers.txt", "../etc/passwd", "/a/./b",
		}).Draw(t, "Resolvers")
		cfg.Integrations.Proxy.URL = rapid.SampledFrom([]string{
			"", "http://127.0.0.1:8080/", "https://corp.proxy/", "file:///etc/passwd", "ftp://x/",
		}).Draw(t, "ProxyURL")

		err := config.Validate(cfg)
		if err == nil {
			return // valid input: pass
		}
		// If non-nil, it MUST be *errors.ConfigError (and Is(ErrConfig)).
		var ce *coreerrors.ConfigError
		if !stderrors.As(err, &ce) {
			t.Fatalf("Validate returned non-ConfigError type %T: %v", err, err)
		}
		if !stderrors.Is(err, coreerrors.ErrConfig) {
			t.Fatalf("Validate returned ConfigError but Is(ErrConfig)=false: %v", err)
		}
	})
}

// TestLoadRoundtrip_Property fuzzes the Load entry point on synthetic TOML
// strings. For ANY input that does not parse, Load must return an error with
// no panic. For inputs that parse + validate clean, Load must return a non-nil
// *Config. This is a structural invariant test, not a value-correctness one.
func TestLoadRoundtrip_Property(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a small TOML body within known-safe schema choices.
		maxJobs := rapid.IntRange(-5, 100).Draw(t, "max_jobs")
		body := genMinimalTOML(maxJobs)

		tmp := t.TempDir() + "/cfg.toml"
		if err := writeFile(tmp, body); err != nil {
			t.Fatalf("write: %v", err)
		}
		cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: tmp})
		if err != nil {
			var ce *coreerrors.ConfigError
			if !stderrors.As(err, &ce) {
				t.Fatalf("Load returned non-ConfigError type %T: %v", err, err)
			}
			return
		}
		if cfg == nil {
			t.Fatal("Load returned nil cfg AND nil err")
		}
	})
}

// helpers (not exported — keep in test file).

func genMinimalTOML(maxJobs int) []byte {
	return []byte("[concurrency]\nmax_jobs = " + itoa(maxJobs) + "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	if neg {
		return "-" + digits
	}
	return digits
}

func writeFile(path string, data []byte) error {
	return writeFileImpl(path, data)
}
