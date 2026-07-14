// Tests for the Config struct shape and Defaults() canonical values.
// Source: ADR 0002 §2.2 (BINDING — v2-native schema with defaults).
//
// External test package — exercises Config + Defaults() only through the
// exported API (no internal field access via reflect that requires lowercase).
package config_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
)

// --- Test 1: Zero-value Config compiles + has expected nested shape ---

func TestConfigZeroValueShape(t *testing.T) {
	t.Parallel()
	var c config.Config

	// Top-level fields must be addressable as struct fields, not map keys.
	// If any of these don't compile, the schema is wrong.
	_ = c.Concurrency
	_ = c.Subdomains
	_ = c.Web
	_ = c.Vulns
	_ = c.OSINT
	_ = c.Notifications
	_ = c.Axiom
	_ = c.MCP
	_ = c.Scheduler
	_ = c.Output
	_ = c.AI
	_ = c.Advanced
	_ = c.Paths
	_ = c.APIKeys
	_ = c.Integrations
	_ = c.Incremental
	_ = c.Monitor
	_ = c.AdaptiveRate
	_ = c.Cache
	_ = c.Legacy // map[string]any
}

// --- Test 2: All canonical secret fields are typed log.Secret ---

func TestSecretFieldsTyped(t *testing.T) {
	t.Parallel()
	var c config.Config

	// Each secret field assignment uses log.Secret on the RHS — the assignment
	// only compiles if the LHS field type is exactly log.Secret. This is a
	// compile-time check + a runtime sanity check on the LogValue() path.
	c.Notifications.Slack.WebhookURL = log.Secret("test-slack-secret-1234567890")
	c.Notifications.Telegram.BotToken = log.Secret("test-telegram-token-1234567890")
	c.Notifications.Discord.WebhookURL = log.Secret("test-discord-secret-1234567890")
	c.AI.OpenAIKey = log.Secret("test-openai-key-1234567890")
	c.AI.AnthropicKey = log.Secret("test-anthropic-key-1234567890")
	c.MCP.APIKey = log.Secret("test-mcp-apikey-1234567890")
	c.APIKeys.Shodan = log.Secret("test-shodan-key-1234567890")
	c.APIKeys.WhoisXML = log.Secret("test-whoisxml-key-1234567890")
	c.APIKeys.PDCP = log.Secret("test-pdcp-key-1234567890")

	// Sanity: each Secret-typed value must auto-redact in slog output.
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("test",
		slog.Any("slack", c.Notifications.Slack.WebhookURL),
		slog.Any("telegram", c.Notifications.Telegram.BotToken),
		slog.Any("discord", c.Notifications.Discord.WebhookURL),
	)
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("not valid JSON: %v\nraw: %s", err, buf.String())
	}
	for _, key := range []string{"slack", "telegram", "discord"} {
		if got := m[key]; got != "***" {
			t.Errorf("attr %q = %v; want %q (LogValue redaction did not fire)", key, got, "***")
		}
	}
}

// --- Test 3: Defaults() returns canonical values from ADR §2.2 ---

func TestDefaults(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	if cfg == nil {
		t.Fatal("Defaults() returned nil")
	}

	// Spot-check the canonical defaults from ADR §2.2 + §2.5.
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Concurrency.MaxJobs", cfg.Concurrency.MaxJobs, 4},
		{"Concurrency.HeartbeatSeconds", cfg.Concurrency.HeartbeatSeconds, 20},
		{"Concurrency.LogMode", cfg.Concurrency.LogMode, "summary"},
		{"Concurrency.TailLines", cfg.Concurrency.TailLines, 20},
		{"Concurrency.JobTimeoutSeconds", cfg.Concurrency.JobTimeoutSeconds, 0},
		{"Concurrency.KillGraceSeconds", cfg.Concurrency.KillGraceSeconds, 10},

		{"Subdomains.Enabled", cfg.Subdomains.Enabled, true},
		{"Subdomains.Passive.Enabled", cfg.Subdomains.Passive.Enabled, true},
		{"Subdomains.Passive.TimeoutMinutes", cfg.Subdomains.Passive.TimeoutMinutes, 180},
		{"Subdomains.CRT.Limit", cfg.Subdomains.CRT.Limit, 999999},
		{"Subdomains.Permut.LimitBytes", cfg.Subdomains.Permut.LimitBytes, int64(2147483648)},

		{"Web.Probe.Enabled", cfg.Web.Probe.Enabled, true},
		{"Web.Probe.RateLimit", cfg.Web.Probe.RateLimit, 150},
		{"Web.Probe.TimeoutSeconds", cfg.Web.Probe.TimeoutSeconds, 10},
		{"Web.Probe.Ports", cfg.Web.Probe.Ports, "80,443"},
		{"Web.Nuclei.Enabled", cfg.Web.Nuclei.Enabled, true},
		{"Web.Nuclei.RateLimit", cfg.Web.Nuclei.RateLimit, 150},
		{"Web.Nuclei.Severity", cfg.Web.Nuclei.Severity, "info,low,medium,high,critical"},
		{"Web.Fuzz.RateLimit", cfg.Web.Fuzz.RateLimit, 0},
		{"Web.Fuzz.MaxTimeSeconds", cfg.Web.Fuzz.MaxTimeSeconds, 900},

		{"Vulns.Enabled", cfg.Vulns.Enabled, false},
		{"Vulns.XSS.Enabled", cfg.Vulns.XSS.Enabled, true},
		{"Vulns.SSTI.Engine", cfg.Vulns.SSTI.Engine, "TInjA"},

		{"OSINT.Enabled", cfg.OSINT.Enabled, true},
		{"OSINT.GoogleDorks.Enabled", cfg.OSINT.GoogleDorks.Enabled, true},

		{"Notifications.Enabled", cfg.Notifications.Enabled, false},

		{"Axiom.Enabled", cfg.Axiom.Enabled, false},
		{"Axiom.FleetCount", cfg.Axiom.FleetCount, 10},
		{"Axiom.FleetName", cfg.Axiom.FleetName, "reconFTW"},

		{"MCP.Enabled", cfg.MCP.Enabled, false},
		{"MCP.Transport", cfg.MCP.Transport, "stdio"},
		{"MCP.Port", cfg.MCP.Port, 8765},

		{"Scheduler.FailurePolicy", cfg.Scheduler.FailurePolicy, "best_effort"},

		{"Output.Verbosity", cfg.Output.Verbosity, 1},
		{"Output.LogFormat", cfg.Output.LogFormat, "json"},
		{"Output.LogLevel", cfg.Output.LogLevel, "info"},

		// INTEG-06: coherent AI default (local-first Ollama, opt-in).
		{"AI.Enabled", cfg.AI.Enabled, false},
		{"AI.Provider", cfg.AI.Provider, "ollama"},
		{"AI.Model", cfg.AI.Model, "llama3:8b"},
		{"AI.OllamaHost", cfg.AI.OllamaHost, "http://localhost:11434"},
	}
	for _, tc := range tests {
		if tc.got != tc.want {
			t.Errorf("%s = %v (%T); want %v (%T)", tc.name, tc.got, tc.got, tc.want, tc.want)
		}
	}
}

// --- Test 3b: AI provider oneof + OllamaHost scheme validation (INTEG-06) ---
//
// The Provider field guards against an unknown provider silently falling
// through to a cloud path; OllamaHost is restricted to http/https so a stray
// scheme can't be used as an SSRF/exfil vector (T-12-02-03).
func TestAIProviderValidation(t *testing.T) {
	t.Parallel()
	providers := []struct {
		provider string
		wantErr  bool
	}{
		{"ollama", false},
		{"openai", false},
		{"anthropic", false},
		{"", false}, // omitempty — empty is allowed (treated as anthropic default)
		{"banana", true},
	}
	for _, tc := range providers {
		t.Run("provider="+tc.provider, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.AI.Provider = tc.provider
			err := config.Validate(cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(ai.provider=%q) err=%v; wantErr=%v", tc.provider, err, tc.wantErr)
			}
		})
	}

	hosts := []struct {
		host    string
		wantErr bool
	}{
		{"http://localhost:11434", false},
		{"https://ollama.internal:11434", false},
		{"", false}, // omitempty
		{"file:///etc/passwd", true},
		{"gopher://attacker/", true},
	}
	for _, tc := range hosts {
		t.Run("ollama_host="+tc.host, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.AI.OllamaHost = tc.host
			err := config.Validate(cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(ai.ollama_host=%q) err=%v; wantErr=%v", tc.host, err, tc.wantErr)
			}
		})
	}
}

// --- Test 4: Logger factory accepts *config.Config via AsLoggerConfig adapter ---
//
// Plan 03-02 swaps the placeholder log.Config for a real config.Config. We
// avoid a circular import (log <-> config) by having config.Config implement
// an interface or expose an adapter. We use the adapter pattern: config.Config
// exposes AsLoggerConfig() *log.Config returning the minimal logger shim.
// This test proves the adapter wires up correctly end-to-end.
func TestConfigAsLoggerConfig(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	cfg.Output.LogFormat = "json"
	cfg.Output.LogLevel = "info"

	var buf bytes.Buffer
	cfg.Output.LogOutput = &buf

	lc := cfg.AsLoggerConfig()
	if lc == nil {
		t.Fatal("AsLoggerConfig() returned nil")
	}
	r := &log.Redactor{}
	r.Register("secret-value-1234567890")
	logger := log.New(lc, r)
	if logger == nil {
		t.Fatal("log.New(cfg.AsLoggerConfig(), r) returned nil")
	}
	logger.Info("event with secret-value-1234567890")

	if bytes.Contains(buf.Bytes(), []byte("secret-value-1234567890")) {
		t.Errorf("secret leaked into log output: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("***")) {
		t.Errorf("redaction did not fire: %s", buf.String())
	}
}
