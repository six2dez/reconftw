// main_test.go — W14 parseEarlyFlags + W10 registerSecrets tests.
package main

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
)

// Test 1 (W14): parseEarlyFlags extracts --config FILE without parsing other flags.
func TestParseEarlyFlagsConfigSpaceForm(t *testing.T) {
	args := []string{"--config", "/etc/x.toml", "--target", "ex.com"}
	efs := parseEarlyFlags(args)
	if efs.configPath != "/etc/x.toml" {
		t.Errorf("configPath = %q, want %q", efs.configPath, "/etc/x.toml")
	}
	// --target IS extracted by parseEarlyFlags (W14 + Phase 3 main needs it
	// to Boot AppContext before cobra dispatch).
	if efs.target != "ex.com" {
		t.Errorf("target = %q, want %q", efs.target, "ex.com")
	}
}

// Test 2 (W14): parseEarlyFlags handles --config=PATH form.
func TestParseEarlyFlagsConfigEqualsForm(t *testing.T) {
	args := []string{"--config=/etc/x.toml"}
	efs := parseEarlyFlags(args)
	if efs.configPath != "/etc/x.toml" {
		t.Errorf("configPath = %q, want %q", efs.configPath, "/etc/x.toml")
	}
}

// Test 3 (W14): parseEarlyFlags handles --secrets FILE (space form).
func TestParseEarlyFlagsSecretsSpaceForm(t *testing.T) {
	args := []string{"--secrets", "/etc/s.toml"}
	efs := parseEarlyFlags(args)
	if efs.secretsPath != "/etc/s.toml" {
		t.Errorf("secretsPath = %q, want %q", efs.secretsPath, "/etc/s.toml")
	}
}

// Test 4 (W14): parseEarlyFlags handles --secrets=PATH form.
func TestParseEarlyFlagsSecretsEqualsForm(t *testing.T) {
	args := []string{"--secrets=/etc/s.toml"}
	efs := parseEarlyFlags(args)
	if efs.secretsPath != "/etc/s.toml" {
		t.Errorf("secretsPath = %q, want %q", efs.secretsPath, "/etc/s.toml")
	}
}

// Test 5 (W14): parseEarlyFlags silently ignores unknown flags.
// Cobra owns full parsing inside Execute() — pre-cobra scan only extracts
// --config / --secrets / --target.
func TestParseEarlyFlagsIgnoresUnknownFlags(t *testing.T) {
	args := []string{"--axiom", "--quiet", "-r", "--log-level=debug"}
	efs := parseEarlyFlags(args)
	if efs.configPath != "" {
		t.Errorf("unknown flags should not populate configPath, got %q", efs.configPath)
	}
	if efs.secretsPath != "" {
		t.Errorf("unknown flags should not populate secretsPath, got %q", efs.secretsPath)
	}
	if efs.target != "" {
		t.Errorf("unknown flags should not populate target, got %q", efs.target)
	}
}

// Test 6 (W14): parseEarlyFlags handles empty args without panic.
func TestParseEarlyFlagsEmpty(t *testing.T) {
	efs := parseEarlyFlags(nil)
	if efs.configPath != "" || efs.secretsPath != "" || efs.target != "" {
		t.Errorf("empty args produced non-zero efs: %+v", efs)
	}
}

// Test 7 (W14): trailing --config without value is silently ignored
// (cobra will surface a proper error later).
func TestParseEarlyFlagsTrailingConfigIgnored(t *testing.T) {
	args := []string{"--config"} // no value
	efs := parseEarlyFlags(args)
	if efs.configPath != "" {
		t.Errorf("trailing --config without value should be ignored, got %q", efs.configPath)
	}
}

// Test 8 (W10): registerSecrets registers every log.Secret-typed field per the
// config.go SECRET FIELD ENUMERATION comment block (9 fields).
//
// Verification strategy: populate cfg with distinguishable secret values >5
// chars each, call registerSecrets, then call redactor.Redact on a string
// containing all 9 values. The output must show "***" 9 times.
func TestRegisterSecretsAllNineFields(t *testing.T) {
	cfg := &config.Config{}
	cfg.Notifications.Slack.WebhookURL = log.Secret("slack-webhook-secret-AAA")
	cfg.Notifications.Telegram.BotToken = log.Secret("telegram-bot-token-BBB")
	cfg.Notifications.Discord.WebhookURL = log.Secret("discord-webhook-secret-CCC")
	cfg.AI.OpenAIKey = log.Secret("openai-key-secret-DDD")
	cfg.AI.AnthropicKey = log.Secret("anthropic-key-secret-EEE")
	cfg.MCP.APIKey = log.Secret("mcp-api-key-secret-FFF")
	cfg.APIKeys.Shodan = log.Secret("shodan-key-secret-GGG")
	cfg.APIKeys.WhoisXML = log.Secret("whoisxml-key-secret-HHH")
	cfg.APIKeys.PDCP = log.Secret("pdcp-key-secret-III")

	r := &log.Redactor{}
	registerSecrets(cfg, r)

	// Concatenate every secret value into a single string and Redact it.
	combined := strings.Join([]string{
		string(cfg.Notifications.Slack.WebhookURL),
		string(cfg.Notifications.Telegram.BotToken),
		string(cfg.Notifications.Discord.WebhookURL),
		string(cfg.AI.OpenAIKey),
		string(cfg.AI.AnthropicKey),
		string(cfg.MCP.APIKey),
		string(cfg.APIKeys.Shodan),
		string(cfg.APIKeys.WhoisXML),
		string(cfg.APIKeys.PDCP),
	}, " ")
	redacted := r.Redact(combined)

	// Every original secret substring should be gone.
	for _, secret := range []string{
		"slack-webhook-secret-AAA",
		"telegram-bot-token-BBB",
		"discord-webhook-secret-CCC",
		"openai-key-secret-DDD",
		"anthropic-key-secret-EEE",
		"mcp-api-key-secret-FFF",
		"shodan-key-secret-GGG",
		"whoisxml-key-secret-HHH",
		"pdcp-key-secret-III",
	} {
		if strings.Contains(redacted, secret) {
			t.Errorf("redacted output still contains secret %q: %q", secret, redacted)
		}
	}
}

// Test 9 (W10): registerSecrets is a no-op when all fields are empty.
// (Redactor.Register skips len ≤ 4 values; empty strings are skipped.)
func TestRegisterSecretsEmptyFieldsNoOp(t *testing.T) {
	cfg := &config.Config{}
	r := &log.Redactor{}
	registerSecrets(cfg, r) // should not panic; should not register anything

	// Calling Redact on a longer string returns it unchanged.
	plain := "no secrets here ever — len > 4"
	out := r.Redact(plain)
	if out != plain {
		t.Errorf("expected empty-cfg Redact to be identity, got %q", out)
	}
}

// Test 10: registerSecrets is XCUT-07 sentinel-compatible — registered secret
// values appear as *** when written via a slog Logger constructed by log.New.
func TestRegisterSecretsXCUT07Sentinel(t *testing.T) {
	cfg := &config.Config{}
	cfg.Notifications.Slack.WebhookURL = log.Secret("xcut07-slack-secret-value")
	r := &log.Redactor{}
	registerSecrets(cfg, r)

	var buf bytesBuffer
	logger := log.New(&log.Config{
		Level:  slog.LevelInfo,
		Format: "json",
		Output: &buf,
	}, r)

	// Log a line that references the raw secret value as a string attr.
	logger.Info("test_event", "url", "xcut07-slack-secret-value")
	out := buf.String()
	if strings.Contains(out, "xcut07-slack-secret-value") {
		t.Errorf("raw secret leaked through Layer 2 redaction: %q", out)
	}
	if !strings.Contains(out, "***") {
		t.Errorf("expected *** in redacted output, got %q", out)
	}
}

// bytesBuffer is a minimal io.Writer for capturing logger output without
// pulling in the bytes package's full API in the test code.
type bytesBuffer struct{ b []byte }

func (b *bytesBuffer) Write(p []byte) (int, error) {
	b.b = append(b.b, p...)
	return len(p), nil
}
func (b *bytesBuffer) String() string { return string(b.b) }
