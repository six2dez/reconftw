// Tests for WriteSnapshot — TOML config snapshot with Secret redaction.
// ADR §3.1 (workspaces/<target>/inputs/config.snapshot.toml location).
// ADR §3.5 (AtomicWriter 4-step pattern: tempfile + fsync + rename + parent-dir fsync).
//
// External test package.
package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
)

// --- Test 1: WriteSnapshot produces a TOML file containing the resolved Config ---

func TestWriteSnapshotProducesFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "config.snapshot.toml")
	cfg := config.Defaults()
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat %s: %v", out, err)
	}
	if info.Size() == 0 {
		t.Errorf("snapshot is empty")
	}
	// File must be a regular file (not symlink, not directory).
	if !info.Mode().IsRegular() {
		t.Errorf("snapshot is not a regular file: %v", info.Mode())
	}
}

// --- Test 2: log.Secret fields are written as "***" ---
//
// CRITICAL: this is the SECURITY gate. If the sentinel value leaks into the
// snapshot file, secrets get committed to disk in operator workspaces.

func TestSnapshotSecretRedaction(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "config.snapshot.toml")
	cfg := config.Defaults()
	const sentinel = "test_sentinel_value_not_a_real_key_abc123"
	cfg.Notifications.Slack.WebhookURL = log.Secret(sentinel)
	cfg.Notifications.Telegram.BotToken = log.Secret(sentinel)
	cfg.Notifications.Discord.WebhookURL = log.Secret(sentinel)
	cfg.AI.OpenAIKey = log.Secret(sentinel)
	cfg.AI.AnthropicKey = log.Secret(sentinel)
	cfg.MCP.APIKey = log.Secret(sentinel)
	cfg.APIKeys.Shodan = log.Secret(sentinel)
	cfg.APIKeys.WhoisXML = log.Secret(sentinel)
	cfg.APIKeys.PDCP = log.Secret(sentinel)

	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if bytes.Contains(data, []byte(sentinel)) {
		t.Fatalf("snapshot leaked sentinel %q into disk:\n%s", sentinel, data)
	}
	// The redacted "***" marker MUST appear at least 9 times (one per Secret field).
	if c := bytes.Count(data, []byte("***")); c < 6 {
		t.Errorf("snapshot has %d *** markers; want ≥6 (one per secret field)", c)
	}
}

// --- Test 3: WriteSnapshot leaves no .tmp.* files behind on success ---

func TestSnapshotAtomicNoTempLeak(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "config.snapshot.toml")
	cfg := config.Defaults()
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	entries, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	tmpFound := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			tmpFound++
		}
	}
	if tmpFound != 0 {
		t.Errorf("found %d leftover .tmp.* files; want 0", tmpFound)
	}
}

// --- Test 4: Load → Validate → WriteSnapshot → Re-load round-trip works ---

func TestLoadValidateSnapshotIntegration(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	src := filepath.Join(tmp, "src.toml")
	const sentinel = "round-trip-sentinel-abcdef-1234567890"
	body := `
[concurrency]
max_jobs = 5

[notifications.slack]
webhook_url = "https://hooks.slack.com/services/aaa/bbb/ccc"

[api_keys]
shodan = "` + sentinel + `"
`
	if err := os.WriteFile(src, []byte(body), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	cfg, err := config.Load(config.LoadOptions{ExplicitConfigPath: src})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Verify the loaded value before snapshot.
	if string(cfg.APIKeys.Shodan) != sentinel {
		t.Fatalf("Load did not retain shodan value; got %q", string(cfg.APIKeys.Shodan))
	}
	snap := filepath.Join(tmp, "config.snapshot.toml")
	if err := config.WriteSnapshot(cfg, snap); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	data, err := os.ReadFile(snap)
	if err != nil {
		t.Fatalf("read snap: %v", err)
	}
	// Sentinel MUST be absent.
	if bytes.Contains(data, []byte(sentinel)) {
		t.Fatalf("round-trip leaked sentinel into snapshot:\n%s", data)
	}
	// Re-parse — must be valid TOML.
	cfg2, err := config.Load(config.LoadOptions{ExplicitConfigPath: snap})
	if err != nil {
		t.Fatalf("re-Load snapshot: %v", err)
	}
	// Non-secret config values must round-trip equal.
	if cfg2.Concurrency.MaxJobs != cfg.Concurrency.MaxJobs {
		t.Errorf("round-trip max_jobs changed: %d → %d", cfg.Concurrency.MaxJobs, cfg2.Concurrency.MaxJobs)
	}
	// Secret values must be "***" after the round-trip.
	if string(cfg2.APIKeys.Shodan) != "***" {
		t.Errorf("round-trip shodan = %q; want %q", string(cfg2.APIKeys.Shodan), "***")
	}
}

// --- Test 5: Snapshot file mode is 0o644 ---

func TestSnapshotFileMode(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "config.snapshot.toml")
	cfg := config.Defaults()
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("WriteSnapshot: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// 0o644 mask — owner can write, world can read.
	if info.Mode().Perm() != 0o644 {
		t.Errorf("snapshot mode = %v; want %v", info.Mode().Perm(), os.FileMode(0o644))
	}
}

// --- Test 6: WriteSnapshot is idempotent ---

func TestSnapshotIdempotent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "config.snapshot.toml")
	cfg := config.Defaults()
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("first WriteSnapshot: %v", err)
	}
	first, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("second WriteSnapshot: %v", err)
	}
	second, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("snapshot is not idempotent — content changed between writes:\nFIRST:\n%s\nSECOND:\n%s",
			first, second)
	}
}

// --- Test: WriteSnapshot creates intermediate directories ---

func TestSnapshotCreatesIntermediateDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "deep", "nested", "path", "config.snapshot.toml")
	cfg := config.Defaults()
	if err := config.WriteSnapshot(cfg, out); err != nil {
		t.Fatalf("WriteSnapshot in deep path: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("snapshot not at expected path: %v", err)
	}
}
