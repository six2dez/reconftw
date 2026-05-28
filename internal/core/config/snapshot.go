// Config snapshot writer — produces inputs/config.snapshot.toml (ADR §3.1).
//
// The snapshot is the resolved, post-validation Config rendered to TOML with
// every log.Secret-typed field replaced by the literal "***". It is:
//   - Auditable: operator can review which keys took effect, without seeing
//     raw secret values that would land in workspace logs / reports.
//   - Replayable (partially): non-secret keys round-trip through Load.
//   - Hashable: stored hash goes into manifest.json as config_hash (§3.3).
//
// Atomic write contract (ADR §3.5):
//   1. Create tempfile in target directory (same filesystem → rename(2) is atomic).
//   2. Write + fsync the tempfile.
//   3. Rename(2) over the target.
//   4. Fsync the parent directory (often-missed step; survives power failure).
//
// TODO(plan-03): replace inline atomicWriteFile with output.WriteFile once
// Plan 03 lands internal/core/output/atomic.go.

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	tomlv2 "github.com/pelletier/go-toml/v2"

	"github.com/six2dez/reconftw/internal/core/log"
)

// WriteSnapshot writes cfg to path as TOML, with every log.Secret-typed field
// rendered as the literal string "***". Uses the 4-step atomic write pattern
// (ADR §3.5). Returns nil on success.
//
// File mode: 0o644 (owner-writable, world-readable — matches other artefacts).
// Intermediate directories are created with mode 0o755.
//
// Idempotent: calling twice with the same Config produces byte-equal output
// (the redaction is deterministic; the TOML marshal is sorted by go-toml/v2).
//
// SECURITY: the returned error NEVER contains a raw secret value, even if the
// failure stems from marshaling a secret field — go-toml/v2 errors carry only
// type and path information, not value contents.
func WriteSnapshot(cfg *Config, path string) error {
	if cfg == nil {
		return fmt.Errorf("config: WriteSnapshot called with nil config")
	}
	redacted := redactSecrets(cfg)
	// go-toml/v2 reads `toml:"..."` tags but the Config struct uses koanf tags
	// (the single source of truth). Convert via the same struct-walk used by
	// structsProvider, which emits a nested map[string]any keyed by koanf tag.
	// Marshaling the map produces TOML with the expected snake_case section
	// names that Load can re-parse. Skip non-koanf-tagged fields and
	// non-readable values (io.Writer for log output).
	tree := walkStructForTOML(reflect.ValueOf(redacted).Elem())
	data, err := tomlv2.Marshal(tree)
	if err != nil {
		return fmt.Errorf("config: marshal snapshot: %w", err)
	}
	return atomicWriteFile(path, data, 0o644)
}

// walkStructForTOML is like walkStruct but applies additional pruning:
//   - log.Secret is preserved as string (already redacted at this point)
//   - io.Writer / nil values are dropped (cannot marshal to TOML)
//   - map[string]any with empty content is dropped (else go-toml renders [legacy])
func walkStructForTOML(v reflect.Value) map[string]any {
	out := make(map[string]any)
	if v.Kind() != reflect.Struct {
		return out
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		ft := t.Field(i)
		tag := ft.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		fv := v.Field(i)
		switch fv.Kind() {
		case reflect.Struct:
			out[tag] = walkStructForTOML(fv)
		case reflect.Interface:
			// io.Writer fields and other interfaces — skip; they're runtime-
			// only and can't be marshaled to TOML.
			continue
		case reflect.Map:
			// Skip empty maps (Legacy in particular) so the snapshot doesn't
			// have a stub [legacy] section.
			if fv.Len() == 0 {
				continue
			}
			out[tag] = fv.Interface()
		default:
			out[tag] = fv.Interface()
		}
	}
	return out
}

// redactSecrets returns a copy of cfg with every log.Secret-typed field
// replaced by log.Secret("***"). The replacement uses an EXPLICIT per-field
// list (not reflection) so the audit log of "which fields are secret" lives
// in source code that can be grepped + code-reviewed.
//
// Adding a new secret field requires adding it both to the Config struct
// AND to this function. The XCUT-07 sentinel test in CI is the regression
// gate — a forgotten Secret field will fail the sentinel check.
func redactSecrets(cfg *Config) *Config {
	clone := *cfg
	// SECRETS — explicit enumeration (audited by W10 + threat-model T-03-02-01).
	clone.Notifications.Slack.WebhookURL = log.Secret("***")
	clone.Notifications.Telegram.BotToken = log.Secret("***")
	clone.Notifications.Discord.WebhookURL = log.Secret("***")
	clone.AI.OpenAIKey = log.Secret("***")
	clone.AI.AnthropicKey = log.Secret("***")
	clone.MCP.APIKey = log.Secret("***")
	clone.APIKeys.Shodan = log.Secret("***")
	clone.APIKeys.WhoisXML = log.Secret("***")
	clone.APIKeys.PDCP = log.Secret("***")
	return &clone
}

// atomicWriteFile implements the 4-step pattern from ADR §3.5 inline. Plan 03
// will ship internal/core/output/atomic.go as the canonical helper; once it
// lands, this function becomes a thin wrapper. See TODO at top of file.
//
// Why the steps matter:
//   1. CreateTemp same-dir: same-filesystem guarantee → rename(2) is atomic,
//      not a cross-device copy-and-delete.
//   2. Sync the tempfile: data bytes on persistent storage before the rename.
//   3. Rename: POSIX atomic — readers see either the old or new file, never torn.
//   4. Sync parent dir: directory entry must reach disk; otherwise a power
//      failure between rename and dir-flush leaves the directory pointing at
//      the old inode.
func atomicWriteFile(target string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", dir, err)
	}

	base := filepath.Base(target)
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return fmt.Errorf("config: create tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: write tempfile: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: chmod tempfile: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config: fsync tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close tempfile: %w", err)
	}

	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("config: rename %s -> %s: %w", tmpName, target, err)
	}
	cleanedUp = true // rename succeeded; tempfile name is gone.

	// Step 4 — parent directory fsync. Skipped on environments where the
	// directory cannot be opened (rare); the rename is durable on POSIX
	// without the dir-fsync, just not crash-safe across power loss.
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("config: open parent dir: %w", err)
	}
	defer parent.Close() //nolint:errcheck
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("config: fsync parent dir: %w", err)
	}
	return nil
}
