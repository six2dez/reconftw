// Config snapshot writer — produces inputs/config.snapshot.toml (ADR §3.1).
//
// The snapshot is the resolved, post-validation Config rendered to TOML with
// every log.Secret-typed field replaced by the literal "***". It is:
//   - Auditable: operator can review which keys took effect, without seeing
//     raw secret values that would land in workspace logs / reports.
//   - Replayable (partially): non-secret keys round-trip through Load.
//   - Hashable: stored hash goes into manifest.json as config_hash (§3.3).
//
// Atomic write contract (ADR §3.5): delegated to internal/core/output.WriteFile
// — the canonical 4-step pattern (tempfile + fsync + rename + parent-dir fsync)
// per Plan 03 (W19 migration). The previous inline 4-step helper has been
// removed; the contract is now owned by the output package which is covered
// by the FOUND-04 atomicity tests + the Ring 3 subprocess SIGKILL smoke test.

package config

import (
	"reflect"

	tomlv2 "github.com/pelletier/go-toml/v2"

	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
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
	data, err := SnapshotBytes(cfg)
	if err != nil {
		return err
	}
	// W19: delegate to internal/core/output.WriteFile — the canonical
	// 4-step AtomicWriter from Plan 03. Same atomicity guarantee as the
	// prior inline helper (which has been removed); behaviour covered by
	// output.TestFOUND04Atomicity + the Ring 3 smoke SIGKILL test.
	return output.WriteFile(path, data, 0o644)
}

// SnapshotBytes returns the deterministic, redacted TOML representation of cfg —
// every log.Secret-typed field rendered as the literal "***". This is the exact
// byte stream WriteSnapshot persists; it is exported so BootReconApp can feed it
// into checkpoint.InputHash as the cfg-slice (INTEG-03), making a task's input
// hash invalidate whenever ANY config byte changes.
//
// Deterministic: redaction is a fixed per-field enumeration and go-toml/v2 sorts
// map keys, so two identical Configs produce byte-equal output — the property the
// input-hash relies on to be stable across runs (threat T-12-01-01).
//
// SECURITY: reuses redactSecrets, so no raw secret value can leak into the hash
// input (threat T-12-01-02). The returned error NEVER contains a raw secret value
// (go-toml/v2 errors carry only type/path information).
func SnapshotBytes(cfg *Config) ([]byte, error) {
	if cfg == nil {
		return nil, errNilConfig
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
		return nil, errMarshal(err)
	}
	return data, nil
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

// errNilConfig + errMarshal are tiny helpers extracted from the prior
// inline body of WriteSnapshot so the function reads as a single linear
// "marshal then write" sequence.
var errNilConfig = errSnapshot("WriteSnapshot called with nil config")

func errSnapshot(msg string) error { return &snapshotError{msg: "config: " + msg} }
func errMarshal(err error) error {
	return &snapshotError{msg: "config: marshal snapshot: " + err.Error(), inner: err}
}

type snapshotError struct {
	msg   string
	inner error
}

func (e *snapshotError) Error() string { return e.msg }
func (e *snapshotError) Unwrap() error { return e.inner }
