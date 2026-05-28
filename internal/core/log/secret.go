// Package log provides reconFTW v2's structured logging primitives: the
// Secret type (type-level secret tagging via slog.LogValuer — Layer 1 of
// the two-layer redaction defense), the Redactor (runtime registry of
// values to scrub — Layer 2), the RedactingHandler (slog.Handler wrapper
// that applies the Redactor to every emitted record), and the logger
// factory log.New.
//
// The package name `log` deliberately shadows Go stdlib `log`; callers
// needing stdlib log should use a named import. In practice stdlib log
// is rare in v2 — slog replaces it everywhere.
//
// Source: ADR 0002 §10 (BINDING).
package log

import "log/slog"

// Secret is a string that auto-redacts itself in all slog output.
//
// Any field in AppContext, Config, or Tool structs holding a secret MUST
// use this type. Code review + the XCUT-07 sentinel test in CI enforce
// the convention; a future golangci-lint custom rule (per ADR §10.1
// lines 2396-2400) will flag exported *Key/*Token/*Password/*Secret
// fields not typed as log.Secret.
//
// BINDING per ADR §10.1: do NOT add a Secret.String() method. The
// absence of String() prevents accidental fmt.Sprintf("%s", s)
// exposure. If a caller needs the raw value (e.g., to register it with
// the Redactor), they MUST explicitly cast: string(mySecret). The
// explicit cast makes the security-sensitive operation visible in code
// review.
//
// Source: ADR 0002 §10.1 — BINDING type-level secret tagging.
// Implementation pattern is the official Go stdlib LogValuer example
// (golang.org/go src/log/slog/example_logvaluer_secret_test.go).
type Secret string

// LogValue implements slog.LogValuer. Returns "***" for any slog attribute
// whose value is a Secret (or a struct embedding Secret). This is Layer 1
// of the two-layer defense — it cannot fail at runtime, requires zero
// per-call redaction code, and works for every slog handler.
func (Secret) LogValue() slog.Value {
	return slog.StringValue("***")
}
