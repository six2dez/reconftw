// Source: ADR 0002 §10.2 lines 2466-2518 (lifted verbatim except for doc
// comments). Implements the slog.Handler wrapper that applies the Redactor
// to every emitted log record (Layer 2 sink).
//
// Pattern reference: Arcjet "Redacting sensitive data from logs with Go
// log/slog" (2024).
//
// Handle() builds a fresh slog.Record (slog.NewRecord) with the redacted
// message, then re-adds each attr via redactAttr so non-string attrs pass
// through unchanged while string attrs route through the Redactor. The
// alternative (mutating r in place) is unsafe because slog.Record values
// may be shared between handlers in some pipelines.
//
// WithGroup currently delegates straight to the inner handler without
// extra redaction logic — group nesting is honored by the inner JSON
// handler, and any string attrs added later still pass through Handle
// (and thus through redactAttr).

package log

import (
	"context"
	"log/slog"
)

// RedactingHandler wraps a slog.Handler and passes every string Attr and the
// record Message through the Redactor before forwarding to the inner handler.
type RedactingHandler struct {
	inner    slog.Handler
	redactor *Redactor
}

// NewRedactingHandler creates a new RedactingHandler wrapping inner.
// The same Redactor instance must be used for both NewRedactingHandler and
// for Redactor.Register() calls at config load time (per ADR §10.3 build order).
func NewRedactingHandler(inner slog.Handler, r *Redactor) *RedactingHandler {
	return &RedactingHandler{inner: inner, redactor: r}
}

// Enabled delegates to the inner handler (no redaction needed for level checks).
func (h *RedactingHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

// Handle redacts the record Message and all string Attr values before forwarding.
// Note: redacts both Message and all string Attr values. Does NOT recurse into
// KindGroup attrs in this version — Phase 3 may extend if needed.
func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := slog.NewRecord(r.Time, r.Level, h.redactor.Redact(r.Message), r.PC)
	r.Attrs(func(a slog.Attr) bool {
		r2.AddAttrs(h.redactAttr(a))
		return true
	})
	return h.inner.Handle(ctx, r2)
}

// WithAttrs returns a new handler with the given attrs pre-applied and redacted.
func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = h.redactAttr(a)
	}
	return &RedactingHandler{inner: h.inner.WithAttrs(redacted), redactor: h.redactor}
}

// WithGroup returns a new handler with the given group name applied.
func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{inner: h.inner.WithGroup(name), redactor: h.redactor}
}

// Redactor returns the underlying *Redactor so callers that discover a live
// secret VALUE at runtime (e.g. the OSINT github_leaks Task parsing trufflehog /
// ghleaks output) can Register it (Layer 2) before emitting any log line.
func (h *RedactingHandler) Redactor() *Redactor { return h.redactor }

// RegisterHandlerSecret registers a runtime-discovered secret value with the
// Redactor backing logger's handler chain (Layer 2), so the value is scrubbed
// from ALL subsequent slog output. It is a no-op when logger is nil, its handler
// is not a *RedactingHandler, or value is too short (Redactor.Register skips
// values ≤4 chars). This is the supported entry point for Tasks that surface
// live secrets at scan time (XCUT-07) — they MUST call it BEFORE any log line
// that could reference the value.
func RegisterHandlerSecret(logger *slog.Logger, value string) {
	if logger == nil || value == "" {
		return
	}
	if rh, ok := logger.Handler().(*RedactingHandler); ok && rh.redactor != nil {
		rh.redactor.Register(value)
	}
}

// redactAttr returns a copy of a with its string value redacted.
// Non-string Attrs are returned unchanged.
func (h *RedactingHandler) redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindString {
		return slog.String(a.Key, h.redactor.Redact(a.Value.String()))
	}
	return a
}
