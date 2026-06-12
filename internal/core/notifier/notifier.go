// Package notifier defines reconFTW v2's notification dispatch layer.
//
// Phase 3 stub depth per CONTEXT default option (a) + FOUND-11:
//   - Notifier interface (Notify method)
//   - LogSink — writes notification to slog at the corresponding level
//   - Slack / Telegram / Discord — real HTTP webhook dispatchers (Phase 10)
//   - Multi — fan-out multiplexer wrapping multiple sinks
//   - Flusher — interface for coalescer flush (Phase 10, BLOCKER 2 fix)
//
// Phase 10 (Monitor + Reporting + Notifications) wires real HTTP webhooks
// for Slack/Telegram/Discord; Phase 3's stubs let the AppContext.Notify
// field be non-nil from day 1 so Tasks can call app.Notify.Notify(...)
// without nil checks.
//
// BLOCKER 2 fix (FlushNow reachability): Boot wires app.Notify =
// notifier.NewMulti(sinks...) — type *notifier.Multi. A type assertion
// app.Notify.(*notifier.DigestCoalescer) fails at runtime because the outer
// type is *Multi. Fix: Flusher interface + Multi.FlushNow delegation —
// the monitor loop calls app.Notify.(notifier.Flusher).FlushNow(ctx) which
// succeeds because *Multi implements Flusher by delegating to any Flusher
// sink (DigestCoalescer).
//
// XCUT-07 invariant: all message bodies pass through the Redactor before
// being emitted. LogSink uses the AppContext logger (which has a
// RedactingHandler chain) — the wired chain provides the redaction.
//
// Source: ADR 0002 §5.3 (AppContext.Notify field) + REQUIREMENTS.md
// FOUND-11.
package notifier

import (
	"context"
	"errors"
)

// Level enumerates notification severity. Maps to slog levels at the
// LogSink boundary.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

// Notifier is the notification dispatch interface. Implementations
// include LogSink (slog passthrough), and real HTTP dispatchers for
// Slack/Telegram/Discord (Phase 10).
//
// BINDING per ADR §5.3 line 1730: adding methods is non-breaking;
// renaming/removing requires an ADR amendment.
type Notifier interface {
	// Notify sends msg at the given level. Implementations are expected to
	// be non-blocking for stubs; real HTTP dispatchers (Phase 10) will use
	// the ctx for cancellation and per-call deadlines.
	Notify(ctx context.Context, level Level, msg string, attrs ...any) error
}

// Flusher is implemented by coalescing notifiers (DigestCoalescer) that
// buffer messages and flush them as a single digest. Multi also implements
// Flusher by delegating to any Flusher sink — this is the BLOCKER 2 fix
// that allows the monitor loop to call:
//
//	app.Notify.(notifier.Flusher).FlushNow(ctx)
//
// The assertion succeeds because app.Notify is *Multi (not *DigestCoalescer),
// and *Multi now satisfies Flusher.
type Flusher interface {
	FlushNow(ctx context.Context) error
}

// Multi is the fan-out Notifier — calls Notify on every wrapped sink and
// joins the errors. AppContext.Notify is typed as Notifier; in practice
// Boot wires a Multi wrapping LogSink + service notifiers (CONTEXT default
// option (a)).
//
// Error semantics: errors are collected via errors.Join — callers that
// want category-level traversal use errors.Is on the result.
type Multi struct {
	Sinks []Notifier
}

// NewMulti constructs a Multi wrapping the given sinks. Empty Multi is
// legal — Notify on it returns nil.
func NewMulti(sinks ...Notifier) *Multi { return &Multi{Sinks: sinks} }

// Notify dispatches to every sink. Each sink's error is collected;
// errors.Join produces the final error. nil is returned if no sink errors.
func (m *Multi) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	if len(m.Sinks) == 0 {
		return nil
	}
	errs := make([]error, 0, len(m.Sinks))
	for _, s := range m.Sinks {
		if s == nil {
			continue
		}
		if err := s.Notify(ctx, lvl, msg, attrs...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FlushNow implements Flusher by ranging over Sinks and delegating to any
// sink that also implements Flusher (e.g. DigestCoalescer). This makes
// *Multi satisfy the Flusher interface so the monitor loop can call:
//
//	app.Notify.(notifier.Flusher).FlushNow(ctx)
//
// Errors from each Flusher sink are collected and joined.
func (m *Multi) FlushNow(ctx context.Context) error {
	errs := make([]error, 0, len(m.Sinks))
	for _, s := range m.Sinks {
		if f, ok := s.(Flusher); ok {
			if err := f.FlushNow(ctx); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

var _ Notifier = (*Multi)(nil)
var _ Flusher = (*Multi)(nil)
