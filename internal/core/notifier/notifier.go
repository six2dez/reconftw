// Package notifier defines reconFTW v2's notification dispatch layer.
//
// Phase 3 stub depth per CONTEXT default option (a) + FOUND-11:
//   - Notifier interface (Notify method)
//   - LogSink — writes notification to slog at the corresponding level
//   - Slack / Telegram / Discord — stubs returning nil after logging
//   - Multi — fan-out multiplexer wrapping multiple sinks
//
// Phase 10 (Monitor + Reporting + Notifications) wires real HTTP webhooks
// for Slack/Telegram/Discord; Phase 3's stubs let the AppContext.Notify
// field be non-nil from day 1 so Tasks can call app.Notify.Notify(...)
// without nil checks.
//
// XCUT-07 invariant: all message bodies pass through the Redactor before
// being emitted. LogSink uses the AppContext logger (which has a
// RedactingHandler chain) — the wired chain provides the redaction.
// Slack/Telegram/Discord stubs that log their "would send" intent also
// flow through the wired logger, inheriting the redaction guarantee.
//
// Source: ADR 0002 §5.3 (AppContext.Notify field) + REQUIREMENTS.md
// FOUND-11.
//
// Phase 3 Plan 5 Task 2 ships the full implementation (LogSink + 3 stubs
// + Multi + tests). Plan 05 Task 1 ships only this skeleton so that
// `internal/core/appctx/appctx.go` can declare `Notify notifier.Notifier`
// without a forward-declaration loop.
package notifier

import "context"

// Level enumerates notification severity. Maps to slog levels at the
// LogSink boundary.
type Level int

const (
	LevelInfo Level = iota
	LevelWarn
	LevelError
)

// Notifier is the notification dispatch interface. Implementations
// include LogSink (slog passthrough), and stubs for Slack/Telegram/Discord
// (Phase 3 returns nil; Phase 10 wires real webhooks).
//
// BINDING per ADR §5.3 line 1730: adding methods is non-breaking;
// renaming/removing requires an ADR amendment.
type Notifier interface {
	// Notify sends msg at the given level. Implementations are expected to
	// be non-blocking for stubs; real HTTP dispatchers (Phase 10) will use
	// the ctx for cancellation and per-call deadlines.
	Notify(ctx context.Context, level Level, msg string, attrs ...any) error
}
