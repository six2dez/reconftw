// Source: REQUIREMENTS.md FOUND-11 — "Notifier interface + log sink".
//
// LogSink writes notifications to the wrapped slog.Logger at the level
// derived from the Notify call. Phase 3 default — the wired logger has a
// RedactingHandler chain (from internal/core/log/redactor.go) so any
// registered secret substrings get scrubbed before hitting stderr or any
// file sink.
//
// The XCUT-07 invariant ("all message bodies pass through redactor before
// send") is satisfied transitively: LogSink.Notify calls Log.Info/Warn/
// Error → RedactingHandler.Handle → inner JSONHandler. Secret values
// registered with the package-level Redactor are scrubbed at the handler
// boundary.

package notifier

import (
	"context"
	"log/slog"
)

// LogSink is the Phase 3 default Notifier implementation. Writes via slog
// at the level corresponding to the Notify call's Level.
type LogSink struct {
	Log *slog.Logger
}

// NewLogSink wraps logger as a Notifier. If logger is nil, slog.Default()
// is used.
func NewLogSink(logger *slog.Logger) *LogSink {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogSink{Log: logger}
}

// Notify writes msg at the level corresponding to lvl. attrs are passed
// through as slog attributes — they get the same redaction treatment as
// the message body.
func (s *LogSink) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	switch lvl {
	case LevelError:
		s.Log.Log(ctx, slog.LevelError, msg, attrs...)
	case LevelWarn:
		s.Log.Log(ctx, slog.LevelWarn, msg, attrs...)
	default:
		s.Log.Log(ctx, slog.LevelInfo, msg, attrs...)
	}
	return nil
}

var _ Notifier = (*LogSink)(nil)
