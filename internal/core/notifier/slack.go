// Source: CONTEXT default option (a) — Slack stub returns nil after
// logging the would-send intent. Phase 10 wires real HTTP webhook
// dispatch (chi/retryablehttp + JSON body + interactive button echo).
//
// TODO(phase-10): replace with real webhook dispatch
//
// The webhook URL is held as a string (typed log.Secret at the config
// boundary); after registration with the Redactor it is scrubbed from
// every "slack_notify_stub" log line.

package notifier

import (
	"context"
	"log/slog"
)

// SlackNotifier is the Phase 3 stub. Phase 10 ships a real
// retryablehttp.Client wrapping a Slack webhook POST.
type SlackNotifier struct {
	Log        *slog.Logger
	webhookURL string // log.Secret at the config boundary; here plain
}

// NewSlack constructs a SlackNotifier stub. logger may be nil → slog.Default.
func NewSlack(logger *slog.Logger, webhookURL string) *SlackNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &SlackNotifier{Log: logger, webhookURL: webhookURL}
}

// Notify is a Phase 3 stub — logs the would-send intent at INFO and
// returns nil without performing any HTTP request.
func (s *SlackNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	args := append([]any{
		slog.String("notify_level", levelString(lvl)),
		slog.String("notify_msg", msg),
	}, attrs...)
	s.Log.Log(ctx, slog.LevelInfo, "slack_notify_stub", args...)
	return nil
}

var _ Notifier = (*SlackNotifier)(nil)

// levelString maps Level → human label for log fields. Shared by the 3
// service stubs.
func levelString(lvl Level) string {
	switch lvl {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	default:
		return "info"
	}
}
