// Source: CONTEXT default option (a) — Discord stub returns nil after
// logging the would-send intent. Phase 10 wires real HTTPS POST to the
// webhook endpoint.
//
// TODO(phase-10): replace with real webhook dispatch
//
// The webhook URL is held as a string (typed log.Secret at the config
// boundary); after registration with the Redactor it is scrubbed from
// every "discord_notify_stub" log line.

package notifier

import (
	"context"
	"log/slog"
)

// DiscordNotifier is the Phase 3 stub. Phase 10 ships a real
// retryablehttp.Client wrapping the webhook URL.
type DiscordNotifier struct {
	Log        *slog.Logger
	webhookURL string // log.Secret at the config boundary; here plain
}

// NewDiscord constructs a DiscordNotifier stub. logger may be nil → slog.Default.
func NewDiscord(logger *slog.Logger, webhookURL string) *DiscordNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &DiscordNotifier{Log: logger, webhookURL: webhookURL}
}

// Notify is a Phase 3 stub — logs the would-send intent at INFO and
// returns nil without performing any HTTP request.
func (d *DiscordNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	args := append([]any{
		slog.String("notify_level", levelString(lvl)),
		slog.String("notify_msg", msg),
	}, attrs...)
	d.Log.Log(ctx, slog.LevelInfo, "discord_notify_stub", args...)
	return nil
}

var _ Notifier = (*DiscordNotifier)(nil)
