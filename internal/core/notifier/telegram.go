// Source: CONTEXT default option (a) — Telegram stub returns nil after
// logging the would-send intent. Phase 10 wires real HTTPS POST to the
// Bot API endpoint.
//
// TODO(phase-10): replace with real webhook dispatch
//
// The bot token is held as a string (typed log.Secret at the config
// boundary); after registration with the Redactor it is scrubbed from
// every "telegram_notify_stub" log line.

package notifier

import (
	"context"
	"log/slog"
)

// TelegramNotifier is the Phase 3 stub. Phase 10 ships a real
// retryablehttp.Client wrapping
// https://api.telegram.org/bot<token>/sendMessage.
type TelegramNotifier struct {
	Log      *slog.Logger
	botToken string // log.Secret at the config boundary; here plain
}

// NewTelegram constructs a TelegramNotifier stub. logger may be nil → slog.Default.
func NewTelegram(logger *slog.Logger, botToken string) *TelegramNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &TelegramNotifier{Log: logger, botToken: botToken}
}

// Notify is a Phase 3 stub — logs the would-send intent at INFO and
// returns nil without performing any HTTP request.
func (t *TelegramNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	args := append([]any{
		slog.String("notify_level", levelString(lvl)),
		slog.String("notify_msg", msg),
	}, attrs...)
	t.Log.Log(ctx, slog.LevelInfo, "telegram_notify_stub", args...)
	return nil
}

var _ Notifier = (*TelegramNotifier)(nil)
