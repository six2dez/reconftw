// Phase 10: real Telegram Bot API dispatcher.
//
// Replaces the Phase 3 stub with a real net/http POST to
// https://api.telegram.org/bot<token>/sendMessage.
//
// Pitfall 1: parse_mode is intentionally omitted. MarkdownV2 causes 400
// errors when finding titles contain underscores, periods, or parentheses
// (common in security tool output). Plain text is safe.
//
// Per D-07, scan-time Notify returns nil on failure (best-effort).
// The private send() method propagates errors for notify --test.
//
// Source: 10-02-PLAN.md Task 1 + 10-PATTERNS.md § TelegramNotifier.

package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// TelegramNotifier dispatches notifications to a Telegram chat via the
// Bot API sendMessage endpoint.
type TelegramNotifier struct {
	Log        *slog.Logger
	botToken   string // log.Secret at the config boundary; here plain
	chatID     string
	httpClient *http.Client
}

// telegramPayload is the JSON body for sendMessage.
// parse_mode is intentionally omitted (Pitfall 1).
type telegramPayload struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
	// parse_mode intentionally omitted — plain text avoids MarkdownV2
	// escaping issues with special chars in finding titles.
}

// NewTelegram constructs a TelegramNotifier. logger may be nil → slog.Default().
// client may be nil → &http.Client{Timeout: 10s}.
func NewTelegram(logger *slog.Logger, client *http.Client, botToken, chatID string) *TelegramNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &TelegramNotifier{Log: logger, httpClient: client, botToken: botToken, chatID: chatID}
}

// Notify dispatches msg to the Telegram chat. Returns nil on any failure
// per D-07 (best-effort — never blocks the scan pipeline).
func (t *TelegramNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	//nolint:errcheck
	_ = t.send(ctx, msg) // discard error per D-07
	return nil
}

// Send exposes the error-propagating send path for notify --test.
func (t *TelegramNotifier) Send(ctx context.Context, msg string) error {
	return t.send(ctx, msg)
}

func (t *TelegramNotifier) send(ctx context.Context, msg string) error {
	if t.botToken == "" || t.chatID == "" {
		return nil
	}
	url := "https://api.telegram.org/bot" + t.botToken + "/sendMessage"
	payload, err := json.Marshal(telegramPayload{ChatID: t.chatID, Text: msg})
	if err != nil {
		return fmt.Errorf("telegram: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
		bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("telegram: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("telegram: send: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram: non-2xx status %d", resp.StatusCode)
	}
	return nil
}

var _ Notifier = (*TelegramNotifier)(nil)
