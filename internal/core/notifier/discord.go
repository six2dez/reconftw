// Phase 10: real Discord webhook dispatcher.
//
// Replaces the Phase 3 stub with a real net/http POST to a Discord
// webhook URL.
//
// Pitfall 2: Discord enforces a 2000-character limit on message content.
// Messages longer than discordMaxContent (1900) are truncated with a
// suffix pointing to reports/hotlist.json for full details.
//
// Per D-07, scan-time Notify returns nil on failure (best-effort).
// The private send() method propagates errors for notify --test.
//
// Source: 10-02-PLAN.md Task 1 + 10-PATTERNS.md § DiscordNotifier.

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

// discordMaxContent is the safe message length before truncation.
// Discord's hard limit is 2000; we use 1900 to leave room for the suffix.
const discordMaxContent = 1900

// discordPayload is the JSON body for Discord webhook execution.
type discordPayload struct {
	Content string `json:"content"`
}

// DiscordNotifier dispatches notifications to a Discord webhook URL.
type DiscordNotifier struct {
	Log        *slog.Logger
	webhookURL string // log.Secret at the config boundary; here plain
	httpClient *http.Client
}

// NewDiscord constructs a DiscordNotifier. logger may be nil → slog.Default().
// client may be nil → &http.Client{Timeout: 10s}.
func NewDiscord(logger *slog.Logger, client *http.Client, webhookURL string) *DiscordNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &DiscordNotifier{Log: logger, httpClient: client, webhookURL: webhookURL}
}

// Notify dispatches msg to the Discord webhook. Returns nil on any failure
// per D-07 (best-effort — never blocks the scan pipeline).
func (d *DiscordNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	//nolint:errcheck
	_ = d.send(ctx, msg) // discard error per D-07
	return nil
}

// Send exposes the error-propagating send path for notify --test.
func (d *DiscordNotifier) Send(ctx context.Context, msg string) error {
	return d.send(ctx, msg)
}

func (d *DiscordNotifier) send(ctx context.Context, msg string) error {
	if d.webhookURL == "" {
		return nil
	}
	content := msg
	if len(content) > discordMaxContent {
		content = content[:discordMaxContent] + "... (truncated — see reports/hotlist.json)"
	}
	payload, err := json.Marshal(discordPayload{Content: content})
	if err != nil {
		return fmt.Errorf("discord: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.webhookURL,
		bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("discord: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("discord: send: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("discord: non-2xx status %d", resp.StatusCode)
	}
	return nil
}

var _ Notifier = (*DiscordNotifier)(nil)
