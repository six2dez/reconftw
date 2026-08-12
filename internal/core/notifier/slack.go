// Phase 10: real Slack webhook dispatcher.
//
// Replaces the Phase 3 stub with a real net/http POST to a Slack
// Incoming Webhook URL. Per D-07, scan-time Notify returns nil on failure
// (best-effort, never blocks the pipeline). The private send() method
// propagates errors for the notify --test reachability path.
//
// NOTIF-01: webhook URL is log.Secret-typed at the config boundary and
// registered with the Redactor in Boot; this file receives a plain string
// because the secret value has already been registered and the slog logger
// carries a RedactingHandler chain that will scrub it from log lines.
//
// Source: 10-02-PLAN.md Task 1 + 10-PATTERNS.md § SlackNotifier.

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

// SlackNotifier dispatches notifications to a Slack Incoming Webhook URL
// via a real HTTP POST.
type SlackNotifier struct {
	Log        *slog.Logger
	webhookURL string // log.Secret at the config boundary; here plain
	httpClient *http.Client
}

// NewSlack constructs a SlackNotifier. logger may be nil → slog.Default().
// client may be nil → &http.Client{Timeout: 10s}.
func NewSlack(logger *slog.Logger, client *http.Client, webhookURL string) *SlackNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &SlackNotifier{Log: logger, httpClient: client, webhookURL: webhookURL}
}

// Notify dispatches msg to the Slack webhook. Returns nil on any failure
// per D-07 (best-effort — never blocks the scan pipeline).
func (s *SlackNotifier) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	//nolint:errcheck
	_ = s.send(ctx, msg) // discard error per D-07
	return nil
}

// send performs the actual HTTP POST and returns the error to the caller.
// Used by notify --test (which propagates errors) and wrapped by Notify
// (which discards the error per D-07).
func (s *SlackNotifier) Send(ctx context.Context, msg string) error {
	return s.send(ctx, msg)
}

func (s *SlackNotifier) send(ctx context.Context, msg string) error {
	if s.webhookURL == "" {
		return nil
	}
	payload, err := json.Marshal(map[string]string{"text": msg})
	if err != nil {
		return fmt.Errorf("slack: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL,
		bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("slack: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack: send: %w", err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: non-2xx status %d", resp.StatusCode)
	}
	return nil
}

var _ Notifier = (*SlackNotifier)(nil)
