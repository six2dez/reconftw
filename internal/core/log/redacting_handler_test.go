// Tests for the RedactingHandler (Layer 2 sink wrapper).
// Source: ADR 0002 §10.2 lines 2466-2518 (canonical: full Handle/WithAttrs/WithGroup).
//
// External test package.
package log_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	log "github.com/six2dez/reconftw/internal/core/log"
)

func newTestHandler() (*log.RedactingHandler, *log.Redactor, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	r := &log.Redactor{}
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := log.NewRedactingHandler(inner, r)
	return h, r, buf
}

func parseJSON(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	bs := bytes.TrimSpace(buf.Bytes())
	if len(bs) == 0 {
		t.Fatalf("buffer empty; nothing to parse")
	}
	var m map[string]any
	if err := json.Unmarshal(bs, &m); err != nil {
		t.Fatalf("not valid JSON: %v\nraw: %s", err, buf.String())
	}
	return m
}

// --- Test 9: Message redacted ---

func TestRedactingHandler_RedactsMessage(t *testing.T) {
	t.Parallel()
	h, r, buf := newTestHandler()
	r.Register("sentinel-12345")
	logger := slog.New(h)
	logger.Info("got value: sentinel-12345")

	m := parseJSON(t, buf)
	if got := m["msg"]; got != "got value: ***" {
		t.Errorf("msg = %v; want %q", got, "got value: ***")
	}
	if bytes.Contains(buf.Bytes(), []byte("sentinel-12345")) {
		t.Errorf("raw secret leaked: %s", buf.String())
	}
}

// --- Test 10: String Attr value redacted ---

func TestRedactingHandler_RedactsStringAttr(t *testing.T) {
	t.Parallel()
	h, r, buf := newTestHandler()
	r.Register("sentinel-12345")
	logger := slog.New(h)
	logger.Info("event", slog.String("token", "sentinel-12345"))

	m := parseJSON(t, buf)
	if got := m["token"]; got != "***" {
		t.Errorf("token attr = %v; want %q", got, "***")
	}
	if bytes.Contains(buf.Bytes(), []byte("sentinel-12345")) {
		t.Errorf("raw secret leaked: %s", buf.String())
	}
}

// --- Test 11: Non-string Attr passes through unchanged ---

func TestRedactingHandler_NonStringAttrPassesThrough(t *testing.T) {
	t.Parallel()
	h, _, buf := newTestHandler()
	logger := slog.New(h)
	logger.Info("event", slog.Int("count", 42), slog.Bool("ok", true))

	m := parseJSON(t, buf)
	// JSON unmarshal yields float64 for numbers.
	if got, _ := m["count"].(float64); got != 42 {
		t.Errorf("count = %v; want 42", m["count"])
	}
	if got, _ := m["ok"].(bool); got != true {
		t.Errorf("ok = %v; want true", m["ok"])
	}
}

// --- Test 12: WithAttrs pre-applies redacted attrs ---

func TestRedactingHandler_WithAttrsPreappliesRedaction(t *testing.T) {
	t.Parallel()
	h, r, buf := newTestHandler()
	r.Register("sentinel-12345")
	withAttrs := h.WithAttrs([]slog.Attr{slog.String("k", "sentinel-12345")})
	logger := slog.New(withAttrs)
	logger.Info("event")

	m := parseJSON(t, buf)
	if got := m["k"]; got != "***" {
		t.Errorf("pre-applied k attr = %v; want %q", got, "***")
	}
	if bytes.Contains(buf.Bytes(), []byte("sentinel-12345")) {
		t.Errorf("raw secret leaked through WithAttrs: %s", buf.String())
	}
}

// --- Test 13: WithGroup delegates to inner.WithGroup ---

func TestRedactingHandler_WithGroupDelegates(t *testing.T) {
	t.Parallel()
	h, r, buf := newTestHandler()
	r.Register("sentinel-12345")
	withGroup := h.WithGroup("g")
	logger := slog.New(withGroup)
	logger.Info("evt", slog.String("key", "sentinel-12345"))

	m := parseJSON(t, buf)
	// Group attrs nest into a JSON object under the group name.
	group, ok := m["g"].(map[string]any)
	if !ok {
		t.Fatalf("g group not present in output: %s", buf.String())
	}
	if got := group["key"]; got != "***" {
		t.Errorf("g.key = %v; want %q", got, "***")
	}
	if bytes.Contains(buf.Bytes(), []byte("sentinel-12345")) {
		t.Errorf("raw secret leaked through WithGroup: %s", buf.String())
	}
}

// --- Bonus: Enabled() delegates to the inner handler ---

func TestRedactingHandler_EnabledDelegates(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	r := &log.Redactor{}
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := log.NewRedactingHandler(inner, r)
	ctx := context.Background()

	if h.Enabled(ctx, slog.LevelInfo) {
		t.Errorf("Enabled(Info) = true; inner level is Warn; want false")
	}
	if !h.Enabled(ctx, slog.LevelWarn) {
		t.Errorf("Enabled(Warn) = false; want true")
	}
	if !h.Enabled(ctx, slog.LevelError) {
		t.Errorf("Enabled(Error) = false; want true")
	}
}

// --- Bonus: Substring (not whole-token) replacement works ---
//
// The Redactor uses strings.ReplaceAll, which matches anywhere in the string
// (not just at word boundaries). Confirm that.
func TestRedactingHandler_SubstringReplacement(t *testing.T) {
	t.Parallel()
	h, r, buf := newTestHandler()
	r.Register("supersecret-token")
	logger := slog.New(h)
	logger.Info("body=[supersecret-token]")
	got := buf.String()
	if !strings.Contains(got, "body=[***]") {
		t.Errorf("expected substring 'body=[***]' in output; got %q", got)
	}
}
