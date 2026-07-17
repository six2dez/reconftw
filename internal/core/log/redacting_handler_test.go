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

// --- XCUT-03 gap: Redactor() accessor (redacting_handler.go:74) ---
//
// Runtime secret-discovery callers (OSINT github_leaks Task) fetch the live
// Redactor via this accessor to Register a just-found secret. Assert it hands
// back the exact same instance the handler was built with.
func TestRedactingHandler_RedactorAccessor(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}
	inner := slog.NewJSONHandler(&bytes.Buffer{}, nil)
	h := log.NewRedactingHandler(inner, r)
	if h.Redactor() != r {
		t.Errorf("Redactor() = %p; want the redactor passed to NewRedactingHandler (%p)", h.Redactor(), r)
	}
}

// --- XCUT-03 gap: RegisterHandlerSecret (redacting_handler.go:83) ---
//
// The supported XCUT-07 entry point for Tasks that surface a live secret at
// scan time: after registration, the value must be scrubbed from ALL
// subsequent slog output. This is the no-secret-in-logs guarantee.
func TestRegisterHandlerSecret_RedactsAfterRegistration(t *testing.T) {
	t.Parallel()
	h, _, buf := newTestHandler()
	logger := slog.New(h)

	log.RegisterHandlerSecret(logger, "runtime-secret-98765")
	logger.Info("leaked value: runtime-secret-98765")

	if bytes.Contains(buf.Bytes(), []byte("runtime-secret-98765")) {
		t.Errorf("raw secret leaked after RegisterHandlerSecret: %s", buf.String())
	}
	if !bytes.Contains(buf.Bytes(), []byte("***")) {
		t.Errorf("expected redaction marker in output: %s", buf.String())
	}
}

// nil logger is a documented no-op (must not panic).
func TestRegisterHandlerSecret_NilLoggerNoOp(t *testing.T) {
	t.Parallel()
	log.RegisterHandlerSecret(nil, "some-secret-value")
}

// Empty value is a documented no-op — nothing is registered, so an unrelated
// string passes through the Redactor untouched.
func TestRegisterHandlerSecret_EmptyValueNoOp(t *testing.T) {
	t.Parallel()
	h, r, _ := newTestHandler()
	logger := slog.New(h)
	log.RegisterHandlerSecret(logger, "")
	if got := r.Redact("plain-text-value"); got != "plain-text-value" {
		t.Errorf("empty value must register nothing; Redact mutated output: %q", got)
	}
}

// A logger whose handler is NOT a *RedactingHandler is a no-op (the type
// assertion fails) — must not panic and must not redact.
func TestRegisterHandlerSecret_NonRedactingHandlerNoOp(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	log.RegisterHandlerSecret(logger, "another-secret-value")
	logger.Info("value: another-secret-value")
	if !bytes.Contains(buf.Bytes(), []byte("another-secret-value")) {
		t.Errorf("plain (non-redacting) handler must not redact; value missing: %s", buf.String())
	}
}
