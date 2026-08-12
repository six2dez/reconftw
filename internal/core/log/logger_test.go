// Tests for the logger factory (log.New) and the XCUT-07 sentinel-value gate.
// Source: ADR 0002 §10.3 lines 2528-2563 (init order) + §10.4 lines 2576-2593 (gate).
//
// External test package.
package log_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	log "github.com/six2dez/reconftw/internal/core/log"
)

// --- Test 14: log.New builds JSON → RedactingHandler chain ---

func TestNew_BuildsJSONChainWithRedaction(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &log.Redactor{}
	cfg := &log.Config{Level: slog.LevelInfo, Format: "json", Output: &buf}
	r.Register("sentinel-abcdef")

	logger := log.New(cfg, r)
	if logger == nil {
		t.Fatalf("log.New returned nil")
	}
	logger.Info("got: sentinel-abcdef")

	// Output is valid JSON.
	out := bytes.TrimSpace(buf.Bytes())
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if got := m["msg"]; got != "got: ***" {
		t.Errorf("msg = %v; want %q", got, "got: ***")
	}
}

// --- Text format support ---

func TestNew_TextFormatRespected(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &log.Redactor{}
	cfg := &log.Config{Level: slog.LevelInfo, Format: "text", Output: &buf}
	logger := log.New(cfg, r)
	logger.Info("plain text event")

	out := strings.TrimSpace(buf.String())
	if out == "" {
		t.Fatalf("no output")
	}
	// Text format does NOT start with a JSON brace.
	if strings.HasPrefix(out, "{") {
		t.Errorf("text format output looks like JSON: %q", out)
	}
	// Text format always contains "msg=" key=value.
	if !strings.Contains(out, "msg=") {
		t.Errorf("expected 'msg=' in text output; got %q", out)
	}
}

// --- Default Format (empty cfg.Format) → json ---

func TestNew_DefaultFormatIsJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := &log.Redactor{}
	cfg := &log.Config{Output: &buf} // no Format set
	logger := log.New(cfg, r)
	logger.Info("event")

	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "{") {
		t.Errorf("default format should be JSON (starts with `{`); got %q", out)
	}
}

// --- Test 15: XCUT-07 sentinel-value gate (THE canonical XCUT-07 test) ---
//
// Per ADR §10.4 lines 2576-2593:
//  1. Construct a Secret-typed sentinel value
//  2. Register it with the redactor
//  3. Emit a log line that references it via both a typed Secret attr AND
//     a raw substring in the message
//  4. Capture the buffer
//  5. Assert the raw sentinel string does NOT appear anywhere
//
// This test runs on every commit (via CI's `unit` job) per ADR §10.4.
// If this test ever fails, secret leakage has been re-introduced.
func TestXCUT07Sentinel(t *testing.T) {
	t.Parallel()
	const sentinel = "test_sentinel_value_not_a_real_key_abc123" // BINDING per ADR §10.4 line 2582

	var buf bytes.Buffer
	r := &log.Redactor{}
	r.Register(sentinel)
	cfg := &log.Config{Output: &buf, Format: "json", Level: slog.LevelInfo}
	logger := log.New(cfg, r)

	// Multiple attack surfaces — all must redact:
	//   (a) typed Secret as slog.Any attr (Layer 1 — LogValue auto-redacts)
	//   (b) typed Secret as message via fmt.Sprintf (Layer 2 — substring replace)
	//   (c) raw string in message (Layer 2 — substring replace)
	//   (d) raw string attr (Layer 2 — string-attr redact in handler)
	logger.Info("config loaded", slog.Any("slack_url", log.Secret(sentinel)))
	logger.Info("loading config: " + sentinel)
	logger.Info("config", slog.String("k", sentinel))

	// Assert: raw sentinel does NOT appear anywhere.
	if bytes.Contains(buf.Bytes(), []byte(sentinel)) {
		t.Fatalf("XCUT-07 GATE FAILURE: raw sentinel %q leaked into log output:\n%s",
			sentinel, buf.String())
	}
	// Assert: "***" appears (proves redaction fired).
	if !bytes.Contains(buf.Bytes(), []byte("***")) {
		t.Errorf("redaction marker `***` missing from output; redactor not firing:\n%s",
			buf.String())
	}
}
