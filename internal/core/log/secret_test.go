// Tests for the Secret type (Layer 1 of two-layer redaction defense).
// Source: ADR 0002 §10.1 lines 2356-2407 (BINDING — no String() method).
//
// External test package — exercises only the public API.
package log_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"testing"

	log "github.com/six2dez/reconftw/internal/core/log"
)

// --- Test 1: Secret.LogValue() returns "***" ---

func TestSecret_LogValueReturnsRedaction(t *testing.T) {
	t.Parallel()
	s := log.Secret("supersecret-token-abc-12345")
	val := s.LogValue()
	got := val.String()
	if got != "***" {
		t.Errorf("LogValue() = %q; want %q", got, "***")
	}
}

// --- Test 2: Secret typed slog Attr auto-redacts in actual JSON output ---

func TestSecret_AutoRedactsInSlogJSONOutput(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	mySecret := log.Secret("my-actual-secret-value-xyz789")
	logger.Info("event", slog.Any("token", mySecret))

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if got, ok := record["token"]; !ok {
		t.Fatalf("token attr missing from record; raw: %s", buf.String())
	} else if got != "***" {
		t.Errorf("token attr = %v; want %q", got, "***")
	}
	// Defensive: the raw secret MUST NOT appear anywhere in the output.
	if bytes.Contains(buf.Bytes(), []byte("my-actual-secret-value-xyz789")) {
		t.Errorf("raw secret leaked into log output: %s", buf.String())
	}
}

// --- Test 3: Secret has NO String() method (XCUT-07 type-level invariant) ---
//
// Per ADR §10.1 BINDING: the absence of String() prevents fmt.Sprintf("%s", s)
// from exposing the raw value. We verify via reflection that the method does
// not exist on the Secret type's method set.
func TestSecret_HasNoStringMethod(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeOf(log.Secret(""))
	if _, ok := typ.MethodByName("String"); ok {
		t.Errorf("log.Secret has a String() method; BINDING per ADR §10.1 forbids it")
	}

	// Sanity: %s formatting falls back to default string-conversion of the
	// underlying type. This means raw values WILL leak via %s — but only when
	// no Secret wrapping is used at the call site (which is the Layer 2 reason).
	// The point of this test is the absence of the method, not the %s behavior.
	raw := "untyped"
	s := log.Secret(raw)
	_ = fmt.Sprintf("%s", s) // compile sanity: no panic, no specific assertion
}

// --- Test 4: Explicit string() cast extracts the raw value ---
//
// Per ADR §10.1: callers needing the raw value (e.g., to call Redactor.Register)
// MUST use string(mySecret). This is the sanctioned escape hatch and makes the
// security-sensitive operation visible in code review.
func TestSecret_ExplicitCastRecoversValue(t *testing.T) {
	t.Parallel()
	const raw = "supersecret-token-abc-12345"
	s := log.Secret(raw)
	if got := string(s); got != raw {
		t.Errorf("string(Secret) = %q; want %q", got, raw)
	}
}
