// Tests for the 7-class typed error hierarchy and 6 sentinel anchors.
// Source: ADR 0002 §6 lines 1771-1898 (canonical); §9.2 names this test set as
// the Ring 1 canonical example.
//
// External test package — exercises only the package's public API.
package errors_test

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	errs "github.com/six2dez/reconftw/internal/core/errors"
)

// --- Test 6: All 7 typed structs implement the error interface ---

var (
	_ error = (*errs.ToolError)(nil)
	_ error = (*errs.ToolTimeout)(nil)
	_ error = (*errs.OutOfScope)(nil)
	_ error = (*errs.AxiomFailure)(nil)
	_ error = (*errs.ConfigError)(nil)
	_ error = (*errs.ScopeError)(nil)
	_ error = (*errs.ChecksumMismatch)(nil)
)

// --- Test 8: Sentinel anchors registry — all 6 are non-nil ---

func TestSentinelAnchorsExistAndAreNonNil(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
	}{
		{"ErrTool", errs.ErrTool},
		{"ErrTimeout", errs.ErrTimeout},
		{"ErrScope", errs.ErrScope},
		{"ErrAxiom", errs.ErrAxiom},
		{"ErrConfig", errs.ErrConfig},
		{"ErrChecksum", errs.ErrChecksum},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err == nil {
				t.Fatalf("sentinel %s is nil; want non-nil", tc.name)
			}
			if tc.err.Error() == "" {
				t.Errorf("sentinel %s has empty Error(); want descriptive message", tc.name)
			}
		})
	}
}

// --- Test 1: errors.Is sentinel bridge works for every typed type ---

func TestErrTool_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.ToolError{Tool: "subfinder", ExitCode: 2}
	if !stderrors.Is(e, errs.ErrTool) {
		t.Errorf("Is(err, ErrTool) = false; want true")
	}
}

func TestErrToolTimeout_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.ToolTimeout{Tool: "httpx", Timeout: 30 * time.Second}
	if !stderrors.Is(e, errs.ErrTimeout) {
		t.Errorf("Is(err, ErrTimeout) = false; want true")
	}
}

func TestErrOutOfScope_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.OutOfScope{Value: "evil.com", Reason: "not in wildcard *.example.com"}
	if !stderrors.Is(e, errs.ErrScope) {
		t.Errorf("Is(err, ErrScope) = false; want true")
	}
}

func TestErrAxiom_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.AxiomFailure{Operation: "exec", Inner: stderrors.New("ssh timeout")}
	if !stderrors.Is(e, errs.ErrAxiom) {
		t.Errorf("Is(err, ErrAxiom) = false; want true")
	}
}

func TestErrConfig_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.ConfigError{File: "/tmp/c.toml", Line: 42, Key: "slack.webhook_url", Message: "invalid URL format"}
	if !stderrors.Is(e, errs.ErrConfig) {
		t.Errorf("Is(err, ErrConfig) = false; want true")
	}
}

func TestErrScopeError_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.ScopeError{Input: "ex;rm -rf .com", Reason: "domain contains shell metacharacters"}
	if !stderrors.Is(e, errs.ErrScope) {
		t.Errorf("Is(err, ErrScope) = false; want true")
	}
}

func TestErrChecksumMismatch_IsSentinel(t *testing.T) {
	t.Parallel()
	e := &errs.ChecksumMismatch{
		URL:      "https://example.com/binary",
		Expected: "abcdef0123456789",
		Got:      "1234567890abcdef",
	}
	if !stderrors.Is(e, errs.ErrChecksum) {
		t.Errorf("Is(err, ErrChecksum) = false; want true")
	}
}

// --- Test 2: errors.As traversal through fmt.Errorf %w wrapping ---

func TestErrTool_AsThroughWrap(t *testing.T) {
	t.Parallel()
	inner := &errs.ToolError{Tool: "subfinder", ExitCode: 2, Inner: io.EOF}
	wrapped := fmt.Errorf("subfinder: %w", inner)

	var te *errs.ToolError
	if !stderrors.As(wrapped, &te) {
		t.Fatalf("As(wrapped, &te) = false; want true")
	}
	if te.Tool != "subfinder" {
		t.Errorf("te.Tool = %q; want %q", te.Tool, "subfinder")
	}
	if te.ExitCode != 2 {
		t.Errorf("te.ExitCode = %d; want %d", te.ExitCode, 2)
	}
	// And Is() still works across the wrap:
	if !stderrors.Is(wrapped, errs.ErrTool) {
		t.Errorf("Is(wrapped, ErrTool) = false; want true (Unwrap chain)")
	}
}

func TestErrAxiom_AsThroughWrap(t *testing.T) {
	t.Parallel()
	innerOriginal := stderrors.New("ssh handshake failed")
	a := &errs.AxiomFailure{Operation: "healthcheck", Inner: innerOriginal}
	wrapped := fmt.Errorf("fleet boot: %w", a)

	var af *errs.AxiomFailure
	if !stderrors.As(wrapped, &af) {
		t.Fatalf("As(wrapped, &af) = false; want true")
	}
	if af.Operation != "healthcheck" {
		t.Errorf("af.Operation = %q; want %q", af.Operation, "healthcheck")
	}
	if af.Inner != innerOriginal {
		t.Errorf("af.Inner not preserved through wrap")
	}
}

// --- Test 3: ToolError.Error() format stability + no secret leak ---

func TestToolError_FormatExact(t *testing.T) {
	t.Parallel()
	e := &errs.ToolError{Tool: "x", ExitCode: 1, Inner: io.EOF}
	want := "tool x (exit 1): EOF"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestToolError_Unwrap(t *testing.T) {
	t.Parallel()
	inner := stderrors.New("custom")
	e := &errs.ToolError{Tool: "x", ExitCode: 1, Inner: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v; want %v", got, inner)
	}
}

// --- Test 4: ConfigError format — no raw value, just field + violation ---

func TestConfigError_FormatNoRawValue(t *testing.T) {
	t.Parallel()
	e := &errs.ConfigError{
		File:    "/tmp/c.toml",
		Line:    42,
		Key:     "slack.webhook_url",
		Message: "invalid URL format",
	}
	want := `/tmp/c.toml:42 key "slack.webhook_url": invalid URL format`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
	// Defensive regression: the message MUST NOT contain any raw URL-shaped value
	// (this test is a smoke test for the rule, not a regex check of the formatter).
	if strings.Contains(e.Error(), "http://") || strings.Contains(e.Error(), "https://") {
		t.Errorf("ConfigError leaked URL substring; got %q", e.Error())
	}
}

// --- Test 5: AxiomFailure.Is(ErrAxiom) returns true ---

func TestAxiomFailure_IsErrAxiom(t *testing.T) {
	t.Parallel()
	e := &errs.AxiomFailure{Operation: "exec", Inner: stderrors.New("ssh timeout")}
	if !e.Is(errs.ErrAxiom) {
		t.Errorf("AxiomFailure.Is(ErrAxiom) = false; want true")
	}
	if e.Is(errs.ErrTool) {
		t.Errorf("AxiomFailure.Is(ErrTool) = true; want false (sentinel bridge must be strict)")
	}
}

func TestAxiomFailure_Unwrap(t *testing.T) {
	t.Parallel()
	inner := stderrors.New("inner")
	e := &errs.AxiomFailure{Operation: "exec", Inner: inner}
	if got := e.Unwrap(); got != inner {
		t.Errorf("Unwrap() = %v; want %v", got, inner)
	}
}

// --- Test 7: ChecksumMismatch truncates SHA-256 hex to first 8 chars + "..." ---

func TestChecksumMismatch_TruncatesHashes(t *testing.T) {
	t.Parallel()
	full := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	e := &errs.ChecksumMismatch{
		URL:      "https://example.com/binary",
		Expected: full,
		Got:      "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
	}
	got := e.Error()
	wantSubstrings := []string{
		"checksum mismatch for https://example.com/binary",
		"expected " + full[:8] + "...",
		"got " + "12345678" + "...",
	}
	for _, w := range wantSubstrings {
		if !strings.Contains(got, w) {
			t.Errorf("Error() = %q; want substring %q", got, w)
		}
	}
	// Defensive: full hash MUST NOT appear verbatim in the error string
	if strings.Contains(got, full) {
		t.Errorf("Error() contains full hash; want truncated. Got: %q", got)
	}
}

// Defensive bounds: if hash is < 8 chars, truncation MUST NOT panic.
func TestChecksumMismatch_ShortHashNoPanic(t *testing.T) {
	t.Parallel()
	e := &errs.ChecksumMismatch{URL: "https://x", Expected: "abc", Got: "def"}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Error() panicked on short hash: %v", r)
		}
	}()
	_ = e.Error()
}

// --- Additional traversal tests: ToolTimeout, OutOfScope, ScopeError formatting ---

func TestToolTimeout_FormatExact(t *testing.T) {
	t.Parallel()
	e := &errs.ToolTimeout{Tool: "puredns", Timeout: 5 * time.Minute}
	want := "tool puredns timed out after 5m0s"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestOutOfScope_FormatExact(t *testing.T) {
	t.Parallel()
	e := &errs.OutOfScope{Value: "evil.com", Reason: "not in wildcard *.example.com"}
	want := "out of scope: evil.com (not in wildcard *.example.com)"
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

func TestScopeError_FormatExact(t *testing.T) {
	t.Parallel()
	e := &errs.ScopeError{Input: "ex;rm -rf .com", Reason: "domain contains shell metacharacters"}
	want := `scope validation: "ex;rm -rf .com" rejected: domain contains shell metacharacters`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q; want %q", got, want)
	}
}

// Both ScopeError and OutOfScope share the ErrScope sentinel (distinct types,
// distinct semantics; both signal "scope-related failure"). Verify both bridge correctly.
func TestErrScope_SharedBetweenScopeErrorAndOutOfScope(t *testing.T) {
	t.Parallel()
	se := &errs.ScopeError{Input: "x", Reason: "y"}
	oos := &errs.OutOfScope{Value: "x", Reason: "y"}
	if !stderrors.Is(se, errs.ErrScope) {
		t.Errorf("Is(ScopeError, ErrScope) = false; want true")
	}
	if !stderrors.Is(oos, errs.ErrScope) {
		t.Errorf("Is(OutOfScope, ErrScope) = false; want true")
	}
}

// --- plan 17-02 / TC-C: the dispatch distinction, and its serialisation cost ---

// TestErrDispatch_NarrowsErrToolRatherThanReplacingIt.
//
// ErrDispatch has to be a REFINEMENT of ErrTool. If it were a sibling, every
// existing `errors.Is(err, ErrTool)` caller — the whole reason the sentinel exists
// — would silently stop matching for exactly the failures this plan is about.
func TestErrDispatch_NarrowsErrToolRatherThanReplacingIt(t *testing.T) {
	t.Parallel()
	never := &errs.ToolError{Tool: "dnsx", ExitCode: -1, Inner: io.EOF, NeverStarted: true}
	ran := &errs.ToolError{Tool: "dnsx", ExitCode: 1, Inner: io.EOF}

	if !stderrors.Is(never, errs.ErrTool) {
		t.Error("a dispatch failure no longer matches ErrTool — every existing caller that branches " +
			"on ErrTool has silently stopped seeing it")
	}
	if !stderrors.Is(never, errs.ErrDispatch) {
		t.Error("a ToolError with NeverStarted=true does not match ErrDispatch")
	}
	if stderrors.Is(ran, errs.ErrDispatch) {
		t.Error("a tool that RAN and exited 1 matches ErrDispatch — the distinction is inverted, " +
			"which is worse than not having it")
	}
	if !stderrors.Is(ran, errs.ErrTool) {
		t.Error("an ordinary tool failure no longer matches ErrTool")
	}
}

// TestIsDispatchFailure_TraversesWrapping.
//
// The fact travels from a backend through the Runner and, on the failover path,
// through a wrapper. A predicate that only works on an unwrapped value would go
// quietly false on the distributed path — where this defect is hardest to see.
func TestIsDispatchFailure_TraversesWrapping(t *testing.T) {
	t.Parallel()
	never := &errs.ToolError{Tool: "cmseek", ExitCode: -1, NeverStarted: true, Inner: io.EOF}
	wrapped := fmt.Errorf("stage subdomains.takeover: %w", never)

	if !errs.IsDispatchFailure(wrapped) {
		t.Error("IsDispatchFailure sees through no wrapping — a fact that does not survive one " +
			"fmt.Errorf is not a fact the system can rely on")
	}
	if errs.IsDispatchFailure(nil) {
		t.Error("IsDispatchFailure(nil) is true")
	}
	if errs.IsDispatchFailure(stderrors.New("plain")) {
		t.Error("IsDispatchFailure is true for an unrelated error")
	}
}

// TestToolError_NeverStartedDoesNotChangeTheRenderedMessage pins the half of the
// published contract a human reads. TestToolError_FormatExact covers the ordinary
// case; this one covers the new field, which must be invisible in the message.
func TestToolError_NeverStartedDoesNotChangeTheRenderedMessage(t *testing.T) {
	t.Parallel()
	with := (&errs.ToolError{Tool: "x", ExitCode: 1, Inner: io.EOF, NeverStarted: true}).Error()
	without := (&errs.ToolError{Tool: "x", ExitCode: 1, Inner: io.EOF}).Error()
	if with != without {
		t.Errorf("Error() differs with NeverStarted set:\n  with:    %q\n  without: %q", with, without)
	}
}

// TestToolError_JSONUnchangedForNonDispatchFailures is the reversibility
// assertion from the plan's <reversibility rating="costly">.
//
// This struct is the published Faraday/SARIF serialisation contract (ARCH-08).
// The change is additive AND `omitempty`, so an existing report consumer sees
// BYTE-IDENTICAL JSON for every error that is not a dispatch failure, and one new
// optional boolean on the ones that are. Asserted rather than asserted-about: a
// later "tidy-up" that drops omitempty would start emitting `"never_started":false`
// on every record in every report, and nothing else would notice.
func TestToolError_JSONUnchangedForNonDispatchFailures(t *testing.T) {
	t.Parallel()
	ran := &errs.ToolError{Tool: "sourcemapper", ExitCode: 1, Stderr: "non-200"}
	b, err := json.Marshal(ran)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "never_started") {
		t.Errorf("a tool that RAN serialises with a never_started key: %s\n"+
			"Faraday and SARIF consumers see this shape; the new field must be absent unless true.", b)
	}

	never := &errs.ToolError{Tool: "cmseek", ExitCode: -1, NeverStarted: true}
	b2, err := json.Marshal(never)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b2), `"never_started":true`) {
		t.Errorf("a dispatch failure does not serialise the fact: %s", b2)
	}
}
