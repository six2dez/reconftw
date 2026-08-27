// Package errors defines the 7-class typed error hierarchy used by the
// reconFTW v2 kernel. The taxonomy spans two use cases: (1) decision errors
// where the caller branches on the error type (use errors.As) and (2) signal
// errors where the caller just re-tags or logs (use errors.Is). Both are
// supported via the Is() sentinel bridge on each struct.
//
// The package name `errors` deliberately shadows the Go stdlib `errors`
// package. Internally we import stdlib as `stderrors`; external callers
// should import this package with an alias when stdlib errors is also needed:
//
//	import (
//	    stderrors "errors"
//	    errs "github.com/six2dez/reconftw/internal/core/errors"
//	)
//
// Source: ADR 0002 §6 (BINDING — lines 1771-1898).
package errors

import (
	stderrors "errors"
	"fmt"
	"strings"
	"time"
)

// --- Sentinel anchors (for errors.Is traversal) ---
//
// Callers check category with errors.Is(err, ErrTool); callers that need
// structured metadata use errors.As to unwrap to the concrete type.
//
// Six sentinels cover seven typed structs because ErrScope is shared between
// ScopeError (input-time validation failure) and OutOfScope (write-time
// rejection). Both are "scope-related" categorically, distinct types
// semantically.
var (
	ErrTool     = stderrors.New("tool execution failure")
	ErrTimeout  = stderrors.New("tool execution timeout")
	ErrScope    = stderrors.New("out of scope")
	ErrAxiom    = stderrors.New("axiom infrastructure failure")
	ErrConfig   = stderrors.New("configuration error")
	ErrChecksum = stderrors.New("checksum mismatch")
	// ErrDispatch marks a tool that NEVER RAN: the binary was absent, not
	// executable, or the process could otherwise not be started. It is a
	// REFINEMENT of ErrTool, not a sibling — errors.Is(err, ErrTool) still holds
	// for a dispatch failure, so no existing caller changes behaviour.
	//
	// WHY A TYPE AND NOT A STRING MATCH. os/exec's message for an empty Path is
	// "exec: no command"; for a missing binary it is a *fs.PathError. Matching on
	// either text is a check that passes for the wrong reason today and stops
	// passing the first time the stdlib rewords itself. The backend is the only
	// layer that KNOWS the process never started — cmd.Start() returned an error —
	// so the fact is carried out of the backend as data, on ToolError.NeverStarted.
	//
	// Origin: 16-06-PARITY §6.4 — 150 of a live run's 319 exit_non_zero outcomes
	// were absent tools wearing the wrong label, because execRecorded had no arm
	// that could tell the two apart.
	ErrDispatch = stderrors.New("tool dispatch failure: the process never started")
	// ErrPassiveViolation is returned by PassiveBackend.Exec/Stream when
	// PassiveMode=true and the tool is in the active-tool hard-block set (D-09).
	// It is a defense-in-depth sentinel; the primary guard is composition-level
	// (passive composite only schedules passive-prefixed tasks).
	ErrPassiveViolation = stderrors.New("passive mode violation: active tool blocked")
)

// --- Typed structs ---
//
// Each struct implements error, Unwrap (where applicable), and an Is()
// sentinel bridge so that errors.Is(err, ErrXxx) traverses the error chain
// correctly. Exported fields marshal cleanly to JSON for Faraday export and
// SARIF output (ARCH-08 serialization contract).

// ToolError wraps a tool exit with structured metadata.
// Used for: non-zero exit codes, tool-level parsing failures.
// Serializes to: Faraday JSON {tool, exit_code, stderr_excerpt}.
type ToolError struct {
	Tool     string // e.g. "subfinder"
	ExitCode int
	Stderr   string // last 1KB of stderr (truncated to prevent runaway allocation)
	Inner    error

	// NeverStarted is true when the PROCESS WAS NEVER CREATED — cmd.Start()
	// failed because the binary is absent, not executable, or the pipes could not
	// be opened. It is set ONLY by a backend, which is the only layer that can
	// know it, and it is read by backend.Runner to choose the outcome label.
	//
	// WHY A FIELD AND NOT A NEW TYPE. This struct is the published
	// Faraday/SARIF serialisation contract (ARCH-08): a new error type would give
	// existing report consumers a shape they have never seen. `omitempty` keeps
	// the JSON BYTE-IDENTICAL for every ToolError that is not a dispatch failure,
	// so a consumer sees no change at all except one new optional boolean on the
	// records that are dispatch failures — where ExitCode is -1 and Stderr is
	// empty by construction, because a process that never ran produced neither.
	// Error() is likewise unchanged; see TestToolError_FormatExact.
	NeverStarted bool `json:"never_started,omitempty"`
}

// renderedStderrCap bounds how much of Stderr appears in the MESSAGE. The full
// tail stays in the struct field and in logs/tools.jsonl; this only stops a
// multi-kilobyte burst from dominating a terminal line.
const renderedStderrCap = 300

func (e *ToolError) Error() string {
	base := fmt.Sprintf("tool %s (exit %d): %v", e.Tool, e.ExitCode, e.Inner)

	// The Stderr field has been carried since phase 3 and shown to NOBODY. That
	// is why every failure in the first live v2 run read "tool stream ended badly:
	// exit status 1" — the tool's own account of what went wrong was already in
	// memory, one field away, and never printed. Rendering it is the difference
	// between that string and "unable to load public resolvers: open t: no such
	// file or directory".
	//
	// Appended only when non-empty, which keeps the message byte-identical for
	// every ToolError constructed without stderr (see TestToolError_FormatExact).
	tail := strings.TrimSpace(e.Stderr)
	if tail == "" {
		return base
	}
	tail = strings.Join(strings.Fields(tail), " ") // collapse newlines/runs
	if len(tail) > renderedStderrCap {
		tail = "..." + tail[len(tail)-renderedStderrCap:]
	}
	return base + ": " + tail
}

func (e *ToolError) Unwrap() error { return e.Inner }

// Is is the sentinel bridge enabling errors.Is(err, ErrTool), and — for a tool
// whose process never started — errors.Is(err, ErrDispatch) as well. ErrTool
// keeps matching in BOTH cases: ErrDispatch narrows the category, it does not
// leave it, so no existing errors.Is(err, ErrTool) caller changes behaviour.
func (e *ToolError) Is(target error) bool {
	if target == ErrDispatch {
		return e.NeverStarted
	}
	return target == ErrTool
}

// IsDispatchFailure reports whether err anywhere in its chain is a tool that
// never ran. Provided so callers do not have to know that the fact lives on
// ToolError.NeverStarted, and so the check can never degrade into a string match.
func IsDispatchFailure(err error) bool { return stderrors.Is(err, ErrDispatch) }

// ToolTimeout is returned when a tool's per-task context deadline is exceeded.
type ToolTimeout struct {
	Tool    string
	Timeout time.Duration
}

func (e *ToolTimeout) Error() string {
	return fmt.Sprintf("tool %s timed out after %v", e.Tool, e.Timeout)
}

// Is is the sentinel bridge enabling errors.Is(err, ErrTimeout).
func (e *ToolTimeout) Is(target error) bool { return target == ErrTimeout }

// OutOfScope is returned by OutputTree.Append when a finding fails scope check.
// The scope filter is enforced at the OutputTree.Append boundary, not inside
// Task.Run(); Tasks do NOT own scope filtering (T-02-04-01 mitigation).
type OutOfScope struct {
	Value  string // the rejected value (domain, IP, URL)
	Reason string // e.g. "not in wildcard *.example.com"
}

func (e *OutOfScope) Error() string {
	return fmt.Sprintf("out of scope: %s (%s)", e.Value, e.Reason)
}

// Is is the sentinel bridge enabling errors.Is(err, ErrScope).
func (e *OutOfScope) Is(target error) bool { return target == ErrScope }

// AxiomFailure signals an Axiom dispatch that must retry locally. Most values
// represent infrastructure failure (SSH timeout, fleet unreachable); Capability
// marks a healthy transport that cannot carry this invocation shape. It is
// distinct from ToolError because it triggers FailoverBackend local fallback.
// The Axiom fleet credentials (SSH key, fleet token)
// flow through tool stderr and may be echoed in ssh client error strings;
// use Redactor.Redact() on the inner error string before constructing this
// value. (ADR §6 PITFALL NOTE; T-02-04-05)
//
// SECURITY NOTE: Inner MUST NOT contain raw credential values.
type AxiomFailure struct {
	Operation string // operation that failed, such as "exec_opts" or "healthcheck"
	Inner     error
	// Capability is true when the fleet transport is healthy but cannot carry
	// this invocation shape (for example stdin, cwd, or child env). Failover must
	// still retry locally, but this refusal must not count toward the fleet
	// kill-switch.
	Capability bool
}

func (e *AxiomFailure) Error() string {
	return fmt.Sprintf("axiom %s: %v", e.Operation, e.Inner)
}

func (e *AxiomFailure) Unwrap() error { return e.Inner }

// Is is the sentinel bridge enabling errors.Is(err, ErrAxiom).
func (e *AxiomFailure) Is(target error) bool { return target == ErrAxiom }

// ConfigError is returned during config load/validation with file:line context.
// Violating the "no raw value" rule causes secret leak via error logging — the
// redactor's two-layer defense (ADR §10) cannot scrub a value the config loader
// didn't register yet (chicken-and-egg). The contract is enforced by code review
// and the XCUT-07 sentinel-value CI gate (ADR §10.4). (T-02-04-02)
//
// SECURITY NOTE: Message MUST NOT include raw secret values; say "invalid URL format" not the URL.
type ConfigError struct {
	File    string
	Line    int
	Key     string
	Message string // human-readable description — NEVER the raw value
}

func (e *ConfigError) Error() string {
	return fmt.Sprintf("%s:%d key %q: %s", e.File, e.Line, e.Key, e.Message)
}

// Is is the sentinel bridge enabling errors.Is(err, ErrConfig).
func (e *ConfigError) Is(target error) bool { return target == ErrConfig }

// ScopeError wraps domain/IP validation failures at input time.
// Distinct from OutOfScope (which is a write-time rejection) — ScopeError is
// returned when the input itself is structurally invalid (metacharacters,
// bad CIDR). Both share the ErrScope sentinel to allow a single
// errors.Is(_, ErrScope) call to catch both classes.
type ScopeError struct {
	Input  string
	Reason string // e.g. "domain contains shell metacharacters", "IP octet out of range"
}

func (e *ScopeError) Error() string {
	return fmt.Sprintf("scope validation: %q rejected: %s", e.Input, e.Reason)
}

// Is is the sentinel bridge enabling errors.Is(err, ErrScope).
func (e *ScopeError) Is(target error) bool { return target == ErrScope }

// PassiveViolation is returned by PassiveBackend.Exec/Stream when the tool
// is in the active-tool hard-block set and PassiveMode=true (D-09).
type PassiveViolation struct {
	Tool string // tool name that was blocked (e.g. "puredns", "nmap")
}

func (e *PassiveViolation) Error() string {
	return fmt.Sprintf("passive mode violation: active tool %q is blocked in passive mode", e.Tool)
}

// Is is the sentinel bridge enabling errors.Is(err, ErrPassiveViolation), and
// also ErrDispatch.
//
// WHY A PASSIVE BLOCK IS A DISPATCH FAILURE. PassiveBackend implements
// Exec/ExecEnv/Stream/StreamEnv and refuses the call BEFORE the inner backend is
// reached, so the process is never created — which is what OutcomeDispatchFailed
// means, and its documented set already includes a policy abort (the rate
// limiter's), not only an absent binary. Without this bridge a blocked tool would
// be recorded as `exit_non_zero`: a claim that it ran and failed, about a tool
// that was deliberately not run. That is the same false statement plan 17-02
// exists to remove, and it would be harder to spot here because in passive mode
// it is the EXPECTED outcome.
//
// errors.Is(err, ErrPassiveViolation) is unaffected, so the reason a caller
// distinguishes a policy block from an absent binary remains available.
func (e *PassiveViolation) Is(target error) bool {
	return target == ErrPassiveViolation || target == ErrDispatch
}

// ChecksumMismatch is returned by the installer when a downloaded binary or
// script does not match its expected SHA-256 hash.
type ChecksumMismatch struct {
	URL      string
	Expected string // full SHA-256 hex
	Got      string // full SHA-256 hex
}

// Error formats the hashes as first-8-hex-chars + "..." to keep the error
// string compact. Defensive bound: if either hash is < 8 chars, the entire
// string is used (no out-of-range panic).
func (e *ChecksumMismatch) Error() string {
	return fmt.Sprintf("checksum mismatch for %s: expected %s got %s",
		e.URL, truncateHashHex(e.Expected), truncateHashHex(e.Got))
}

// Is is the sentinel bridge enabling errors.Is(err, ErrChecksum).
func (e *ChecksumMismatch) Is(target error) bool { return target == ErrChecksum }

// truncateHashHex returns hash[:8]+"..." when hash is at least 8 chars long;
// otherwise returns hash unchanged (defensive — no panic on malformed input).
func truncateHashHex(hash string) string {
	if len(hash) < 8 {
		return hash
	}
	return hash[:8] + "..."
}
