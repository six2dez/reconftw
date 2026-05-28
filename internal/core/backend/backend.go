// Package backend defines the subprocess execution abstraction for reconFTW v2.
//
// The Backend interface (ADR §5.2 lines 1616-1691, BINDING) is implemented by:
//   - LocalBackend: kill-tree-safe `os/exec` wrapper (ports spike/go/internal/proc/proc.go)
//   - AxiomBackend: Phase 3 compile-only stub returning *AxiomFailure; Phase 4 ships the
//     real SSH-fleet implementation.
//
// Tasks NEVER call a Backend directly. They call `app.Tools.Run(ctx, toolName, args)`
// which dispatches through the Runner (registry lookup → rate-limit gate → Backend.Exec)
// and back. This indirection is what allows the AxiomBackend swap to be transparent to
// Tasks and what gives the FOUND-10 lint rule a single allowlisted exec.Command call site
// (LocalBackend.Exec/Stream).
//
// Source-of-truth: .planning/decisions/0002-architecture-v2.md §5.2 (BINDING signatures).
// Pre-sign verification: cmd/interfaces_check/main.go mirrors the placeholder shapes.
package backend

import (
	"context"
	"time"
)

// Event is a single streaming output unit from a running tool.
//
// Source: ADR §5.2 lines 1636-1641.
type Event struct {
	Line   []byte // raw stdout/stderr line (no trailing newline)
	Source string // tool name, e.g. "nuclei"
	IsErr  bool   // true if line came from stderr
}

// Result holds the complete output of a buffered Exec call.
//
// Source: ADR §5.2 lines 1643-1649.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// Tool describes a single external binary. Resolved at startup by ToolRegistry
// via exec.LookPath and version detection.
//
// BINDING-NOTE (revision iter 1, Blocker 5): The `Critical` field is added as a
// non-breaking extension per ADR §0 D-07. Phase 3 Plan 04 introduces it; Phase 4+
// tools.lock entries declare per-tool criticality. The field is zero-valued (false)
// for any tool that does not set it explicitly — preserving backward compatibility
// with the ADR §5.2 BINDING shape (lines 1651-1659).
//
// FOUND-08 (REQUIREMENTS.md line 47) calls for two tiers of missing-tool handling:
//   - "warn on missing-but-required"  → tool is in registry but absent from PATH AND Critical=false
//   - "fail on missing-and-critical"  → tool is in registry but absent from PATH AND Critical=true
//
// ToolRegistry.MissingRequired() returns the union of both tiers; MissingCritical()
// returns only the latter.
type Tool struct {
	Name        string
	Path        string        // absolute path from exec.LookPath
	Version     string        // parsed from `tool --version` at health-check
	DefaultArgs []string
	Timeout     time.Duration // per-invocation timeout; 0 = no timeout
	Critical    bool          // FOUND-08 missing-and-critical tier (Blocker 5; ADR §0 D-07 non-breaking field)
	// InputFlag is the CLI flag (or empty string for positional last arg) that
	// receives the input file in Axiom fleet splits. E.g. puredns uses
	// InputFlag="" (positional), dnsx uses InputFlag="-l", tlsx uses
	// InputFlag="-l", s3scanner uses InputFlag="--bucket-file". Empty string =
	// positional last argument. Used by AxiomBackend.Exec to split the correct
	// argument; prevents the extractInputFile heuristic bug (REVIEWS finding #5).
	InputFlag string
}

// Backend abstracts local subprocess execution from distributed (Axiom) execution.
//
// Implementations: LocalBackend (default), AxiomBackend (when axiom.enabled = true).
// BINDING: adding methods is non-breaking (ADR §0 D-07); renaming, removing, or
// changing method signatures requires an ADR amendment (ADR §0 D-06).
//
// Source: ADR §5.2 lines 1661-1690.
type Backend interface {
	// Exec runs tool with args, buffers stdout+stderr, returns when done.
	// Suitable for tools with bounded, short-lived output (subfinder, dnsx, crt).
	// The tool's process group is killed on ctx cancellation.
	Exec(ctx context.Context, t *Tool, args []string) (*Result, error)

	// Stream runs tool with args, yields stdout and stderr lines as Events on
	// the returned channel. Channel closes when tool exits (clean or error).
	// Suitable for long-running tools (nuclei, dalfox, katana).
	// Caller MUST drain the channel until closed to avoid goroutine leak.
	//
	// Phase 8 MCP server wraps this channel via SSE notifications; see ADR §5.2
	// MCP integration note. Backend.Stream() shape is sufficient for MCP —
	// no protocol-level change anticipated.
	Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error)

	// HealthCheck verifies the backend is operational (binaries reachable,
	// axiom fleet up and authenticated). Called at startup and by the
	// `reconftw health-check` subcommand. Returns nil if healthy.
	HealthCheck(ctx context.Context) error

	// Capacity returns the number of concurrent tool invocations this backend
	// supports. LocalBackend returns runtime.NumCPU() * 2; AxiomBackend returns
	// the configured fleet_count. Used by Scheduler as a hint for SetLimit(N).
	Capacity() int
}
