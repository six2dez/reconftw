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
	// Err is set on a FINAL event when the stream did not end cleanly: the
	// scanner overflowed (a line longer than scannerMaxBuf, which silently
	// truncates the tool's output) or the process exited non-zero.
	//
	// Both used to be discarded with `_ =`, so a tool that crashed halfway
	// through, or whose output was cut off mid-stream, was indistinguishable
	// from one that completed successfully — the consumer just saw the channel
	// close. Consumers that ignore this field behave exactly as before.
	Err error
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
	Name string
	Path string // absolute path from exec.LookPath
	// Version is the PINNED version from tools.lock (INST-02 / XCUT-08),
	// populated at init() from the embedded manifest. The installer (INST-11)
	// and `install --health-check` (INST-10) compare it against the probed
	// installed version (`go version -m` / `uv tool list`) for D-04 idempotency.
	Version string
	// Install metadata copied from tools.lock so the Phase 11 installer can
	// resolve each tool's install coordinate off backend.Default without
	// re-parsing the manifest (INST-02/05/06/07/08/09).
	Kind         string // go | python | system | rust | go_clone | python_venv
	GoModule     string // Go module path for `go install <go_module>@<version>` (kind=go)
	PipPackage   string // uv/pip target for `uv tool install <pip_package>==<version>` (kind=python)
	RepoURL      string // git URL for repo-clone build (kind=go_clone | python_venv)
	CargoPackage string // cargo crate/path for `cargo install` (kind=rust)
	Sha256       string // expected SHA-256 for downloaded binaries/bootstrappers (INST-03/04); "" for go.sum/PyPI-backed kinds (D-01)
	DefaultArgs  []string
	Timeout      time.Duration // per-invocation timeout; 0 = no timeout
	Critical     bool          // FOUND-08 missing-and-critical tier (Blocker 5; ADR §0 D-07 non-breaking field)
	// InputFlag is the CLI flag (or empty string for positional last arg) that
	// receives the input file in Axiom fleet splits. E.g. puredns uses
	// InputFlag="" (positional), dnsx uses InputFlag="-l", tlsx uses
	// InputFlag="-l", s3scanner uses InputFlag="--bucket-file". Empty string =
	// positional last argument. Used by AxiomBackend.Exec to split the correct
	// argument; prevents the extractInputFile heuristic bug (REVIEWS finding #5).
	InputFlag string

	// ArgvPrefix is prepended to the command line AHEAD of DefaultArgs, for tools
	// whose executable is not a single binary — an interpreter plus a script path
	// (e.g. Path="/usr/bin/python3", ArgvPrefix=["/home/u/Tools/regulator/main.py"]).
	// The prefix is part of the executable's IDENTITY, which is why it precedes
	// DefaultArgs: DefaultArgs are flags TO the program the prefix names.
	//
	// Declared here (18-01); POPULATED by ToolRegistry.Discover in plan 18-02 from
	// the tools.lock clone coordinates. Zero value = today's behaviour exactly.
	ArgvPrefix []string

	// WorkDir is the working directory the tool's process is started in. Some
	// repo-clone tools resolve their own data files (wordlists, configs) relative
	// to their clone root and therefore cannot run from an arbitrary cwd.
	//
	// Precedence: ExecOptions.Dir wins over Tool.WorkDir; when neither is set the
	// child inherits the parent's working directory (today's behaviour).
	//
	// Declared here (18-01); POPULATED by ToolRegistry.Discover in plan 18-02.
	WorkDir string

	// ---- Repo-clone coordinates (18-02) -----------------------------------
	//
	// A large minority of reconFTW's inventory is not installed as a binary on
	// PATH at all: install.sh clones the repo under the tools root and builds a
	// per-tool virtualenv inside it. exec.LookPath cannot see any of those, so
	// before 18-02 they were reported "missing" while sitting on disk, and every
	// module that wanted one reached into $HOME/Tools itself — the FOUND-10
	// bypass this phase exists to close.
	//
	// All three are RELATIVE paths and are DECLARED in tools.lock, never derived
	// from Name. `cmseek` lives in a directory called `CMSeeK`: a name-derived
	// guess resolves on macOS (case-insensitive filesystem) and fails on Linux,
	// where scans actually run. TestEveryDeclaredCloneEntryIsRelative refuses an
	// absolute or upward-traversing value, because the containment check in
	// Discover works by JOINING under the tools root and an absolute path would
	// bypass it by never being joined (T-18-02-02).

	// CloneDir is the clone's directory, relative to the configured tools root
	// (paths.tools_dir, default $HOME/Tools). Empty = this tool is not a clone.
	CloneDir string

	// CloneEntry is the executable or script to run, relative to CloneDir.
	CloneEntry string

	// CloneInterpreter is optional and relative to CloneDir. When set IT becomes
	// Tool.Path and CloneEntry becomes Tool.ArgvPrefix (regulator:
	// venv/bin/python3 + main.py). When empty, CloneEntry is Tool.Path and there
	// is no prefix (gato: a console script at venv/bin/gato).
	CloneInterpreter string

	// CloneWorkDir opts the tool in to running WITH ITS CLONE DIRECTORY AS CWD —
	// i.e. it is what makes Discover populate WorkDir.
	//
	// IT IS OPT-IN, AND THAT IS A CORRECTNESS REQUIREMENT, NOT A PREFERENCE.
	// reconFTW's default workspace root is the RELATIVE "workspaces" (see
	// cmd/reconftw/root.go's -o default and workspaceRootOrFallback's own comment:
	// "an empty configured root means the workspace lands in ./workspaces relative
	// to cwd"). Modules build tool arguments with
	// filepath.Join(app.Target.WorkDir, ...), so under the default config those
	// argv paths are CWD-RELATIVE. Changing a tool's cwd to its clone directory
	// therefore re-points every one of its input and output paths into ~/Tools —
	// regulator's `-f inputs/resolved.merged.txt` would resolve under
	// ~/Tools/regulator and find nothing.
	//
	// So the default is OFF: a clone tool inherits the process cwd exactly as it
	// does today, and only a tool with a DEMONSTRATED need for its own directory
	// declares clone_workdir. nomore403 is that tool — it resolves its payload
	// wordlists relative to its own clone root, which is why web/nomore403.go and
	// vulns/bypass4xx.go already set cmd.Dir by hand today.
	//
	// Pinned in both directions by TestDiscoverSetsWorkDirOnlyWhenDeclared.
	CloneWorkDir bool
}

// ExecOptions carries the per-invocation execution options that the name-keyed
// Backend/Runner seam could not express before plan 18-01. Its absence is the
// stated justification on every FOUND-10 allowlist entry that pipes stdin.
//
// BACKWARD-COMPAT CONTRACT (ADR §0 D-07), identical in force to the one ExecEnv
// already states: a ZERO-VALUED ExecOptions MUST behave byte-for-byte as Exec.
// Exec is ExecOpts with a zero struct and ExecEnv is ExecOpts with only Env set,
// so there is exactly one code path per mode and nil-option callers are provably
// unchanged.
//
// STDIN IS []byte AND NOT AN io.Reader, DELIBERATELY. FailoverBackend dispatches
// to its fallback leg as a SECOND call after the primary fails (failover.go
// ExecEnv). An io.Reader is consumed once, so a retry would re-read an exhausted
// reader and hand the tool an EMPTY standard input — silently, producing zero
// findings and a clean exit, indistinguishable from a genuinely empty result.
// That is the outcome-mislabelling shape phase 16 spent two plans removing.
// []byte and a file path are both re-readable.
//
// Recorded nuance (operator decision, 2026-08-26): today's AxiomBackend refuses a
// stdin dispatch BEFORE reading, so on that particular path the reader would not
// in fact be exhausted. The hazard is therefore STRUCTURAL rather than a
// demonstrated defect on that route — and the type is fixed by ADR amendment
// procedure once set, so it is chosen against any FUTURE primary that consumes
// before failing.
//
// Residual cost, stated rather than hidden: Stdin holds the whole payload in
// memory. Every existing call site already does exactly that (strings.Join /
// bytes.NewReader); StdinPath is the escape hatch when a corpus is large.
type ExecOptions struct {
	// Env is a set of "KEY=VALUE" entries appended onto the os.Environ()
	// baseline for the child process. Same contract as ExecEnv's env parameter.
	Env []string

	// Stdin is written to the child's standard input. MUTUALLY EXCLUSIVE with
	// StdinPath: setting BOTH is a programming error which the implementation
	// REPORTS as a typed error before creating any process, rather than silently
	// resolving in favour of one. A nil Stdin with an empty StdinPath leaves the
	// child's stdin exactly as it is today.
	Stdin []byte

	// StdinPath names a file whose contents are piped to the child's standard
	// input. The backend opens it and closes it after the process is reaped.
	// Prefer this over Stdin for large corpora. Mutually exclusive with Stdin.
	//
	// The PATH is never echoed into the invocation record (T-18-01-02); only the
	// resolved tool name and argv are recorded, exactly as today.
	StdinPath string

	// Dir is the working directory for the child process. Takes precedence over
	// Tool.WorkDir; when both are empty the child inherits the parent's cwd.
	Dir string
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

	// ExecEnv is Exec with an additional set of "KEY=VALUE" environment entries
	// appended onto the os.Environ() baseline for the child process. This is the
	// secret-safe seam used to pass tokens (e.g. GH_TOKEN) into a tool's child
	// environment WITHOUT placing them on argv (which would leak into the process
	// listing) — ARCH-02 (v2 never passes secrets as CLI args).
	//
	// Backward-compat contract (ADR §0 D-07, additive non-breaking method):
	// when env is nil/empty, ExecEnv MUST behave byte-for-byte identically to
	// Exec. Exec is defined as ExecEnv(ctx, t, args, nil), so there is exactly
	// one code path and nil-env callers are provably unchanged.
	//
	// Scope: implementations MUST inject EXACTLY the requested entries over the
	// os.Environ() baseline — no extra parent vars beyond the normal inherited
	// environment. AxiomBackend does not support env passthrough (the fleet split
	// has no env channel) and returns *AxiomFailure when env is non-empty; OSINT
	// tools run on LocalBackend (D-O1), so this restriction does not affect them.
	ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error)

	// Stream runs tool with args, yields stdout and stderr lines as Events on
	// the returned channel. Channel closes when tool exits (clean or error).
	// Suitable for long-running tools (nuclei, dalfox, katana).
	// Caller MUST drain the channel until closed to avoid goroutine leak.
	//
	// Phase 8 MCP server wraps this channel via SSE notifications; see ADR §5.2
	// MCP integration note. Backend.Stream() shape is sufficient for MCP —
	// no protocol-level change anticipated.
	Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error)

	// StreamEnv is Stream with additional "KEY=VALUE" child-env entries (see
	// ExecEnv for the contract). Stream is defined as StreamEnv(ctx, t, args, nil),
	// so nil-env callers are byte-for-byte unchanged.
	StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error)

	// ExecOpts is the single real buffered dispatch body. Exec is defined as
	// ExecOpts with a zero ExecOptions and ExecEnv as ExecOpts with only Env set,
	// so a zero-valued options struct is byte-for-byte identical to Exec (the same
	// contract ExecEnv states for a nil env).
	//
	// Implementations MUST report ExecOptions.Stdin and ExecOptions.StdinPath both
	// being set as a typed error WITHOUT creating a process, so the failure lands
	// in the dispatch_failed bucket rather than looking like a tool that ran.
	//
	// AxiomBackend does not support stdin or a working directory (a fleet split has
	// no stdin channel) and returns *AxiomFailure naming the unsupported option
	// rather than dropping it — refusing loudly so FailoverBackend engages.
	//
	// BINDING (ADR §0 D-07): a WRAPPING backend that forgets to forward these
	// options is a COMPILE error rather than a silently lost capability. That is
	// the whole reason this lives on the interface (operator decision 2026-08-26,
	// Option A) instead of a type-asserted optional interface.
	ExecOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (*Result, error)

	// StreamOpts is ExecOpts for the streaming mode; Stream is StreamOpts with a
	// zero ExecOptions and StreamEnv is StreamOpts with only Env set. Same
	// mutual-exclusion, same axiom refusal, same zero-value contract.
	StreamOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (<-chan Event, error)

	// HealthCheck verifies the backend is operational (binaries reachable,
	// axiom fleet up and authenticated). Called at startup and by the
	// `reconftw health-check` subcommand. Returns nil if healthy.
	HealthCheck(ctx context.Context) error

	// Capacity returns the number of concurrent tool invocations this backend
	// supports. LocalBackend returns runtime.NumCPU() * 2; AxiomBackend returns
	// the configured fleet_count. Used by Scheduler as a hint for SetLimit(N).
	Capacity() int
}
