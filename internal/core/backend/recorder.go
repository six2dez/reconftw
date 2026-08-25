// recorder.go — ToolRecorder: the append-only record of every tool invocation.
//
// WHY THIS EXISTS. <workspace>/logs/ is created by output.NewTree and
// output.WorkspaceInit and was then never written to: tool argv, tool stderr and
// tool exit codes were persisted nowhere. Every one of the seven defects found in
// the first end-to-end v2 live run presented as the same string —
// "tool stream ended badly: exit status 1" — and each had to be diagnosed by
// hand-reproducing the invocation over ssh, minutes at a time. With argv on disk
// each would have been a grep.
//
// WHY IT BYPASSES output.WriteFile / output.WriteJSONL. Those are
// replace-whole-file atomic writers. Rewriting the whole log on every invocation
// is quadratic, and — the part that matters — it destroys the partial file a
// crashed or hung run leaves behind, which is precisely the artefact this file
// exists to produce. So the recorder holds one append-mode descriptor for the
// life of the run. internal/core/output/lock.go carries the only other such
// exemption in the tree, for the same class of reason: some files are not
// snapshots of a final state.
//
// WHY TWO RECORDS PER INVOCATION. A hung tool never reaches its end record, so a
// start with no matching end IS the diagnosis of a hang, readable from the file
// alone. A single completion record would be silent in exactly the case that has
// cost the most time.
//
// WHY 0o600 RATHER THAN THE WORKSPACE'S USUAL 0o644. This file carries tool
// stderr, which can contain response fragments from the target.

package backend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Invocation phase discriminators.
const (
	PhaseStart = "start"
	PhaseEnd   = "end"
)

// Dispatch modes.
const (
	ModeExec   = "exec"
	ModeStream = "stream"
)

// Outcome labels. A small CLOSED set, exported so a grep can be written against a
// stable vocabulary and a typo at one call site cannot invent a fourth spelling.
//
// OutcomeDispatchFailed is deliberately distinct from OutcomeExitNonZero. Their
// conflation is not hypothetical: takeover.go logged dnstake's
// "flag provided but not defined" as "run failed or tool not registered" at Debug
// level, and because those two facts looked alike nobody noticed that takeover
// detection had been producing zero for months.
const (
	OutcomeSuccess        = "success"         // the tool ran and exited 0
	OutcomeExitNonZero    = "exit_non_zero"   // the tool ran and exited non-zero
	OutcomeDispatchFailed = "dispatch_failed" // the tool never ran: unregistered, absent, rate-limit abort
	OutcomeTimeout        = "timeout"         // the tool ran and its context deadline fired
)

// InvocationRecord is one line of logs/tools.jsonl.
type InvocationRecord struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
	Time  string `json:"time"`
	Tool  string `json:"tool"`
	Mode  string `json:"mode"`
	// Argv is what the PROCESS received, captured after applyToolContract has
	// merged Tool.DefaultArgs — not what the module wrote. An operator debugging
	// a wrong flag needs the real command line.
	Argv []string `json:"argv,omitempty"`

	// End-record-only fields.
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS *int64 `json:"duration_ms,omitempty"`
	Outcome    string `json:"outcome,omitempty"`
	StderrTail string `json:"stderr_tail,omitempty"`
}

// Redactor is the one method the recorder needs from *log.Redactor.
//
// Declared as an interface rather than taking the concrete type so this package
// stays free of a log dependency it would otherwise need only for one call, and
// so a test can supply a trivial stub. Same inversion, for the same reason, as
// appctx.SchedulerRunner.
type Redactor interface {
	Redact(string) string
}

// maxToolLogBytes is the ceiling at which tools.jsonl rotates.
//
// A full recon run dispatches on the order of a few hundred invocations, and a
// record with a 1 KiB stderr tail is at most ~1.5 KiB, so 8 MiB keeps several
// entire runs intact — the log is useless if it rotates away the run being
// investigated. Checked on OPEN, not per write: a mid-run rotation would split
// one invocation's start and end records across two files and destroy the
// start-without-end shape that identifies a hang.
const maxToolLogBytes = 8 << 20

// ToolRecorder appends InvocationRecords to a JSONL file.
//
// The zero value is not usable; construct with NewToolRecorder. A nil
// *ToolRecorder is fully usable and does nothing, so call sites never need a
// guard.
type ToolRecorder struct {
	path     string
	redactor Redactor

	mu  sync.Mutex
	f   *os.File
	seq uint64

	// err latches the FIRST write failure. A recorder that cannot write is a lost
	// diagnostic; a recorder that fails a scan is a new outage. So write errors
	// never propagate into the dispatch path — they are latched here and surfaced
	// by Close.
	err atomic.Pointer[error]
}

// NewToolRecorder constructs a recorder for path. It does NOT touch the
// filesystem — see the lazy-creation note on ensureOpenLocked.
//
// redactor may be nil, which degrades to NO redaction. That is a deliberate
// degradation rather than a panic, but it is not a safe default: two module
// sites put a GitHub/GitLab token's CONTENT on argv, so a nil redactor here is a
// path by which a plaintext token reaches disk.
func NewToolRecorder(path string, redactor Redactor) *ToolRecorder {
	return &ToolRecorder{path: path, redactor: redactor}
}

// Start writes the start record and returns the invocation id used to pair it
// with its end record. Nil-receiver safe.
func (r *ToolRecorder) Start(tool, mode string, argv []string) string {
	if r == nil {
		return ""
	}
	id := r.nextID()
	r.write(InvocationRecord{
		ID:    id,
		Phase: PhaseStart,
		Time:  time.Now().Format(time.RFC3339Nano),
		Tool:  tool,
		Mode:  mode,
		Argv:  argv,
	})
	return id
}

// End writes the end record for id. Nil-receiver safe; an empty id is ignored so
// a caller that got one from a nil recorder can call End unconditionally.
func (r *ToolRecorder) End(id string, exitCode int, dur time.Duration, outcome, stderrTail string) {
	if r == nil || id == "" {
		return
	}
	ms := dur.Milliseconds()
	r.write(InvocationRecord{
		ID:         id,
		Phase:      PhaseEnd,
		Time:       time.Now().Format(time.RFC3339Nano),
		ExitCode:   &exitCode,
		DurationMS: &ms,
		Outcome:    outcome,
		StderrTail: stderrTail,
	})
}

// Close releases the descriptor and reports the first latched write error, if
// any. Idempotent: closing a recorder that never opened its file returns nil.
func (r *ToolRecorder) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	var closeErr error
	if r.f != nil {
		closeErr = r.f.Close()
		r.f = nil
	}
	if p := r.err.Load(); p != nil && *p != nil {
		return *p
	}
	return closeErr
}

// nextID returns a per-recorder monotonic id. Monotonic rather than random so the
// file reads in dispatch order and so tests are deterministic.
func (r *ToolRecorder) nextID() string {
	r.mu.Lock()
	r.seq++
	n := r.seq
	r.mu.Unlock()
	return strconv.FormatUint(n, 10)
}

// redact scrubs registered secrets from the record IMMEDIATELY before
// marshalling, and never before: the unredacted argv is what gets dispatched, so
// redaction must not touch the value on its way to the process.
func (r *ToolRecorder) redact(rec InvocationRecord) InvocationRecord {
	if r.redactor == nil {
		return rec
	}
	if len(rec.Argv) > 0 {
		scrubbed := make([]string, len(rec.Argv))
		for i, a := range rec.Argv {
			scrubbed[i] = r.redactor.Redact(a)
		}
		rec.Argv = scrubbed
	}
	rec.StderrTail = r.redactor.Redact(rec.StderrTail)
	return rec
}

// write serialises one record. Never returns an error by design — see the err
// field's comment.
func (r *ToolRecorder) write(rec InvocationRecord) {
	line, err := json.Marshal(r.redact(rec))
	if err != nil {
		r.latch(fmt.Errorf("marshal invocation record: %w", err))
		return
	}
	line = append(line, '\n')

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.ensureOpenLocked(); err != nil {
		r.latch(err)
		return
	}
	if _, err := r.f.Write(line); err != nil {
		r.latch(fmt.Errorf("write invocation record: %w", err))
	}
}

// ensureOpenLocked opens the file on FIRST use and never before.
//
// LAZY CREATION IS A CORRECTNESS REQUIREMENT, NOT AN OPTIMISATION. Acceptance
// gate 1 of the cutover is "a dry run leaves the filesystem byte-for-byte
// unchanged". A recorder constructed by a boot that dispatches no tool must leave
// no trace — not an empty file, not even the parent directory.
func (r *ToolRecorder) ensureOpenLocked() error {
	if r.f != nil {
		return nil
	}
	if r.path == "" {
		return fmt.Errorf("tool recorder: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o750); err != nil {
		return fmt.Errorf("create tool log dir: %w", err)
	}
	r.rotateIfOversizeLocked()
	f, err := os.OpenFile(r.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // path derived from the run's own workspace
	if err != nil {
		return fmt.Errorf("open tool log: %w", err)
	}
	r.f = f
	return nil
}

// rotateIfOversizeLocked renames an oversize log aside so the file cannot grow
// without bound in a workspace the operator may never clean.
//
// A file UNDER the ceiling is left alone and appended to. That matters: a crashed
// or hung run's partial tail is precisely the artefact this package exists to
// preserve, so opening must never truncate it.
//
// Exactly one generation is kept. Rotation is best-effort — a rename failure must
// not stop the run from recording.
func (r *ToolRecorder) rotateIfOversizeLocked() {
	fi, err := os.Stat(r.path)
	if err != nil || fi.Size() < maxToolLogBytes {
		return
	}
	_ = os.Rename(r.path, r.path+".1")
}

// latch records the first error only.
func (r *ToolRecorder) latch(err error) {
	if err == nil {
		return
	}
	r.err.CompareAndSwap(nil, &err)
}
