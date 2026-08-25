// recorder_test.go — proofs for the tool-invocation record.
//
// Each test here corresponds to a property the file must have for an operator to
// answer a question with a grep instead of an ssh session.

package backend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readRecords(t *testing.T, path string) []InvocationRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []InvocationRecord
	for i, ln := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var rec InvocationRecord
		if err := json.Unmarshal([]byte(ln), &rec); err != nil {
			t.Fatalf("line %d is not valid JSON (%v): %s", i+1, err, ln)
		}
		out = append(out, rec)
	}
	return out
}

// TestRecorderLazyCreation pins the property acceptance gate 1 depends on: a
// recorder that records nothing must leave NO trace — not an empty file, not the
// parent directory.
func TestRecorderLazyCreation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "tools.jsonl")

	r := NewToolRecorder(path, nil)
	if err := r.Close(); err != nil {
		t.Fatalf("Close on an unused recorder: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("unused recorder created %s (err=%v) — a dry run must leave the "+
			"filesystem byte-for-byte unchanged", path, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("unused recorder created the parent directory %s", filepath.Dir(path))
	}
}

// TestRecorderStartEndPairing is the base shape: one invocation, two records,
// paired by id.
func TestRecorderStartEndPairing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, nil)

	id := r.Start("httpx", ModeStream, []string{"-l", "hosts.txt", "-silent"})
	r.End(id, 0, 1500*time.Millisecond, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2 (one start, one end)", len(recs))
	}
	if recs[0].Phase != PhaseStart || recs[1].Phase != PhaseEnd {
		t.Errorf("phases = %q,%q want %q,%q", recs[0].Phase, recs[1].Phase, PhaseStart, PhaseEnd)
	}
	if recs[0].ID != recs[1].ID {
		t.Errorf("start id %q does not pair with end id %q", recs[0].ID, recs[1].ID)
	}
	if got := strings.Join(recs[0].Argv, " "); got != "-l hosts.txt -silent" {
		t.Errorf("argv = %q, want the exact argv the process received", got)
	}
	if recs[1].DurationMS == nil || *recs[1].DurationMS != 1500 {
		t.Errorf("duration_ms = %v, want 1500", recs[1].DurationMS)
	}
}

// TestRecorderHangShape is THE assertion that makes the file useful. A tool that
// never finishes leaves a start with no matching end, and that asymmetry is the
// diagnosis — readable from the file alone, without reproducing anything.
func TestRecorderHangShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, nil)

	hung := r.Start("httpx", ModeStream, []string{"-l", "hosts.txt"})
	done := r.Start("dnsx", ModeExec, []string{"-silent"})
	r.End(done, 0, time.Second, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ended := map[string]bool{}
	started := map[string]string{}
	for _, rec := range readRecords(t, path) {
		switch rec.Phase {
		case PhaseStart:
			started[rec.ID] = rec.Tool
		case PhaseEnd:
			ended[rec.ID] = true
		}
	}
	if ended[hung] {
		t.Error("the hung invocation has an end record — the hang shape is destroyed")
	}
	if !ended[done] {
		t.Error("the completed invocation has no end record")
	}
	if started[hung] != "httpx" {
		t.Errorf("the unfinished start record does not name its tool: %q", started[hung])
	}
}

// TestOutcomeLabelsAreDistinct asserts the two facts are different VALUES, not
// different spellings. Conflating "never ran" with "ran and failed" is what hid
// dnstake's broken arg vector for months.
func TestOutcomeLabelsAreDistinct(t *testing.T) {
	if OutcomeDispatchFailed == OutcomeExitNonZero {
		t.Fatal("dispatch failure and non-zero exit share a label — an operator " +
			"cannot tell a tool that never ran from one that ran and failed")
	}
	seen := map[string]bool{}
	for _, o := range []string{OutcomeSuccess, OutcomeExitNonZero, OutcomeDispatchFailed, OutcomeTimeout} {
		if seen[o] {
			t.Errorf("duplicate outcome label %q", o)
		}
		seen[o] = true
	}
}

// TestRecorderNilSafe: every call site calls unconditionally, so a nil recorder
// must be a no-op rather than a panic.
func TestRecorderNilSafe(t *testing.T) {
	var r *ToolRecorder
	id := r.Start("httpx", ModeExec, []string{"-x"})
	if id != "" {
		t.Errorf("nil recorder returned id %q, want empty", id)
	}
	r.End(id, 0, time.Second, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Errorf("nil recorder Close: %v", err)
	}
}

// TestRecorderConcurrentWrites catches the specific defect an unsynchronised
// writer produces: interleaved partial lines. Every line must parse, and the
// record count must be exactly 2 per invocation.
func TestRecorderConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, nil)

	const goroutines, each = 8, 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				id := r.Start("httpx", ModeExec, []string{"-a", "-b"})
				r.End(id, 0, time.Millisecond, OutcomeSuccess, "")
			}
		}()
	}
	wg.Wait()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readRecords(t, path) // fails the test if any line is not valid JSON
	if want := goroutines * each * 2; len(recs) != want {
		t.Errorf("got %d records, want %d — records were lost or interleaved", len(recs), want)
	}
	ids := map[string]int{}
	for _, rec := range recs {
		ids[rec.ID]++
	}
	for id, n := range ids {
		if n != 2 {
			t.Errorf("id %q appears %d times, want exactly 2 (one start, one end)", id, n)
		}
	}
}

// TestRecorderFilePermissions: the file carries tool stderr, which can contain
// response fragments from the target, so it is 0600 rather than the workspace's
// usual 0644.
func TestRecorderFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, nil)
	r.End(r.Start("httpx", ModeExec, nil), 0, 0, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %04o, want 0600 — this file can carry target response fragments", perm)
	}
}

// TestRecorderWriteFailureDoesNotPanic: a recorder that cannot write is a lost
// diagnostic; it must never become an outage. The error is latched and surfaced
// by Close instead.
func TestRecorderWriteFailureDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	// A path whose parent is a FILE: MkdirAll and OpenFile both fail.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := NewToolRecorder(filepath.Join(blocker, "logs", "tools.jsonl"), nil)

	id := r.Start("httpx", ModeExec, []string{"-x"}) // must not panic
	r.End(id, 0, 0, OutcomeSuccess, "")

	if err := r.Close(); err == nil {
		t.Error("Close reported success after every write failed — the failure is invisible")
	}
}

// ---------------------------------------------------------------------------
// Runner-seam recording. These go through streamWithContract / execRecorded, so
// they are what the plan's mutation proof targets.
// ---------------------------------------------------------------------------

// recordingTestBackend streams a fixed set of events, then optionally blocks
// forever to model a hung tool.
type recordingTestBackend struct {
	lines    []string
	termErr  error
	hangOpen bool // never close the channel: the tool never finishes
}

func (b *recordingTestBackend) Exec(_ context.Context, _ *Tool, _ []string) (*Result, error) {
	return &Result{ExitCode: 0}, nil
}

func (b *recordingTestBackend) ExecEnv(ctx context.Context, t *Tool, a []string, _ []string) (*Result, error) {
	return b.Exec(ctx, t, a)
}

func (b *recordingTestBackend) Stream(_ context.Context, _ *Tool, _ []string) (<-chan Event, error) {
	ch := make(chan Event, len(b.lines)+1)
	for _, l := range b.lines {
		ch <- Event{Line: []byte(l)}
	}
	if b.termErr != nil {
		ch <- Event{Err: b.termErr}
	}
	if !b.hangOpen {
		close(ch)
	}
	return ch, nil
}

func (b *recordingTestBackend) StreamEnv(ctx context.Context, t *Tool, a []string, _ []string) (<-chan Event, error) {
	return b.Stream(ctx, t, a)
}

func (b *recordingTestBackend) HealthCheck(_ context.Context) error { return nil }
func (b *recordingTestBackend) Capacity() int                       { return 1 }

func newRecordingRunner(t *testing.T, be Backend) (*Runner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	reg := NewToolRegistry()
	reg.Register(&Tool{Name: "stubtool"})
	r := NewRunner(be, reg, nil)
	r.Recorder = NewToolRecorder(path, nil)
	return r, path
}

// TestRunnerStreamRecordsThroughTheSeam proves the Runner — not just the recorder
// — writes a pair for a completed stream, with the post-contract argv.
func TestRunnerStreamRecordsThroughTheSeam(t *testing.T) {
	r, path := newRecordingRunner(t, &recordingTestBackend{lines: []string{"a", "b"}})

	ch, err := r.Stream(context.Background(), "stubtool", []string{"-x", "1"})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	for range ch { //nolint:revive // drain to completion
	}
	if err := r.Recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	recs := readRecords(t, path)
	if len(recs) != 2 {
		t.Fatalf("got %d records, want a start/end pair: %+v", len(recs), recs)
	}
	if recs[0].Mode != ModeStream {
		t.Errorf("mode = %q, want %q", recs[0].Mode, ModeStream)
	}
	if got := strings.Join(recs[0].Argv, " "); got != "-x 1" {
		t.Errorf("argv = %q, want %q", got, "-x 1")
	}
	if recs[1].Outcome != OutcomeSuccess {
		t.Errorf("outcome = %q, want %q", recs[1].Outcome, OutcomeSuccess)
	}
}

// TestRunnerStreamHangLeavesStartWithoutEnd is THE mutation target named in the
// plan: remove Recorder.Start from streamWithContract and this fails.
//
// A stream whose channel never closes is a tool that never finished. The relay
// goroutine therefore never reaches its end record, and the file is left showing
// a start with no end — which is the diagnosis, available without reproducing
// anything. This is the shape that would have answered the open web.httpx
// question in one grep.
func TestRunnerStreamHangLeavesStartWithoutEnd(t *testing.T) {
	r, path := newRecordingRunner(t, &recordingTestBackend{
		lines:    []string{"partial"},
		hangOpen: true,
	})

	ch, err := r.Stream(context.Background(), "stubtool", []string{"-l", "hosts.txt"})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	<-ch // consume the one line; the tool then "hangs" — the channel never closes

	// Do NOT close the recorder via the relay: the relay is still alive, which is
	// the point. Flush what exists.
	recs := readRecords(t, path)

	var starts, ends int
	for _, rec := range recs {
		switch rec.Phase {
		case PhaseStart:
			starts++
		case PhaseEnd:
			ends++
		}
	}
	if starts != 1 {
		t.Fatalf("got %d start records, want 1 — without a start record a hang is "+
			"INVISIBLE in the log, which is the whole failure this file prevents; records: %+v",
			starts, recs)
	}
	if ends != 0 {
		t.Errorf("got %d end records for a tool that never finished, want 0 — "+
			"the start-without-end shape is what identifies the hang", ends)
	}
}

// TestRunnerExecRecordsNonZeroExitDistinctly: a tool that RAN and failed must not
// share an outcome with one that never ran.
func TestRunnerExecRecordsNonZeroExitDistinctly(t *testing.T) {
	r, path := newRecordingRunner(t, &recordingTestBackend{})

	// Registered tool, exits 0 → success.
	if _, err := r.Run(context.Background(), "stubtool", []string{"-a"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Unregistered tool → never ran.
	if _, err := r.Run(context.Background(), "absenttool", []string{"-b"}); err == nil {
		t.Fatal("expected an error for an unregistered tool")
	}
	if err := r.Recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	outcomes := map[string]string{} // tool → outcome
	for _, rec := range readRecords(t, path) {
		if rec.Phase == PhaseEnd {
			outcomes[rec.ID] = rec.Outcome
		}
	}
	var sawSuccess, sawDispatchFailed bool
	for _, o := range outcomes {
		switch o {
		case OutcomeSuccess:
			sawSuccess = true
		case OutcomeDispatchFailed:
			sawDispatchFailed = true
		}
	}
	if !sawSuccess {
		t.Error("the tool that ran and exited 0 is not recorded as success")
	}
	if !sawDispatchFailed {
		t.Error("the unregistered tool is not recorded as dispatch_failed — an operator " +
			"cannot tell it apart from a tool that ran and failed")
	}
}

// ---------------------------------------------------------------------------
// Redaction and rotation.
// ---------------------------------------------------------------------------

// stubRedactor is the minimal Redactor: it replaces registered values.
type stubRedactor struct {
	mu      sync.Mutex
	secrets []string
}

func (s *stubRedactor) Register(v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets = append(s.secrets, v)
}

func (s *stubRedactor) Redact(in string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sec := range s.secrets {
		if sec != "" {
			in = strings.ReplaceAll(in, sec, "[REDACTED]")
		}
	}
	return in
}

// TestRecorderRedactsSecretsFromFile asserts on the FILE BYTES, not the record
// struct. The struct is not what leaks.
func TestRecorderRedactsSecretsFromFile(t *testing.T) {
	const token = "ghp_ThisIsAFakeGitHubTokenValue123456"
	red := &stubRedactor{}
	red.Register(token)

	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, red)
	id := r.Start("github-subdomains", ModeExec, []string{"-d", "example.com", "-t", token})
	r.End(id, 1, time.Second, OutcomeExitNonZero, "auth failed for "+token)
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), token) {
		t.Errorf("the token is present in %s as plaintext", path)
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Error("no redaction placeholder — the value was dropped rather than redacted")
	}

	// DIAGNOSTIC SURVIVAL, asserted in the same test: a redactor that scrubbed the
	// whole argv would satisfy the check above and destroy the file's purpose.
	for _, keep := range []string{"github-subdomains", "-d", "example.com", "-t"} {
		if !strings.Contains(string(raw), keep) {
			t.Errorf("redaction destroyed the diagnostic: %q is missing from the record", keep)
		}
	}
	if !strings.Contains(string(raw), "auth failed for") {
		t.Error("redaction destroyed the stderr tail's non-secret text")
	}
}

// TestRecorderRedactsSecretRegisteredAfterConstruction: registration and
// recording are not ordered by construction — a token read mid-run must still be
// scrubbed.
func TestRecorderRedactsSecretRegisteredAfterConstruction(t *testing.T) {
	const token = "glpat-FakeGitLabTokenValue0987654321"
	red := &stubRedactor{}

	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	r := NewToolRecorder(path, red) // constructed BEFORE the token is known
	red.Register(token)             // ...registered later, as a task reading a token file would

	id := r.Start("gitlab-subdomains", ModeExec, []string{"-t", token})
	r.End(id, 0, 0, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), token) {
		t.Error("a token registered after construction reached the file in plaintext")
	}
}

// TestRecorderRotatesAtCeiling: asserts WHICH records ended up where, not merely
// that two files exist.
func TestRecorderRotatesAtCeiling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "tools.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Seed an OVERSIZE previous log carrying a recognisable marker.
	big := make([]byte, maxToolLogBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	copy(big, []byte("OLD_GENERATION_MARKER"))
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewToolRecorder(path, nil)
	id := r.Start("httpx", ModeExec, []string{"-fresh"})
	r.End(id, 0, 0, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if !strings.Contains(string(cur), "-fresh") {
		t.Error("the CURRENT file does not hold the most recent records")
	}
	if strings.Contains(string(cur), "OLD_GENERATION_MARKER") {
		t.Error("the current file still holds the rotated-away generation")
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read rotated: %v", err)
	}
	if !strings.Contains(string(rotated), "OLD_GENERATION_MARKER") {
		t.Error("the previous generation was destroyed rather than rotated")
	}
}

// TestRecorderAppendsToUndersizeLog: a crashed run's partial tail is exactly the
// artefact this package exists to preserve, so opening must never truncate it.
func TestRecorderAppendsToUndersizeLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs", "tools.jsonl")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	prior := `{"id":"99","phase":"start","tool":"crashedtool","mode":"stream"}` + "\n"
	if err := os.WriteFile(path, []byte(prior), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := NewToolRecorder(path, nil)
	id := r.Start("httpx", ModeExec, nil)
	r.End(id, 0, 0, OutcomeSuccess, "")
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "crashedtool") {
		t.Error("the previous run's partial tail was truncated on open — that tail is " +
			"the diagnosis of whatever killed it")
	}
	if !strings.Contains(string(raw), "httpx") {
		t.Error("the new records were not appended")
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Error("an undersize log was rotated; rotation must only fire at the ceiling")
	}
}
