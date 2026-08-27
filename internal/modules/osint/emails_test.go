// emails_test.go — behavior tests for the EmailsTask LeakSearch fold (13-05 Task 1).
//
// Proves the PAR-03 parity restore: after EmailHarvester, EmailsTask runs
// LeakSearch → osint/passwords.txt (plaintext, single-writer) + a REDACTED
// findings.passwords.jsonl stream (XCUT-07 / T-13-05-02 — the raw password is
// registered with the Redactor and never reaches the JSONL or a log line), and
// a LeakSearch failure degrades to StatusDone without disturbing the emails path.
//
// Internal (package osint) to reach the unexported helpers + reuse the in-package
// redacting-logger idiom (github_actions_test.go). Synthetic FAKE_ markers mirror
// the vulns dalfox FAKE_XSS_MARKER convention so redaction is asserted without
// committing a real credential.
//
// Source: .planning/phases/13-domain-parity/13-05-PLAN.md Task 1.
package osint

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// fakeLeakPassword is a clearly-synthetic leaked-credential marker so redaction
// can be asserted without committing a real secret.
const fakeLeakPassword = "FAKE_LEAK_PASSWORD_AAAA_correcthorsebatterystaple"

// leaksearchBackend is a Backend double for the EmailsTask Run path. It returns
// emailHarvesterOut on EmailHarvester stdout, and (unless leaksearchFails) writes
// leakPasswords to the LeakSearch "-o" file (simulating the tool's file output,
// like enumerepo -o) without spawning a subprocess. leaksearchFails simulates a
// missing tool / venv (best_effort degrade).
type leaksearchBackend struct {
	emailHarvesterOut string
	leakPasswords     string
	leaksearchFails   bool
}

func (b *leaksearchBackend) writeLeakOutput(args []string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-o" {
			_ = os.WriteFile(args[i+1], []byte(b.leakPasswords), 0o600)
			return
		}
	}
}

func (b *leaksearchBackend) Exec(_ context.Context, tool *backend.Tool, args []string) (*backend.Result, error) {
	switch tool.Name {
	case "EmailHarvester":
		return &backend.Result{Stdout: []byte(b.emailHarvesterOut), ExitCode: 0}, nil
	case "LeakSearch":
		if b.leaksearchFails {
			return nil, errors.New("LeakSearch: venv missing")
		}
		b.writeLeakOutput(args)
		return &backend.Result{ExitCode: 0}, nil
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (b *leaksearchBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, tool, args)
}

func (b *leaksearchBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *leaksearchBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *leaksearchBackend) HealthCheck(_ context.Context) error { return nil }
func (b *leaksearchBackend) Capacity() int                       { return 1 }

// runEmailsTask wires an EmailsTask with a redacting logger over buf and the
// given backend, then runs it. Returns the app (for workspace inspection), the
// log buffer (for leak assertions), and the Result.
func runEmailsTask(t *testing.T, be *leaksearchBackend) (*appctx.AppContext, *bytes.Buffer, task.Result) {
	t.Helper()
	workDir := t.TempDir()

	cfg := &config.Config{}
	cfg.OSINT.Emails.Enabled = true

	redactor := &log.Redactor{}
	buf := &bytes.Buffer{}
	logger := slog.New(log.NewRedactingHandler(
		slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}), redactor))

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "EmailHarvester"})
	reg.Register(&backend.Tool{Name: "LeakSearch"})
	runner := backend.NewRunner(be, reg, nil)

	app := &appctx.AppContext{
		Log:    logger,
		Cfg:    cfg,
		Tools:  runner,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
	res, err := (&EmailsTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("EmailsTask.Run: unexpected error: %v", err)
	}
	return app, buf, res
}

// TestEmailsTask_LeakSearchWritesPasswordsAndRedacts is the happy path: LeakSearch
// output → plaintext osint/passwords.txt + REDACTED findings.passwords.jsonl, with
// the raw password scrubbed from logs and never present in the JSONL stream.
func TestEmailsTask_LeakSearchWritesPasswordsAndRedacts(t *testing.T) {
	be := &leaksearchBackend{
		emailHarvesterOut: "admin@example.com\nsupport@example.com\n",
		leakPasswords:     fakeLeakPassword + "\nsecond_fake_leak_line_9988\n" + fakeLeakPassword + "\n", // dup
	}
	app, buf, res := runEmailsTask(t, be)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}

	// 1. osint/passwords.txt holds the PLAINTEXT passwords (D-O5 human file), deduped.
	pwPath := filepath.Join(app.Target.WorkDir, "osint", "passwords.txt")
	pwData, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatalf("osint/passwords.txt not written: %v", err)
	}
	if !strings.Contains(string(pwData), fakeLeakPassword) {
		t.Errorf("passwords.txt missing plaintext leaked password; got:\n%s", pwData)
	}
	if n := strings.Count(string(pwData), fakeLeakPassword); n != 1 {
		t.Errorf("passwords.txt should dedup the leaked password (want 1 occurrence, got %d)", n)
	}

	// 2. findings.passwords.jsonl exists, is REDACTED, and NEVER carries the raw secret.
	fPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.passwords.jsonl")
	fData, err := os.ReadFile(fPath)
	if err != nil {
		t.Fatalf("inputs/findings.passwords.jsonl not written: %v", err)
	}
	if bytes.Contains(fData, []byte(fakeLeakPassword)) {
		t.Fatalf("XCUT-07 VIOLATION: raw password leaked into findings.passwords.jsonl:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"value_redacted":"***"`)) {
		t.Errorf("findings.passwords.jsonl must carry value_redacted=***; got:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"category":"leaked-password"`)) {
		t.Errorf("findings.passwords.jsonl missing category leaked-password; got:\n%s", fData)
	}

	// 3. XCUT-07 L2: the raw password was registered → scrubbed from ALL log output.
	app.Log.Info("emails-test-probe", "pw", fakeLeakPassword)
	if strings.Contains(buf.String(), fakeLeakPassword) {
		t.Fatalf("XCUT-07 L2 VIOLATION: raw password leaked into log output:\n%s", buf.String())
	}

	// 4. Regression: the EmailHarvester path (osint/emails.txt + findings.emails.jsonl)
	//    is unchanged.
	emailsData, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "osint", "emails.txt"))
	if err != nil {
		t.Fatalf("osint/emails.txt regression — not written: %v", err)
	}
	if !strings.Contains(string(emailsData), "admin@example.com") {
		t.Errorf("emails.txt missing harvested email; got:\n%s", emailsData)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "inputs", "findings.emails.jsonl")); err != nil {
		t.Errorf("findings.emails.jsonl regression — not written: %v", err)
	}
	if res.Stats["passwords"] != 2 {
		t.Errorf("Stats[passwords] = %d, want 2 (deduped)", res.Stats["passwords"])
	}
	if res.Stats["emails"] != 2 {
		t.Errorf("Stats[emails] = %d, want 2", res.Stats["emails"])
	}
}

// TestEmailsTask_LeakSearchDegrades proves a LeakSearch failure (missing venv)
// degrades to StatusDone with no passwords.txt, and the emails path is intact.
func TestEmailsTask_LeakSearchDegrades(t *testing.T) {
	be := &leaksearchBackend{
		emailHarvesterOut: "admin@example.com\n",
		leaksearchFails:   true,
	}
	app, _, res := runEmailsTask(t, be)

	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done (best_effort degrade)", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "passwords.txt")); err == nil {
		t.Error("passwords.txt written despite LeakSearch failure")
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "inputs", "findings.passwords.jsonl")); err == nil {
		t.Error("findings.passwords.jsonl written despite LeakSearch failure")
	}
	// Emails path unaffected.
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "emails.txt")); err != nil {
		t.Errorf("emails.txt regression on LeakSearch failure: %v", err)
	}
	if res.Stats["passwords"] != 0 {
		t.Errorf("Stats[passwords] = %d, want 0 on degrade", res.Stats["passwords"])
	}
}

// TestEmailsTask_LeakSearchRunsEvenIfHarvesterFails proves bash parity: LeakSearch
// runs in its own subshell regardless of the EmailHarvester result (osint.sh:552).
func TestEmailsTask_LeakSearchRunsEvenIfHarvesterFails(t *testing.T) {
	// EmailHarvester "fails" by returning no emails; LeakSearch still succeeds.
	be := &leaksearchBackend{
		emailHarvesterOut: "",
		leakPasswords:     fakeLeakPassword + "\n",
	}
	app, _, res := runEmailsTask(t, be)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "passwords.txt")); err != nil {
		t.Errorf("passwords.txt should be written even with no harvested emails: %v", err)
	}
	if res.Stats["passwords"] != 1 {
		t.Errorf("Stats[passwords] = %d, want 1", res.Stats["passwords"])
	}
}

func TestParseLeakSearchPasswords_Dedup(t *testing.T) {
	in := []byte("pw_one\n\npw_two\npw_one\n  \npw_three\n")
	got := parseLeakSearchPasswords(in)
	want := []string{"pw_one", "pw_two", "pw_three"}
	if len(got) != len(want) {
		t.Fatalf("got %d passwords, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("password[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if recs := parseLeakSearchPasswords(nil); recs != nil {
		t.Errorf("expected nil for empty input, got %v", recs)
	}
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (b *leaksearchBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *leaksearchBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
}
