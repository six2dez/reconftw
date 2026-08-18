// staging_lifecycle_test.go — behavioural proof of the F3 write-or-remove
// staging contract for the osint package (plan 15-14 Task 1).
//
// osint has exactly ONE staging writer — writeOSINTStaging (domain_info.go) —
// which fronts 23 call sites across 20 producer files, so a single migration
// closes the whole package for the AST guard. That concentration is also the
// risk: the guard proves the write is unconditional, but only a behavioural test
// proves each PRODUCER reaches it in the right state. These tests drive real
// Task.Run bodies end to end.
//
// The stakes here are higher than elsewhere in the sweep. osint publishes leaked
// credentials, exposed buckets and public secrets. Clearing on a zero-result run
// is what stops a rotated credential being reported as still leaked forever;
// NOT clearing when the scanner is simply absent is what stops a missing
// optional binary silently retracting a real secret exposure.
package osint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

type osintStageBackend struct {
	mu          sync.Mutex
	calls       []string
	stdout      map[string][]byte
	errs        map[string]error
	streamLines map[string][]string
	terminalErr map[string]error
}

func newOsintStageBackend() *osintStageBackend {
	return &osintStageBackend{
		stdout:      map[string][]byte{},
		errs:        map[string]error{},
		streamLines: map[string][]string{},
		terminalErr: map[string]error{},
	}
}

func (b *osintStageBackend) Exec(_ context.Context, t *backend.Tool, _ []string) (*backend.Result, error) {
	b.mu.Lock()
	b.calls = append(b.calls, t.Name)
	err := b.errs[t.Name]
	out := b.stdout[t.Name]
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &backend.Result{Stdout: out, ExitCode: 0}, nil
}

func (b *osintStageBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *osintStageBackend) Stream(_ context.Context, t *backend.Tool, _ []string) (<-chan backend.Event, error) {
	b.mu.Lock()
	b.calls = append(b.calls, t.Name)
	err := b.errs[t.Name]
	lines := b.streamLines[t.Name]
	term := b.terminalErr[t.Name]
	b.mu.Unlock()
	if err != nil {
		// DISPATCH failure — the binary is not on PATH; the stream never ran.
		return nil, err
	}
	ch := make(chan backend.Event, len(lines)+1)
	for _, l := range lines {
		ch <- backend.Event{Line: []byte(l), Source: t.Name}
	}
	if term != nil {
		ch <- backend.Event{Source: t.Name, Err: term}
	}
	close(ch)
	return ch, nil
}

func (b *osintStageBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *osintStageBackend) HealthCheck(_ context.Context) error { return nil }
func (b *osintStageBackend) Capacity() int                       { return 1 }

func newOsintStageApp(t *testing.T, be backend.Backend) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	for _, name := range []string{"cloud_enum", "misconfig-mapper", "ghleaks", "trufflehog", "dnsx", "whois"} {
		reg.Register(&backend.Tool{Name: name})
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
		Cfg:    &config.Config{},
	}
}

const osintStaleRecord = `{"class":"osint","source":"STALE-PREVIOUS-RUN"}` + "\n"

func seedOsintStaging(t *testing.T, app *appctx.AppContext, name string) string {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(osintStaleRecord), 0o644); err != nil {
		t.Fatalf("seed staging: %v", err)
	}
	return p
}

func osintMustBeCleared(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		body, _ := os.ReadFile(path) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("%s: staging file %s survived a zero-result run — the previous run's "+
			"OSINT finding will be republished:\n%s", why, path, body)
	} else if !os.IsNotExist(err) {
		t.Fatalf("%s: unexpected stat error: %v", why, err)
	}
}

func osintMustBePreserved(t *testing.T, path, why string) {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("%s: staging file %s was DELETED by a task that never ran — a real finding "+
			"was silently retracted: %v", why, path, err)
	}
	if string(body) != osintStaleRecord {
		t.Fatalf("%s: staging file %s was rewritten by a task that never ran:\n%s", why, path, body)
	}
}

// ---------------------------------------------------------------------------
// Write-then-clear — two osint tasks
// ---------------------------------------------------------------------------

// TestCloudEnumStagingWriteThenClear — a STREAM-based osint producer. A bucket
// that has since been locked down must stop being reported as world-readable.
func TestCloudEnumStagingWriteThenClear(t *testing.T) {
	t.Run("run A: an open bucket is found", func(t *testing.T) {
		be := newOsintStageBackend()
		be.streamLines["cloud_enum"] = []string{
			"[+] OPEN S3 BUCKET: http://acme.s3.amazonaws.com/",
		}
		app := newOsintStageApp(t, be)
		staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.cloud_enum.jsonl")

		if _, err := (&CloudEnumTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run A: %v", err)
		}
		body, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		if err != nil {
			t.Fatalf("run A must WRITE the staging file: %v", err)
		}
		if !strings.Contains(string(body), "cloud-bucket-s3") {
			t.Fatalf("run A staging is missing the bucket record:\n%s", body)
		}
	})

	t.Run("run B: the bucket is gone and staging clears", func(t *testing.T) {
		be := newOsintStageBackend()
		be.streamLines["cloud_enum"] = nil // ran, found nothing
		app := newOsintStageApp(t, be)
		staging := seedOsintStaging(t, app, "findings.cloud_enum.jsonl")

		if _, err := (&CloudEnumTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run B: %v", err)
		}
		osintMustBeCleared(t, staging, "cloud_enum ran and found no exposed bucket")
	})
}

// TestCloudEnumDidNotRunPreservesStaging — cloud_enum absent → preserve.
func TestCloudEnumDidNotRunPreservesStaging(t *testing.T) {
	be := newOsintStageBackend()
	be.errs["cloud_enum"] = errors.New("exec: \"cloud_enum\": executable file not found in $PATH")
	app := newOsintStageApp(t, be)
	staging := seedOsintStaging(t, app, "findings.cloud_enum.jsonl")

	res, err := (&CloudEnumTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("an absent optional tool must not error: %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("an absent binary is a DISPATCH failure and must never escalate to errored")
	}
	osintMustBePreserved(t, staging, "cloud_enum is not installed")
}

// TestMisconfigStagingWriteThenClear — a RUN-based osint producer. A third-party
// misconfiguration that has since been fixed must stop being republished.
func TestMisconfigStagingWriteThenClear(t *testing.T) {
	t.Run("run A: an exposed board is found", func(t *testing.T) {
		be := newOsintStageBackend()
		be.stdout["misconfig-mapper"] = []byte(
			"[+] Detected exposed Jira board: https://acme.atlassian.net\n")
		app := newOsintStageApp(t, be)
		staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.misconfig.jsonl")

		if _, err := (&MisconfigTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run A: %v", err)
		}
		body, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		if err != nil {
			t.Fatalf("run A must WRITE the staging file: %v", err)
		}
		if !strings.Contains(string(body), "misconfig") {
			t.Fatalf("run A staging is missing the record:\n%s", body)
		}
	})

	t.Run("run B: the board is private and staging clears", func(t *testing.T) {
		be := newOsintStageBackend()
		be.stdout["misconfig-mapper"] = nil // ran, found nothing
		app := newOsintStageApp(t, be)
		staging := seedOsintStaging(t, app, "findings.misconfig.jsonl")

		if _, err := (&MisconfigTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run B: %v", err)
		}
		osintMustBeCleared(t, staging, "misconfig-mapper ran and found no exposure")
	})
}

// TestMisconfigDidNotRunPreservesStaging — misconfig-mapper absent → preserve.
func TestMisconfigDidNotRunPreservesStaging(t *testing.T) {
	be := newOsintStageBackend()
	be.errs["misconfig-mapper"] = errors.New("exec: \"misconfig-mapper\": executable file not found in $PATH")
	app := newOsintStageApp(t, be)
	staging := seedOsintStaging(t, app, "findings.misconfig.jsonl")

	if _, err := (&MisconfigTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("an absent optional tool must not error: %v", err)
	}
	osintMustBePreserved(t, staging, "misconfig-mapper is not installed")
}

// ---------------------------------------------------------------------------
// The resume-preservation guard — a config/key-gated skip must not clear
// ---------------------------------------------------------------------------

// TestKeyGatedSkipDoesNotClearOSINTStaging drives osint.github_leaks with no
// GitHub token: it returns StatusSkipped at the D-O8 key gate WITHOUT invoking
// any scanner. It observed nothing, so a previously reported secret exposure
// must survive — this is the criterion a careless sweep breaks.
func TestKeyGatedSkipDoesNotClearOSINTStaging(t *testing.T) {
	be := newOsintStageBackend()
	app := newOsintStageApp(t, be) // no APIKeys.GitHub / tokens file configured
	staging := seedOsintStaging(t, app, "findings.github_leaks.jsonl")

	res, err := (&GitHubLeaksTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("key-gated skip must not error: %v", err)
	}
	if res.Status != "skipped" {
		t.Fatalf("status = %q, want skipped (no GitHub token)", res.Status)
	}
	osintMustBePreserved(t, staging, "osint.github_leaks was key-gated and never ran")
	if len(be.calls) != 0 {
		t.Fatalf("a key-gated task must dispatch NO tool, got %v", be.calls)
	}
}

// ---------------------------------------------------------------------------
// Gate 3 end to end — producer → MergeOSINTFindings → artefacts/findings.jsonl
// ---------------------------------------------------------------------------

// TestGate3OSINTProducerToMergedFindings drives the audit's F3 scenario for
// osint: run A publishes an exposure, run B finds nothing and the artefact must
// become PRESENT and EMPTY rather than keeping run A's record.
func TestGate3OSINTProducerToMergedFindings(t *testing.T) {
	be := newOsintStageBackend()
	be.stdout["misconfig-mapper"] = []byte(
		"[+] Detected exposed Jira board: https://acme.atlassian.net\n")
	app := newOsintStageApp(t, be)
	tree, err := output.NewTree(app.Target.WorkDir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	app.Tree = tree
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	if _, err := (&MisconfigTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("run A producer: %v", err)
	}
	if err := MergeOSINTFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A merge: %v", err)
	}
	body, rErr := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
	if rErr != nil {
		t.Fatalf("run A artefact: %v", rErr)
	}
	if n := countOSINTLines(string(body)); n != 1 {
		t.Fatalf("run A artefact should hold 1 finding, got %d:\n%s", n, body)
	}

	be.stdout["misconfig-mapper"] = nil
	if _, err := (&MisconfigTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("run B producer: %v", err)
	}
	if err := MergeOSINTFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B merge: %v", err)
	}
	info, sErr := os.Stat(artefact)
	if sErr != nil {
		t.Fatalf("run B must leave the artefact PRESENT: %v", sErr)
	}
	if info.Size() != 0 {
		after, _ := os.ReadFile(artefact) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's exposure (size %d):\n%s", info.Size(), after)
	}
}

// ---------------------------------------------------------------------------
// The single-writer invariant
// ---------------------------------------------------------------------------

// TestWriteOSINTStagingIsTheOnlyStagingWriter pins the property that makes "one
// migration closes the package" true, and prevents a future producer from
// reintroducing a raw staging write that the AST guard would then have to catch
// after the fact. It also proves no READER was given a fabricated staging call
// to make the guard go green.
func TestWriteOSINTStagingIsTheOnlyStagingWriter(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rErr := os.ReadFile(name) //nolint:gosec // fixed in-package path
		if rErr != nil {
			t.Fatalf("read %s: %v", name, rErr)
		}
		body := string(src)
		for _, helper := range []string{"output.StageJSONL(", "output.StageLines("} {
			if strings.Contains(body, helper) && name != "domain_info.go" {
				t.Errorf("%s calls %s — writeOSINTStaging (domain_info.go) is the package's "+
					"SINGLE staging writer. A staging call added anywhere else is either a "+
					"duplicate lifecycle or, in a reader-only file, a fabricated fix that "+
					"would DELETE a file the reader depends on.", name, helper)
			}
		}
		if strings.Contains(body, "output.WriteJSONL(") && name != "merge.go" {
			t.Errorf("%s calls output.WriteJSONL directly — producer staging must go through "+
				"writeOSINTStaging so the F3 write-or-remove lifecycle stays in one place", name)
		}
	}
}

func countOSINTLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}
