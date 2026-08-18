// staging_lifecycle_test.go — behavioural proof of the F3 write-or-remove
// staging contract for the vulns package (plan 15-14 Task 1).
//
// The staging-contract AST guard proves no RAW merger-globbed write remains. It
// cannot prove the resulting behaviour, and it is structurally blind to two
// things this file covers:
//
//   - a `return` placed in front of an already-correct staging call (the same F3
//     bug one statement earlier), and
//   - inputs/gf/<class>.txt, which lives under an inputs/ SUBDIRECTORY that no
//     merger glob can reach, so gf.go is out of the detector's scope BY
//     CONSTRUCTION — not exempted. Its correctness is hand-verified in the
//     15-14 SUMMARY and pinned behaviourally by TestGFBucketRewrittenOnZeroMatch
//     below.
//
// Every "cleared" assertion uses os.Stat explicitly and treats a still-present
// file as a failure; every "preserved" assertion reads the file back and
// requires the ORIGINAL bytes, so a helper that truncated instead of preserving
// would fail.
package vulns

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

// stageFakeBackend dispatches on tool name. A tool present in errs fails; a tool
// present in streamLines produces those lines followed by a clean close; a tool
// present in terminalErr produces its lines followed by a FINAL event carrying
// Err (the F6 "ran and ended badly" shape).
type stageFakeBackend struct {
	mu          sync.Mutex
	calls       []string
	stdout      map[string][]byte
	errs        map[string]error
	streamLines map[string][]string
	terminalErr map[string]error
	// onExec runs before a successful Exec returns, letting a test emulate a
	// tool that writes an output file.
	onExec func(tool string, args []string)
}

func newStageFakeBackend() *stageFakeBackend {
	return &stageFakeBackend{
		stdout:      map[string][]byte{},
		errs:        map[string]error{},
		streamLines: map[string][]string{},
		terminalErr: map[string]error{},
	}
}

func (b *stageFakeBackend) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	b.mu.Lock()
	b.calls = append(b.calls, t.Name)
	err := b.errs[t.Name]
	out := b.stdout[t.Name]
	hook := b.onExec
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if hook != nil {
		hook(t.Name, args)
	}
	return &backend.Result{Stdout: out, ExitCode: 0}, nil
}

func (b *stageFakeBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *stageFakeBackend) Stream(_ context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	b.mu.Lock()
	b.calls = append(b.calls, t.Name)
	err := b.errs[t.Name]
	lines := b.streamLines[t.Name]
	term := b.terminalErr[t.Name]
	hook := b.onExec
	b.mu.Unlock()
	if err != nil {
		// DISPATCH failure — the binary is not on PATH; the stream never ran.
		return nil, err
	}
	if hook != nil {
		hook(t.Name, args)
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

func (b *stageFakeBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *stageFakeBackend) HealthCheck(_ context.Context) error { return nil }
func (b *stageFakeBackend) Capacity() int                       { return 1 }

// newStageTestApp builds an AppContext whose registry knows every tool this file
// drives, so a Runner lookup never masks the behaviour under test.
func newStageTestApp(t *testing.T, be backend.Backend, cfg *config.Config) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	for _, name := range []string{
		"crlfuzz", "smugglex", "gf", "sqlmap", "ghauri",
		"Web-Cache-Vulnerability-Scanner", "toxicache",
	} {
		reg.Register(&backend.Tool{Name: name})
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
		Cfg:    cfg,
	}
}

// seedURLCorpus writes artefacts/urls.jsonl, the D-V5 corpus every URL-driven
// vulns task resolves.
func seedURLCorpus(t *testing.T, app *appctx.AppContext, urls ...string) {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	var b strings.Builder
	for _, u := range urls {
		b.WriteString(`{"url":"` + u + `"}` + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "urls.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write urls.jsonl: %v", err)
	}
}

// seedStaging writes a previous run's staging file and returns its path.
func seedStaging(t *testing.T, app *appctx.AppContext, name string) string {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(stalePreviousRunRecord), 0o644); err != nil {
		t.Fatalf("seed staging %s: %v", name, err)
	}
	return p
}

// stalePreviousRunRecord is a finding from a PREVIOUS run. Its distinctive
// marker makes a republish unmistakable in a failure message.
const stalePreviousRunRecord = `{"host":"stale.example.com","vuln_class":"STALE-PREVIOUS-RUN"}` + "\n"

func mustBeCleared(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		body, _ := os.ReadFile(path) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("%s: staging file %s still exists after a zero-result run — the previous "+
			"run's findings will be republished by the merge:\n%s", why, path, body)
	} else if !os.IsNotExist(err) {
		t.Fatalf("%s: unexpected stat error on %s: %v", why, path, err)
	}
}

func mustBePreserved(t *testing.T, path, why string) {
	t.Helper()
	body, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("%s: staging file %s was DELETED by a task that never ran — resume is "+
			"broken and the previous run's findings are lost: %v", why, path, err)
	}
	if string(body) != stalePreviousRunRecord {
		t.Fatalf("%s: staging file %s was rewritten by a task that never ran:\n%s", why, path, body)
	}
}

// ---------------------------------------------------------------------------
// Write-then-clear — two vulns tasks
// ---------------------------------------------------------------------------

// TestCRLFStagingWriteThenClear is the vulns half of gate 3 at the producer for
// a STREAM-based task. Run A finds an injection; run B finds none and must
// remove the staging file rather than leave run A's for the merge.
//
// It also covers the premature-return hole this plan closed: crlf.go used to
// `return StatusDone` on os.IsNotExist(readErr) — i.e. on the completely normal
// "clean target, crlfuzz wrote no output file" path — one statement BEFORE the
// staging write, so a target that had been fixed kept reporting its old CRLF
// injection forever. The detector could never have seen that.
func TestCRLFStagingWriteThenClear(t *testing.T) {
	t.Run("run A: crlfuzz finds an injection", func(t *testing.T) {
		be := newStageFakeBackend()
		app := newStageTestApp(t, be, nil)
		seedURLCorpus(t, app, "https://a.example.com/")
		staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.crlf.jsonl")

		// crlfuzz writes its hits to the -o path.
		be.onExec = func(tool string, args []string) {
			if tool != "crlfuzz" {
				return
			}
			out := argAfter(args, "-o")
			_ = os.WriteFile(out, []byte("https://a.example.com/%0d%0aSet-Cookie:x\n"), 0o644) //nolint:gosec,errcheck
		}

		res, err := (&CRLFTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("run A: %v", err)
		}
		if res.Status != "done" {
			t.Fatalf("run A status = %q, want done", res.Status)
		}
		body, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		if rErr != nil {
			t.Fatalf("run A must WRITE the staging file: %v", rErr)
		}
		if !strings.Contains(string(body), "crlf") {
			t.Fatalf("run A staging is missing the finding:\n%s", body)
		}
	})

	t.Run("run B: crlfuzz finds nothing and clears", func(t *testing.T) {
		be := newStageFakeBackend()
		app := newStageTestApp(t, be, nil)
		seedURLCorpus(t, app, "https://a.example.com/")
		staging := seedStaging(t, app, "findings.crlf.jsonl")

		// crlfuzz runs and writes NO output file — the clean-target path.
		res, err := (&CRLFTask{}).Run(context.Background(), app)
		if err != nil {
			t.Fatalf("run B: %v", err)
		}
		if res.Status != "done" {
			t.Fatalf("run B status = %q, want done", res.Status)
		}
		mustBeCleared(t, staging, "crlfuzz ran and found no injection")
	})
}

// TestCRLFDidNotRunPreservesStaging is the companion: crlfuzz is not installed,
// so the task observed nothing and must NOT delete the previous run's findings.
// This is the regression the write-or-remove migration would otherwise have
// introduced on every host without the optional binary.
func TestCRLFDidNotRunPreservesStaging(t *testing.T) {
	be := newStageFakeBackend()
	be.errs["crlfuzz"] = errors.New("exec: \"crlfuzz\": executable file not found in $PATH")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/")
	staging := seedStaging(t, app, "findings.crlf.jsonl")

	res, err := (&CRLFTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("an absent optional tool must not error: %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("an absent binary is a DISPATCH failure and must never escalate to errored")
	}
	mustBePreserved(t, staging, "crlfuzz is not installed")
}

// TestSmugglingStagingWriteThenClear is the vulns half of gate 3 at the producer
// for a RUN-based (non-stream) task.
func TestSmugglingStagingWriteThenClear(t *testing.T) {
	t.Run("run A: smugglex detects a desync", func(t *testing.T) {
		be := newStageFakeBackend()
		be.stdout["smugglex"] = []byte(`{"detected":true,"target":"https://a.example.com/"}` + "\n")
		app := newStageTestApp(t, be, nil)
		seedURLCorpus(t, app, "https://a.example.com/")
		staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.smuggling.jsonl")

		if _, err := (&SmugglingTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run A: %v", err)
		}
		body, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		if rErr != nil {
			t.Fatalf("run A must WRITE the staging file: %v", rErr)
		}
		if !strings.Contains(string(body), "smuggling") {
			t.Fatalf("run A staging is missing the finding:\n%s", body)
		}
	})

	t.Run("run B: smugglex detects nothing and clears", func(t *testing.T) {
		be := newStageFakeBackend()
		be.stdout["smugglex"] = nil
		app := newStageTestApp(t, be, nil)
		seedURLCorpus(t, app, "https://a.example.com/")
		staging := seedStaging(t, app, "findings.smuggling.jsonl")

		if _, err := (&SmugglingTask{}).Run(context.Background(), app); err != nil {
			t.Fatalf("run B: %v", err)
		}
		mustBeCleared(t, staging, "smugglex ran and detected no desync")
	})
}

// TestSmugglingDidNotRunPreservesStaging — smugglex absent → preserve.
func TestSmugglingDidNotRunPreservesStaging(t *testing.T) {
	be := newStageFakeBackend()
	be.errs["smugglex"] = errors.New("exec: \"smugglex\": executable file not found in $PATH")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/")
	staging := seedStaging(t, app, "findings.smuggling.jsonl")

	if _, err := (&SmugglingTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("an absent optional tool must not error: %v", err)
	}
	mustBePreserved(t, staging, "smugglex is not installed")
}

// ---------------------------------------------------------------------------
// The resume-preservation guard — a CONFIG-GATED skip must not clear
// ---------------------------------------------------------------------------

// TestConfigGatedSkipDoesNotClearStaging is the criterion most likely to be
// violated by a careless sweep: vulns.sqli with BOTH engines disabled returns
// StatusSkipped without running anything. It never observed the corpus, so its
// staging file must survive for the merge — that is what makes checkpoint resume
// work (internal/core/output/staging.go).
func TestConfigGatedSkipDoesNotClearStaging(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SQLi = config.VulnSQLi{Enabled: true, SQLMap: false, Ghauri: false}

	be := newStageFakeBackend()
	app := newStageTestApp(t, be, cfg)
	staging := seedStaging(t, app, "findings.sqli.jsonl")
	// A populated gf bucket, so the ONLY reason to skip is the config gate.
	seedGFBucket(t, app, "sqli", "https://a.example.com/?id=1")

	res, err := (&SQLiTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("config-gated skip must not error: %v", err)
	}
	if res.Status != "skipped" {
		t.Fatalf("status = %q, want skipped (no engine enabled)", res.Status)
	}
	mustBePreserved(t, staging, "vulns.sqli was config-gated and never ran")
	if len(be.calls) != 0 {
		t.Fatalf("a config-gated task must dispatch NO tool, got %v", be.calls)
	}
}

// ---------------------------------------------------------------------------
// Gate 3 end to end — producer → MergeVulnsFindings → artefacts/findings.jsonl
// ---------------------------------------------------------------------------

// TestGate3VulnsProducerToMergedFindings drives the full path the audit's
// finding F3 describes: run A publishes a vulnerability, run B finds nothing and
// the artefact must become PRESENT and EMPTY rather than keeping run A's record.
//
// "findings" has no direct artefact writer outside the merge path, so an empty
// publish is the correct outcome here (15-03 Case A).
func TestGate3VulnsProducerToMergedFindings(t *testing.T) {
	be := newStageFakeBackend()
	be.stdout["smugglex"] = []byte(`{"detected":true,"target":"https://a.example.com/"}` + "\n")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/")
	if err := attachTree(app); err != nil {
		t.Fatalf("attach tree: %v", err)
	}
	artefact := filepath.Join(app.Target.WorkDir, "artefacts", "findings.jsonl")

	// Run A — producer finds one, merge publishes one.
	if _, err := (&SmugglingTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("run A producer: %v", err)
	}
	if err := MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run A merge: %v", err)
	}
	body, err := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("run A artefact: %v", err)
	}
	if n := countJSONLines(string(body)); n != 1 {
		t.Fatalf("run A artefact should hold 1 finding, got %d:\n%s", n, body)
	}

	// Run B — producer finds nothing, staging is cleared, merge publishes empty.
	be.stdout["smugglex"] = nil
	if _, err := (&SmugglingTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("run B producer: %v", err)
	}
	if err := MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("run B merge: %v", err)
	}
	info, sErr := os.Stat(artefact)
	if sErr != nil {
		t.Fatalf("run B must leave the artefact PRESENT: %v", sErr)
	}
	if info.Size() != 0 {
		after, _ := os.ReadFile(artefact) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("run B republished run A's vulnerability (size %d):\n%s", info.Size(), after)
	}
}

// ---------------------------------------------------------------------------
// Credential redaction survives the migration (XCUT-07 / T-15-14-04)
// ---------------------------------------------------------------------------

// TestSprayStagedRecordKeepsCredentialRedacted proves the F3 sweep did not
// disturb the spray redaction: the staged record carries "***" and no raw
// credential value reaches inputs/findings.spray.jsonl.
func TestSprayStagedRecordKeepsCredentialRedacted(t *testing.T) {
	const rawPassword = "Sup3rS3cret!"
	app := newStageTestApp(t, newStageFakeBackend(), nil)

	findings := parseBrutesprayHits([]byte(
		"[+] ssh - 10.0.0.5:22 - Login Successful - admin:" + rawPassword + "\n"))
	if len(findings) == 0 {
		t.Fatalf("fixture produced no spray finding — the parser changed shape")
	}
	sprayWriteFindings(app, true, findings)

	staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.spray.jsonl")
	body, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("spray staging must exist: %v", err)
	}
	if strings.Contains(string(body), rawPassword) {
		t.Fatalf("XCUT-07 VIOLATION: the raw credential reached the staged record:\n%s", body)
	}
	if !strings.Contains(string(body), "***") {
		t.Fatalf("the staged spray record must carry the *** redaction marker:\n%s", body)
	}
}

// TestSprayZeroFindingsClearsStaging — the spray write-then-clear half.
func TestSprayZeroFindingsClearsStaging(t *testing.T) {
	app := newStageTestApp(t, newStageFakeBackend(), nil)
	staging := seedStaging(t, app, "findings.spray.jsonl")

	sprayWriteFindings(app, true, nil)
	mustBeCleared(t, staging, "the spray engine ran and no credential was accepted")
}

// TestSprayDidNotRunPreservesStaging — brutus absent → preserve.
func TestSprayDidNotRunPreservesStaging(t *testing.T) {
	app := newStageTestApp(t, newStageFakeBackend(), nil)
	staging := seedStaging(t, app, "findings.spray.jsonl")

	sprayWriteFindings(app, false, nil)
	mustBePreserved(t, staging, "the spray engine binary is absent")
}

// ---------------------------------------------------------------------------
// gf buckets — the detector's structural blind spot, covered behaviourally
// ---------------------------------------------------------------------------

// TestGFBucketRewrittenOnZeroMatch is the executable half of the gf hand
// verification (plan 15-14 Task 1).
//
// inputs/gf/<class>.txt is a SUBDIRECTORY path, and filepath.Glob's `*` does not
// cross `/`, so no merger glob can reach it and the staging-contract detector is
// structurally blind to gf.go. gf.go is therefore out of scope BY CONSTRUCTION —
// it is in neither the allowlist nor derivedOutputExemptions. The cost of that
// blindness is paid here: sqli, xss, lfi and ssrf all take their targets from
// these buckets, so a stale bucket silently redirects four scanners at the
// previous run's URLs.
//
// The bucket must be REWRITTEN (to empty), never REMOVED — four scanners open it.
func TestGFBucketRewrittenOnZeroMatch(t *testing.T) {
	be := newStageFakeBackend()
	// gf matches nothing for any class this run.
	be.stdout["gf"] = nil
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/?id=1")

	// A PREVIOUS run's xss bucket, holding a URL that no longer matches.
	const staleURL = "https://stale.example.com/?q=STALE-PREVIOUS-RUN"
	seedGFBucket(t, app, "xss", staleURL)
	bucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "xss.txt")

	if _, err := (&GFTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("gf run: %v", err)
	}

	body, err := os.ReadFile(bucket) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("the gf bucket must still EXIST (four scanners stat it), got: %v", err)
	}
	if strings.Contains(string(body), "STALE-PREVIOUS-RUN") {
		t.Fatalf("the previous run's bucket survived a zero-match run — sqli/xss/lfi/ssrf "+
			"would be pointed at last run's URLs:\n%s", body)
	}
	if n := countNonBlankLines(string(body)); n != 0 {
		t.Fatalf("a zero-match class must leave an EMPTY bucket, got %d non-blank lines:\n%s", n, body)
	}
}

// TestGFBucketRewrittenWhenToolFails covers the second of gf's three write
// paths: gf itself fails for a class. The bucket is still rewritten empty so a
// downstream scanner can stat it without error and cannot read stale targets.
func TestGFBucketRewrittenWhenToolFails(t *testing.T) {
	be := newStageFakeBackend()
	be.errs["gf"] = errors.New("exec: \"gf\": executable file not found in $PATH")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/?id=1")
	seedGFBucket(t, app, "sqli", "https://stale.example.com/?id=STALE-PREVIOUS-RUN")
	bucket := filepath.Join(app.Target.WorkDir, "inputs", "gf", "sqli.txt")

	if _, err := (&GFTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("gf run: %v", err)
	}
	body, err := os.ReadFile(bucket) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("the gf bucket must still EXIST after a tool failure: %v", err)
	}
	if strings.Contains(string(body), "STALE-PREVIOUS-RUN") {
		t.Fatalf("a gf failure left the previous run's bucket in place:\n%s", body)
	}
}

// TestGFEveryClassBucketRewritten pins the enumerated hand verification: after a
// completed run, EVERY class in gfClasses has a present bucket. A class that
// could be skipped without its bucket being rewritten is exactly the F3 gap the
// hand verification looks for.
func TestGFEveryClassBucketRewritten(t *testing.T) {
	be := newStageFakeBackend()
	be.stdout["gf"] = nil
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/?id=1")

	if _, err := (&GFTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("gf run: %v", err)
	}
	for _, class := range gfClasses {
		p := filepath.Join(app.Target.WorkDir, "inputs", "gf", class+".txt")
		if _, err := os.Stat(p); err != nil {
			t.Errorf("class %q has no bucket after a completed run — a scanner that stats it "+
				"would read the PREVIOUS run's file, or fail: %v", class, err)
		}
	}
}

// TestGFBucketsAreNotRoutedThroughStagingHelpers pins the negative direction:
// remove-on-empty semantics must never be applied to the gf buckets, because
// four scanners open the path and a missing file is not the same as an empty one.
func TestGFBucketsAreNotRoutedThroughStagingHelpers(t *testing.T) {
	src, err := os.ReadFile("gf.go")
	if err != nil {
		t.Fatalf("read gf.go: %v", err)
	}
	body := string(src)
	for _, banned := range []string{"output.StageJSONL(", "output.StageLines(", "stageVulnFindings("} {
		if strings.Contains(body, banned) {
			t.Errorf("gf.go must NOT call %s — inputs/gf/<class>.txt is a derived intermediate "+
				"that sqli/xss/lfi/ssrf open as a file; remove-on-empty would break them. It "+
				"writes an EMPTY bucket instead.", banned)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func seedGFBucket(t *testing.T, app *appctx.AppContext, class string, urls ...string) {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "inputs", "gf")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir inputs/gf: %v", err)
	}
	body := strings.Join(urls, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, class+".txt"), []byte(body), 0o644); err != nil {
		t.Fatalf("seed gf bucket %s: %v", class, err)
	}
}

// attachTree gives the AppContext an OutputTree so MergeVulnsFindings can
// publish. A nil ScopeFilter admits every record, which is what these
// F3-lifecycle tests are about — scope behaviour is covered elsewhere.
func attachTree(app *appctx.AppContext) error {
	tree, err := output.NewTree(app.Target.WorkDir, nil)
	if err != nil {
		return err
	}
	app.Tree = tree
	return nil
}

func argAfter(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func countJSONLines(s string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			n++
		}
	}
	return n
}

func countNonBlankLines(s string) int { return countJSONLines(s) }
