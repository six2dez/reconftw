// github_repos_test.go — behavior tests for the GithubReposTask company-repo
// secret scan (13-06 Task 1, PAR-03).
//
// Proves the highest-complexity OSINT parity restore: after enumerepo,
// GithubReposTask clones every company repo (sha256-named dirs, no token on
// argv), runs titus (bash's default engine) + trufflehog, merges the per-repo
// scan output into osint/github_company_secrets.json (bash-parity human
// artefact), and emits REDACTED OSINTFindingRecords to
// inputs/findings.github_secrets.jsonl (XCUT-07 / T-13-06-02 — the raw secret is
// registered with the Redactor and NEVER reaches the JSONL stream or a log line).
//
// noseyparker is DEFERRED to Phase 14: SecretsEngine=="noseyparker" logs a
// "deferred — using titus" note and runs titus (no noseyparker invocation).
//
// Internal (package osint) to reach the unexported git-clone seam
// (githubReposGitClone) + reuse the in-package redacting-logger idiom
// (emails_test.go / github_actions_test.go). Synthetic FAKE_ markers mirror the
// vulns dalfox FAKE_XSS_MARKER convention so redaction is asserted without
// committing a real credential.
//
// Source: .planning/phases/13-domain-parity/13-06-PLAN.md Task 1.
package osint

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// fakeGithubSecret / fakeGithubToken are clearly-synthetic markers so redaction
// and argv-hygiene can be asserted without committing a real secret.
const (
	fakeGithubSecret = "FAKE_GH_REPO_SECRET_AAAA_correcthorsebatterystaple"
	fakeGithubToken  = "FAKE_GH_TOKEN_ghp_0000deadbeef0000deadbeef0000deadbeef"
)

// githubReposBackend is a Backend double for the GithubReposTask Run path.
//   - enumerepo: writes enumerepoOut to the "-o" file (like the real tool).
//   - titus:     returns titusOut on stdout (bash redirects titus stdout → json).
//   - trufflehog: returns trufflehogOut on stdout.
//
// It records every arg vector (seenArgs, mutex-guarded — clone/scan run
// concurrently) so the token-off-argv (XCUT-07) invariant can be asserted.
type githubReposBackend struct {
	mu            sync.Mutex
	enumerepoOut  string
	titusOut      string
	trufflehogOut string
	seenArgs      [][]string
}

func (b *githubReposBackend) record(args []string) {
	b.mu.Lock()
	b.seenArgs = append(b.seenArgs, append([]string(nil), args...))
	b.mu.Unlock()
}

func (b *githubReposBackend) Exec(_ context.Context, tool *backend.Tool, args []string) (*backend.Result, error) {
	b.record(args)
	switch tool.Name {
	case "enumerepo":
		for i := 0; i+1 < len(args); i++ {
			if args[i] == "-o" {
				_ = os.WriteFile(args[i+1], []byte(b.enumerepoOut), 0o644) //nolint:errcheck,gosec
			}
		}
		return &backend.Result{ExitCode: 0}, nil
	case "titus":
		return &backend.Result{Stdout: []byte(b.titusOut), ExitCode: 0}, nil
	case "trufflehog":
		return &backend.Result{Stdout: []byte(b.trufflehogOut), ExitCode: 0}, nil
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (b *githubReposBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, tool, args)
}

func (b *githubReposBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *githubReposBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *githubReposBackend) HealthCheck(_ context.Context) error { return nil }
func (b *githubReposBackend) Capacity() int                       { return 1 }

// githubReposFixture bundles the knobs a test needs to drive GithubReposTask.
type githubReposFixture struct {
	be              *githubReposBackend
	token           string // written to cfg.Paths.GitHubTokens (empty → no token file)
	secretsEngine   string // cfg.OSINT.GitHub.SecretsEngine
	registerTitus   bool
	registerTruffle bool
}

// runGithubReposTask wires a GithubReposTask with a redacting logger over buf,
// the given Backend double, and a hermetic git-clone seam (creates the dest dir
// instead of spawning git). Returns the app (workspace inspection), the log
// buffer (leak assertions), and the Result.
func runGithubReposTask(t *testing.T, fx githubReposFixture) (*appctx.AppContext, *bytes.Buffer, task.Result) {
	t.Helper()
	workDir := t.TempDir()

	cfg := &config.Config{}
	cfg.OSINT.GitHub.Enabled = true
	cfg.OSINT.GitHub.Threads = 4
	cfg.OSINT.GitHub.ScanGitHistory = true
	cfg.OSINT.GitHub.SecretsEngine = fx.secretsEngine
	if fx.token != "" {
		tokenPath := filepath.Join(workDir, "ghtokens.txt")
		if err := os.WriteFile(tokenPath, []byte(fx.token+"\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		cfg.Paths.GitHubTokens = tokenPath
	}

	redactor := &log.Redactor{}
	buf := &bytes.Buffer{}
	logger := slog.New(log.NewRedactingHandler(
		slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}), redactor))

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "enumerepo"})
	if fx.registerTitus {
		reg.Register(&backend.Tool{Name: "titus"})
	}
	if fx.registerTruffle {
		reg.Register(&backend.Tool{Name: "trufflehog"})
	}
	runner := backend.NewRunner(fx.be, reg, nil)

	// Hermetic clone seam: create the destination dir (a stand-in for a cloned
	// repo) so the titus scan step has a directory to target — no real git.
	prevClone := githubReposGitClone
	t.Cleanup(func() { githubReposGitClone = prevClone })
	githubReposGitClone = func(_ context.Context, _ string, dest string) error {
		return os.MkdirAll(dest, 0o755)
	}

	app := &appctx.AppContext{
		Log:    logger,
		Cfg:    cfg,
		Tools:  runner,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
	res, err := (&GitHubReposTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("GithubReposTask.Run: unexpected error: %v", err)
	}
	return app, buf, res
}

// enumerepoTwoRepos is a canonical enumerepo -o JSON blob with two repo URLs.
const enumerepoTwoRepos = `[{"username":"example","repos":[` +
	`{"url":"https://github.com/example/repo1"},` +
	`{"url":"https://github.com/example/repo2"}]}]`

// titusOneSecret is a stubbed `titus scan --format json` output carrying one
// synthetic secret (bash-parity native tool output).
var titusOneSecret = `[{"detector":"AWS","file":".env","line":3,"validated":true,"secret":"` + fakeGithubSecret + `"}]`

// TestGithubReposTask_TitusScanProducesRedactedFindings is the happy path:
// enumerepo → clone → titus → merged github_company_secrets.json + REDACTED
// findings.github_secrets.jsonl, with the raw secret scrubbed from logs and
// absent from the JSONL stream. Also proves token-off-argv (XCUT-07).
func TestGithubReposTask_TitusScanProducesRedactedFindings(t *testing.T) {
	fx := githubReposFixture{
		be:              &githubReposBackend{enumerepoOut: enumerepoTwoRepos, titusOut: titusOneSecret},
		token:           fakeGithubToken,
		secretsEngine:   "titus",
		registerTitus:   true,
		registerTruffle: true,
	}
	app, buf, res := runGithubReposTask(t, fx)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}

	// 1. github_company_secrets.json (bash-parity human artefact) is produced.
	secretsPath := filepath.Join(app.Target.WorkDir, "osint", "github_company_secrets.json")
	sData, err := os.ReadFile(secretsPath)
	if err != nil {
		t.Fatalf("osint/github_company_secrets.json not written: %v", err)
	}
	if len(bytes.TrimSpace(sData)) == 0 {
		t.Errorf("github_company_secrets.json is empty; want native titus output")
	}

	// 2. findings.github_secrets.jsonl exists, is REDACTED, never carries the raw secret.
	fPath := filepath.Join(app.Target.WorkDir, "inputs", "findings.github_secrets.jsonl")
	fData, err := os.ReadFile(fPath)
	if err != nil {
		t.Fatalf("inputs/findings.github_secrets.jsonl not written: %v", err)
	}
	if bytes.Contains(fData, []byte(fakeGithubSecret)) {
		t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into findings.github_secrets.jsonl:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"value_redacted":"***"`)) {
		t.Errorf("findings.github_secrets.jsonl must carry value_redacted=***; got:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"category":"leaked-secret"`)) {
		t.Errorf("findings.github_secrets.jsonl missing category leaked-secret; got:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"source":"github_repos"`)) {
		t.Errorf("findings.github_secrets.jsonl missing source github_repos; got:\n%s", fData)
	}

	// 3. XCUT-07 L2: the raw secret was registered → scrubbed from ALL log output.
	app.Log.Info("github-repos-test-probe", "secret", fakeGithubSecret)
	if strings.Contains(buf.String(), fakeGithubSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: raw secret leaked into log output:\n%s", buf.String())
	}

	// 4. XCUT-07 T-13-06-01: the token NEVER appears on any tool argv, and
	//    enumerepo received -token-file pointing at a temp file (removed after run).
	var tokenFilePath string
	for _, args := range fx.be.seenArgs {
		for i, a := range args {
			if strings.Contains(a, fakeGithubToken) {
				t.Fatalf("XCUT-07 VIOLATION: token on argv: %v", args)
			}
			if a == "-token-file" && i+1 < len(args) {
				tokenFilePath = args[i+1]
			}
		}
	}
	if tokenFilePath == "" {
		t.Errorf("enumerepo not invoked with -token-file (token hygiene)")
	} else if _, statErr := os.Stat(tokenFilePath); statErr == nil {
		t.Errorf("temp token file %q not removed after run", tokenFilePath)
	}

	if res.Stats["secrets"] < 1 {
		t.Errorf("Stats[secrets] = %d, want >= 1", res.Stats["secrets"])
	}
}

// TestGithubReposTask_NoseyparkerDefersToTitus proves the Phase-14 deferral:
// SecretsEngine=="noseyparker" logs a deferral note and runs titus (no
// noseyparker invocation), still producing github_company_secrets.json.
func TestGithubReposTask_NoseyparkerDefersToTitus(t *testing.T) {
	fx := githubReposFixture{
		be:              &githubReposBackend{enumerepoOut: enumerepoTwoRepos, titusOut: titusOneSecret},
		token:           fakeGithubToken,
		secretsEngine:   "noseyparker",
		registerTitus:   true,
		registerTruffle: true,
	}
	app, buf, res := runGithubReposTask(t, fx)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}
	logs := strings.ToLower(buf.String())
	if !strings.Contains(logs, "noseyparker") || !strings.Contains(logs, "titus") {
		t.Errorf("expected a noseyparker-deferred/using-titus log note; got:\n%s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "github_company_secrets.json")); err != nil {
		t.Errorf("titus fallback did not produce github_company_secrets.json: %v", err)
	}
	if res.Stats["secrets"] < 1 {
		t.Errorf("Stats[secrets] = %d, want >= 1 (titus fallback ran)", res.Stats["secrets"])
	}
}

// TestGithubReposTask_NoTokenSkips proves the D-O8 key gate: no GitHub token →
// StatusSkipped, no clone, no secrets file.
func TestGithubReposTask_NoTokenSkips(t *testing.T) {
	fx := githubReposFixture{
		be:            &githubReposBackend{enumerepoOut: enumerepoTwoRepos, titusOut: titusOneSecret},
		token:         "", // no token file configured
		secretsEngine: "titus",
		registerTitus: true,
	}
	app, _, res := runGithubReposTask(t, fx)

	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %q, want skipped (no token)", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "github_company_secrets.json")); err == nil {
		t.Error("github_company_secrets.json written despite missing token")
	}
}

// TestGithubReposTask_TitusAbsentDegrades proves best-effort (D-O8): titus not
// registered → StatusDone + warning, no crash, no github_company_secrets.json
// (trufflehog yields nothing here). enumerepo-only behavior is preserved.
func TestGithubReposTask_TitusAbsentDegrades(t *testing.T) {
	fx := githubReposFixture{
		be:              &githubReposBackend{enumerepoOut: enumerepoTwoRepos, trufflehogOut: ""},
		token:           fakeGithubToken,
		secretsEngine:   "titus",
		registerTitus:   false, // titus unavailable
		registerTruffle: true,
	}
	app, buf, res := runGithubReposTask(t, fx)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done (best_effort degrade)", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "github_company_secrets.json")); err == nil {
		t.Error("github_company_secrets.json written despite no scan output")
	}
	if !strings.Contains(strings.ToLower(buf.String()), "titus") {
		t.Errorf("expected a titus-unavailable warning; got:\n%s", buf.String())
	}
	if res.Stats["secrets"] != 0 {
		t.Errorf("Stats[secrets] = %d, want 0 on degrade", res.Stats["secrets"])
	}
	// enumerepo-only artefact preserved (feeds github_leaks).
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "inputs", "github_repos.txt")); err != nil {
		t.Errorf("inputs/github_repos.txt regression — not written: %v", err)
	}
}

// TestGithubReposTask_TrufflehogFindingsRedacted proves trufflehog enrichment
// (all engines) also surfaces REDACTED findings and merges into the human file.
func TestGithubReposTask_TrufflehogFindingsRedacted(t *testing.T) {
	th := `{"DetectorName":"AWS","Verified":true,"Raw":"` + fakeGithubSecret + `",` +
		`"SourceMetadata":{"Data":{"Git":{"repository":"https://github.com/example/repo1","file":".env","line":3}}}}`
	fx := githubReposFixture{
		be:              &githubReposBackend{enumerepoOut: enumerepoTwoRepos, trufflehogOut: th},
		token:           fakeGithubToken,
		secretsEngine:   "titus",
		registerTitus:   false, // titus absent → trufflehog carries the finding
		registerTruffle: true,
	}
	app, buf, res := runGithubReposTask(t, fx)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}
	fData, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "findings.github_secrets.jsonl"))
	if err != nil {
		t.Fatalf("findings.github_secrets.jsonl not written: %v", err)
	}
	if bytes.Contains(fData, []byte(fakeGithubSecret)) {
		t.Fatalf("XCUT-07 VIOLATION: raw trufflehog secret leaked into findings:\n%s", fData)
	}
	if !bytes.Contains(fData, []byte(`"value_redacted":"***"`)) {
		t.Errorf("trufflehog finding missing value_redacted=***; got:\n%s", fData)
	}
	app.Log.Info("probe", "s", fakeGithubSecret)
	if strings.Contains(buf.String(), fakeGithubSecret) {
		t.Fatalf("XCUT-07 L2 VIOLATION: raw trufflehog secret leaked into logs:\n%s", buf.String())
	}
	if res.Stats["secrets"] < 1 {
		t.Errorf("Stats[secrets] = %d, want >= 1 (trufflehog)", res.Stats["secrets"])
	}
}

// TestGithubReposGitCloneRejectsNonURL proves the WR-13-04 hardening: the git
// clone seam refuses any target that is not an http(s)/git URL BEFORE invoking
// git, so an option-injection value (leading "-", ext:: transport, file://) can
// never reach git's argv. The scheme check runs before exec.LookPath, so this is
// deterministic regardless of whether git is installed on the runner.
func TestGithubReposGitCloneRejectsNonURL(t *testing.T) {
	for _, bad := range []string{
		"--upload-pack=touch /tmp/pwned", // option injection
		"-oProxyCommand=evil",            // option injection
		"ext::sh -c whoami",              // ext:: transport → RCE
		"file:///etc/passwd",             // non-http(s)/git scheme
		"",                               // empty
	} {
		err := githubReposGitClone(context.Background(), bad, t.TempDir())
		if err == nil {
			t.Errorf("githubReposGitClone(%q) = nil; want rejection error", bad)
			continue
		}
		if !strings.Contains(err.Error(), "refusing to clone") {
			t.Errorf("githubReposGitClone(%q) err = %v; want 'refusing to clone'", bad, err)
		}
	}
}

// TestParseEnumerepoOutputFallbackOnlyOnParseFailure proves the WR-13-05 gate:
// the plain-text fallback runs ONLY when the payload is not valid JSON. Valid
// JSON whose repo keys are unrecognized (schema drift) must yield an empty list —
// NOT the pretty-printed JSON shredded into per-line "{"/"}" garbage.
func TestParseEnumerepoOutputFallbackOnlyOnParseFailure(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "enumerepo.json")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}

	t.Run("recognized JSON yields repo URLs", func(t *testing.T) {
		got := parseEnumerepoOutput(write(t, `[{"repos":[{"clone_url":"https://github.com/example/repo1"}]}]`))
		if len(got) != 1 || got[0] != "https://github.com/example/repo1" {
			t.Errorf("got %v, want [https://github.com/example/repo1]", got)
		}
	})

	t.Run("valid but unrecognized JSON yields empty (not shredded)", func(t *testing.T) {
		// Pretty-printed JSON whose keys collectRepoURLs does not match. The OLD
		// (len(out)>0) gate would shred this into 5 bogus per-line "repos".
		pretty := "{\n  \"unexpected\": [\n    {\"name\": \"repo1\"}\n  ]\n}\n"
		got := parseEnumerepoOutput(write(t, pretty))
		if len(got) != 0 {
			t.Errorf("schema-drift JSON shredded into %d bogus entries: %v; want empty", len(got), got)
		}
	})

	t.Run("non-JSON plaintext falls back to per-line URLs", func(t *testing.T) {
		got := parseEnumerepoOutput(write(t,
			"https://github.com/example/repo1\nhttps://github.com/example/repo2\n"))
		if len(got) != 2 {
			t.Errorf("plaintext fallback got %v, want 2 URLs", got)
		}
	})
}
