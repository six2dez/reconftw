// github_actions_test.go — XCUT-07 redaction + parse assertions for the gato
// GitHub Actions audit (OSINT-06).
//
// CRITICAL (T-07-03-01): gato output may embed live workflow secrets. These
// tests prove the raw secret VALUE is NEVER propagated to a record — every
// secret-exposure record carries ValueRedacted="***" and only a non-secret
// locator survives.
package osint

import (
	"bytes"
	"context"
	"encoding/json"
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

// FAKE_WORKFLOW_SECRET_AAAA is a clearly-synthetic secret marker (mirrors the
// vulns dalfox FAKE_XSS_MARKER convention) so we can assert redaction without
// committing a real secret value.
const fakeWorkflowSecret = "FAKE_WORKFLOW_SECRET_AAAA_ghp_deadbeefcafebabe"

func TestParseGatoOutput_RedactsSurfacedSecret(t *testing.T) {
	// Synthetic gato-shaped JSON with a secret-bearing artifact entry.
	gatoJSON := `{
		"organization": "acme",
		"repositories": [
			{
				"name": "acme/ci",
				"workflow_secrets": ["` + fakeWorkflowSecret + `"],
				"artifact_token": "` + fakeWorkflowSecret + `"
			}
		]
	}`

	records := parseGatoOutput([]byte(gatoJSON))
	if len(records) == 0 {
		t.Fatal("parseGatoOutput returned no records for secret-bearing gato JSON")
	}

	for _, rec := range records {
		// Marshal the full record and assert the raw secret never appears.
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if strings.Contains(string(b), fakeWorkflowSecret) {
			t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into record: %s", string(b))
		}
		if rec.Category == "workflow-secret-exposure" && rec.ValueRedacted != "***" {
			t.Fatalf("expected ValueRedacted=*** for secret-exposure record, got %q", rec.ValueRedacted)
		}
	}
}

// gatoFakeBackend is a Backend test double for the GitHub Actions Run path. On
// ExecEnv it records the env (so we can assert GH_TOKEN delivery) and writes
// gatoJSON to the file named after the "-oJ" arg (simulating gato's -oJ output),
// without spawning a subprocess.
type gatoFakeBackend struct {
	gatoJSON string   // content to write to the -oJ target
	lastEnv  []string // env captured from the most recent ExecEnv call
}

func (g *gatoFakeBackend) writeOutput(args []string) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-oJ" {
			_ = os.WriteFile(args[i+1], []byte(g.gatoJSON), 0o600)
			return
		}
	}
}

func (g *gatoFakeBackend) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	g.writeOutput(args)
	return &backend.Result{ExitCode: 0}, nil
}

func (g *gatoFakeBackend) ExecEnv(_ context.Context, _ *backend.Tool, args []string, env []string) (*backend.Result, error) {
	g.lastEnv = append([]string(nil), env...)
	g.writeOutput(args)
	return &backend.Result{ExitCode: 0}, nil
}

func (g *gatoFakeBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (g *gatoFakeBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (g *gatoFakeBackend) HealthCheck(_ context.Context) error { return nil }
func (g *gatoFakeBackend) Capacity() int                       { return 1 }

// runGitHubActions wires a GitHubActionsTask with a token file, a redacting
// logger over buf, and the gatoFakeBackend, then runs it. Returns the backend
// (for env assertions) and the logger buffer (for leak assertions).
func runGitHubActions(t *testing.T, gatoJSON, token string) (*gatoFakeBackend, *bytes.Buffer, string) {
	t.Helper()
	workDir := t.TempDir()

	// Token file (the D-O8 key gate source).
	tokenFile := filepath.Join(workDir, "github_tokens.txt")
	if err := os.WriteFile(tokenFile, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := &config.Config{}
	cfg.OSINT.GitHub.ActionsAudit.Enabled = true
	cfg.Paths.GitHubTokens = tokenFile

	// Redacting logger over a buffer so we can assert the token never leaks.
	redactor := &log.Redactor{}
	buf := &bytes.Buffer{}
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(log.NewRedactingHandler(inner, redactor))

	be := &gatoFakeBackend{gatoJSON: gatoJSON}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "gato"})
	runner := backend.NewRunner(be, reg, nil)

	app := &appctx.AppContext{
		Log:   logger,
		Cfg:   cfg,
		Tools: runner,
		Target: &appctx.Target{
			Domain:  "acme.com",
			WorkDir: workDir,
		},
	}

	res, err := (&GitHubActionsTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("GitHubActionsTask.Run returned err=%v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("Run status = %v, want StatusDone", res.Status)
	}
	return be, buf, workDir
}

// TestGitHubActions_SideFileHasNoRawSecret proves GAP-03: the raw gato JSON
// (which embeds a live workflow secret) is NEVER persisted to a side-file under
// the workspace — only the redacted findings.jsonl survives.
func TestGitHubActions_SideFileHasNoRawSecret(t *testing.T) {
	gatoJSON := `{
		"organization": "acme",
		"repositories": [
			{"name": "acme/ci", "workflow_secrets": ["` + fakeWorkflowSecret + `"]}
		]
	}`

	_, _, workDir := runGitHubActions(t, gatoJSON, "ghp_faketoken_value_AAAA_1234567890")

	// 1. No persisted osint/github_actions_audit.json (omitted entirely).
	if _, err := os.Stat(filepath.Join(workDir, "osint", "github_actions_audit.json")); err == nil {
		t.Fatal("XCUT-07 VIOLATION: osint/github_actions_audit.json was persisted")
	}

	// 2. The raw secret marker must not appear in ANY persisted file in the workspace.
	err := filepath.Walk(workDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, rErr := os.ReadFile(path) //nolint:gosec // test workspace
		if rErr != nil {
			return nil
		}
		if bytes.Contains(data, []byte(fakeWorkflowSecret)) {
			t.Fatalf("XCUT-07 VIOLATION: raw secret leaked into persisted file %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk workspace: %v", err)
	}

	// 3. The redacted findings staging file IS written (redacted records survive).
	staging := filepath.Join(workDir, "inputs", "findings.github_actions.jsonl")
	if data, sErr := os.ReadFile(staging); sErr == nil {
		if !bytes.Contains(data, []byte("***")) {
			t.Errorf("expected redacted findings (ValueRedacted=***) in %s", staging)
		}
	}
}

// TestGitHubActions_GHTokenEnvAndNoLogLeak proves GAP-02 + T-07-09-01: gato is
// invoked with GH_TOKEN in its child env (off argv), and the token value never
// appears in any log line.
func TestGitHubActions_GHTokenEnvAndNoLogLeak(t *testing.T) {
	const token = "ghp_secret_token_value_DEADBEEF_998877"
	gatoJSON := `{"organization":"acme"}`

	be, logBuf, _ := runGitHubActions(t, gatoJSON, token)

	// 1. GH_TOKEN env entry is constructed and forwarded to the env-capable call.
	wantEntry := "GH_TOKEN=" + token
	found := false
	for _, e := range be.lastEnv {
		if e == wantEntry {
			found = true
		}
	}
	if !found {
		t.Fatalf("gato was not invoked with %q in its env; got env=%v", wantEntry, be.lastEnv)
	}

	// 2. The token value must NEVER appear in captured log output (redactor L2).
	if strings.Contains(logBuf.String(), token) {
		t.Fatalf("XCUT-07 VIOLATION: GH_TOKEN leaked into log output: %s", logBuf.String())
	}
}

func TestParseGatoOutput_Empty(t *testing.T) {
	if recs := parseGatoOutput(nil); recs != nil {
		t.Fatalf("expected nil for empty input, got %v", recs)
	}
	if recs := parseGatoOutput([]byte("   ")); recs != nil {
		t.Fatalf("expected nil for whitespace input, got %v", recs)
	}
	if recs := parseGatoOutput([]byte("not json")); recs != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", recs)
	}
}

func TestCompanyName(t *testing.T) {
	cases := map[string]string{
		"example.com":     "example",
		"example.co.uk":   "example",
		"sub.example.com": "example",
		"acme.org":        "acme",
		"acme.com.au":     "acme",
		"single":          "single",
	}
	for in, want := range cases {
		if got := companyName(in); got != want {
			t.Errorf("companyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDorkRecords_Dedup(t *testing.T) {
	hits := []string{"https://x/1", "https://x/1", "https://x/2"}
	recs := dorkRecords(hits, "github_dorks", "github-dork")
	if len(recs) != 2 {
		t.Fatalf("expected 2 deduped records, got %d", len(recs))
	}
	for _, r := range recs {
		if r.Severity != "informational" || r.Source != "github_dorks" {
			t.Errorf("unexpected record shape: %+v", r)
		}
	}
}
