// stream_terminal_test.go — behavioural proof of the F6 terminal-error contract
// for the osint package (acceptance gate 5, plan 15-14 Task 2).
//
// osint has exactly two app.Tools.Stream call sites — CloudEnumTask.Run and
// GitHubLeaksTask.Run — and both are followed by work that treats whatever is on
// disk as this run's result: cloud_enum's bucket lines become the exposure
// verdict, and github_leaks os.ReadFile's the ghleaks --report path, which is
// NOT cleared between runs.
//
// Both directions are asserted:
//
//	TERMINAL — the scanner ran and exited 7 → task.StatusErrored, no partial
//	           publish, staging untouched.
//	DISPATCH — the scanner is not on PATH → best-effort, never errored. `osint`
//	           is PolicyBestEffort (internal/core/scheduler/policy.go).
package osint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// TestCloudEnumExitSevenErrorsAndDoesNotPublish is gate 5 for the osint stream
// site whose partial output would otherwise become a bucket-exposure verdict.
//
// cloud_enum reports one open bucket, then exits 7 with the keyword space only
// partly enumerated. Publishing that as this run's result would report a
// still-open bucket as closed; clearing staging on a crashed scanner's word
// would delete a real exposure. Neither may happen.
func TestCloudEnumExitSevenErrorsAndDoesNotPublish(t *testing.T) {
	be := newOsintStageBackend()
	be.streamLines["cloud_enum"] = []string{"[+] OPEN S3 BUCKET: http://acme.s3.amazonaws.com/"}
	be.terminalErr["cloud_enum"] = errors.New("exit status 7")
	app := newOsintStageApp(t, be)
	staging := seedOsintStaging(t, app, "findings.cloud_enum.jsonl")

	res, err := (&CloudEnumTask{}).Run(context.Background(), app)
	if res.Status != "errored" {
		t.Fatalf("status = %q, want errored (cloud_enum ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Fatalf("a terminal stream error must be RETURNED, not swallowed")
	}
	// The partial enumeration must not have been published, and the previous
	// run's real exposure must not have been retracted.
	osintMustBePreserved(t, staging, "cloud_enum exited 7")
	listPath := filepath.Join(app.Target.WorkDir, "osint", "cloud_enum.txt")
	if _, sErr := os.Stat(listPath); sErr == nil {
		body, _ := os.ReadFile(listPath) //nolint:gosec,errcheck // diagnostics only
		t.Fatalf("a crashed cloud_enum still wrote its partial bucket list to %s:\n%s",
			listPath, body)
	}
}

// TestCloudEnumAbsentBinaryStaysNonErrored pins the other side of the boundary.
func TestCloudEnumAbsentBinaryStaysNonErrored(t *testing.T) {
	be := newOsintStageBackend()
	be.errs["cloud_enum"] = errors.New("exec: \"cloud_enum\": executable file not found in $PATH")
	app := newOsintStageApp(t, be)

	res, err := (&CloudEnumTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("an absent optional scanner must not return an error: %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("an absent binary was escalated to errored — osint is PolicyBestEffort " +
			"and an incomplete optional toolchain must not fail a run")
	}
}

// TestGitHubLeaksExitSevenErrorsAndDoesNotReadReport is the higher-consequence
// of the two osint sites. ghleaks writes its findings to a --report path that
// nothing clears between runs, and the drain is immediately followed by
// os.ReadFile of that path — so a ghleaks killed mid-search used to have the
// PREVIOUS run's secret findings parsed and republished as this run's result.
func TestGitHubLeaksExitSevenErrorsAndDoesNotReadReport(t *testing.T) {
	be := newOsintStageBackend()
	be.streamLines["ghleaks"] = []string{"searching"}
	be.terminalErr["ghleaks"] = errors.New("exit status 7")
	app := newOsintStageApp(t, be)
	withGitHubToken(t, app)
	staging := seedOsintStaging(t, app, "findings.github_leaks.jsonl")

	// A PREVIOUS run's ghleaks report sitting at the --report path.
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		t.Fatalf("mkdir osint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(osintDir, "github_leaks.json"),
		[]byte(`[{"file":"stale-ghleaks.example/config.yml","match":"x"}]`+"\n"), 0o644); err != nil {
		t.Fatalf("seed stale report: %v", err)
	}

	res, err := (&GitHubLeaksTask{}).Run(context.Background(), app)
	if res.Status != "errored" {
		t.Fatalf("status = %q, want errored (ghleaks ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Fatalf("a terminal stream error must be RETURNED, not swallowed")
	}
	body, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if rErr != nil {
		t.Fatalf("staging must be preserved untouched after a crash: %v", rErr)
	}
	if strings.Contains(string(body), "stale-ghleaks.example") {
		t.Fatalf("a crashed ghleaks published the PREVIOUS run's report as this run's "+
			"secret finding:\n%s", body)
	}
}

// withGitHubToken satisfies the D-O8 key gate so the task reaches its scanner
// rather than returning StatusSkipped at the gate.
func withGitHubToken(t *testing.T, app *appctx.AppContext) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "github_tokens.txt")
	if err := os.WriteFile(p, []byte("ghp_testtoken000000000000000000000000\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	app.Cfg.Paths.GitHubTokens = p
}
