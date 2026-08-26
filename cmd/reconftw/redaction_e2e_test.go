// redaction_e2e_test.go — one reproduction, three sinks.
//
// Plan 16-01 changed ToolError.Error() to append up to 300 bytes of the tool's
// own stderr. That was the right call: it is the difference between "tool stream
// ended badly: exit status 1" and a message an operator can act on. But it also
// made tool-controlled bytes flow into places that had been documented as free
// of them — Result.Reason (via task.ToolDegraded) is printed to the terminal by
// StageProgress.TaskDoneReason, whose package header asserts as an INVARIANT
// that no tool stderr reaches it.
//
// A tool's stderr is not merely target-controlled. It routinely echoes the
// operator's own argv and configuration back: `-t <token>`, an auth failure
// quoting a bearer, a URL with an API key in the query string. So a config
// secret can arrive at a sink by a path no argv-redaction guard covers.
//
// This file drives the REAL compiled binary against ONE stub tool whose stderr
// is ONE generated high-entropy literal that is also the value of a config field
// registerSecrets knows (api_keys.shodan). Every sink assertion is made against
// that single reproduction rather than three differently-shaped ones — if the
// reproduction stops reproducing, all three fail together and loudly, instead of
// one quietly going green for the wrong reason.
//
// dnstake is the stub tool because it is the only tool in the subs pipeline that
// is (a) dispatched by exactly one task, (b) dispatched via the buffered Exec
// path, and (c) degraded through task.ToolDegraded on failure — which is what
// puts the tool's stderr into Result.Reason. A Stream-path tool (tlsx, puredns,
// or dnsx via SubNoerrorTask) returns StatusErrored with a non-nil error, which
// fail-fasts the subdomains group and makes the assertion racy.
package main_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// redactionSecret is the one literal every sink assertion in this file is made
// against. High-entropy and structurally unmistakable so a match cannot be a
// coincidence, and short enough to survive reasonSuffix's 90-column cap once the
// "dnstake: tool dnstake (exit 1): exit status 1: " prefix (47 bytes) is
// accounted for — a secret truncated away by the cap would make this test pass
// for a reason that has nothing to do with redaction.
const redactionSecret = "Sh0dAnK3y7Qx2Wv9Zb4Nm6Tj"

// redactionPlaceholder is what log.Redactor substitutes.
const redactionPlaceholder = "***"

// writeSecretConfig writes a minimal TOML config whose api_keys.shodan carries
// redactionSecret, and returns its path.
//
// api_keys.shodan is chosen because registerSecrets (cmd/reconftw/main.go)
// already enumerates it, so the value is unambiguously operator-supplied and
// unambiguously a secret by the tree's own definition — not a literal this test
// invented and then declared sensitive.
func writeSecretConfig(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, "reconftw.toml")
	body := "[api_keys]\nshodan = \"" + redactionSecret + "\"\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write secret config: %v", err)
	}
	return p
}

// runWithLeakyTool runs the real binary on a subs scan with a dnstake stub whose
// stderr is exactly the config secret, and returns the combined terminal bytes
// plus the workspace root.
func runWithLeakyTool(t *testing.T) (terminal string, dataDir string) {
	t.Helper()
	out, dataDir := runLeakyScan(t, false)
	return out, dataDir
}

// runLeakyScan is the one reproduction all three sink assertions share.
//
// charDeviceStderr selects the run.log branch. commonAfterBoot routes slog to
// <workdir>/run.log only when ui.IsTTY(os.Stderr) reports true, and IsTTY's test
// is `st.Mode()&os.ModeCharDevice != 0` — which /dev/null satisfies. So handing
// the child a character device for stderr takes the REAL production branch, with
// no pty and no test-only hook; it is the same code path an operator gets at a
// terminal. The cost is that stderr is then discarded, which is why the terminal
// assertions use the pipe form and only the run.log assertion uses this one.
func runLeakyScan(t *testing.T, charDeviceStderr bool) (terminal string, dataDir string) {
	t.Helper()
	bin := buildBinary(t)
	work := t.TempDir()
	dataDir = filepath.Join(work, "ws")
	cfgPath := writeSecretConfig(t, work)

	// The stub echoes the secret to stderr and exits non-zero — the shape of a
	// tool rejecting the credential it was handed.
	pathDir, _ := plantStubTool(t, stubToolSpec{
		name:   "dnstake",
		script: `printf '%s\n' "` + redactionSecret + `" >&2; exit 1`,
	})

	cmd := exec.Command(bin, "subs", "--target", "example.com",
		"-o", dataDir, "--config", cfgPath)
	cmd.Dir = work
	// PATH is the stub dir plus the base system dirs ONLY — deliberately NOT
	// os.Getenv("PATH"). With the developer's real toolchain visible this run
	// took 5m22s and resolved 296k live hostnames against example.com, which is
	// neither hermetic nor a test. Every recon tool except the stub now fails
	// dispatch immediately, and the one invocation under assertion is the one
	// this file planted.
	cmd.Env = hermeticResolverEnv(t, "PATH="+pathDir+":/usr/bin:/bin")

	if charDeviceStderr {
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			t.Fatalf("open %s: %v", os.DevNull, err)
		}
		defer devNull.Close() //nolint:errcheck
		cmd.Stdout, cmd.Stderr = devNull, devNull
		_ = cmd.Run() // a non-zero exit is fine; run.log is the evidence
		return "", dataDir
	}

	out, _ := cmd.CombinedOutput() // a non-zero exit is fine; the bytes are the evidence
	return string(out), dataDir
}

// findRunLog returns the path of the run.log the routed slog handler wrote.
func findRunLog(t *testing.T, workspaceRoot string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(workspaceRoot, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && filepath.Base(p) == "run.log" {
			found = p
		}
		return nil
	})
	if found == "" {
		t.Fatalf("no run.log anywhere under %s — the liveUI branch was not taken, "+
			"so this test asserted nothing about the run.log sink", workspaceRoot)
	}
	return found
}

// TestE2EConfigSecretInToolStderrNeverReachesRunLog is sink 3: <workspace>/run.log,
// the file an operator most often pastes wholesale into a bug report.
//
// It runs the SAME stub tool with the SAME generated literal as the other two
// sink tests, so all three are assertions about one reproduction. If the
// reproduction stops reproducing, all three fail together rather than one going
// quietly green.
func TestE2EConfigSecretInToolStderrNeverReachesRunLog(t *testing.T) {
	_, dataDir := runLeakyScan(t, true)

	p := findRunLog(t, dataDir)
	raw, err := os.ReadFile(p) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	body := string(raw)

	// Reproduction guard first, for the same reason as the terminal test: a
	// run.log that never mentions dnstake proves nothing about redaction.
	if !strings.Contains(body, "takeover_tool_failed") {
		t.Fatalf("run.log at %s carries no dnstake failure line, so nothing "+
			"carried the secret toward this sink.\ncontents:\n%s", p, body)
	}
	if strings.Contains(body, redactionSecret) {
		t.Errorf("config secret api_keys.shodan is in %s verbatim\ncontents:\n%s", p, body)
	}
	if !strings.Contains(body, redactionPlaceholder) {
		t.Errorf("no redaction placeholder in %s — the value was dropped rather "+
			"than redacted\ncontents:\n%s", p, body)
	}
}

// TestE2EConfigSecretInToolStderrNeverReachesTerminal is sink 1: the operator's
// screen, and everything that captures it (CI logs, tmux scrollback, a screen
// recording pasted into an issue).
func TestE2EConfigSecretInToolStderrNeverReachesTerminal(t *testing.T) {
	terminal, _ := runWithLeakyTool(t)

	// Guard on the reproduction itself FIRST. Without this, a run in which the
	// stub was never dispatched — a renamed task, a disabled default, a changed
	// stage list — produces terminal bytes with no secret in them and this test
	// reports PASS having proven nothing. That is the exact false-green shape
	// phase 17 exists to eliminate.
	if !strings.Contains(terminal, "dnstake") {
		t.Fatalf("the reproduction did not reproduce: no dnstake task line in the "+
			"terminal output, so nothing carried the secret toward this sink.\n"+
			"terminal output:\n%s", terminal)
	}

	if strings.Contains(terminal, redactionSecret) {
		t.Errorf("config secret api_keys.shodan reached the terminal verbatim via a "+
			"tool's stderr.\nsecret: %s\nterminal output:\n%s", redactionSecret, terminal)
	}
	if !strings.Contains(terminal, redactionPlaceholder) {
		t.Errorf("no redaction placeholder %q in the terminal output — the reason was "+
			"dropped rather than redacted.\nterminal output:\n%s",
			redactionPlaceholder, terminal)
	}
}

// TestE2EConfigSecretRedactedTaskLineStaysInformative is threat T-17-01-05: a
// redaction that blanks the whole reason trades one defect for another. The
// operator must still be able to tell WHICH task degraded and WHY-ish.
func TestE2EConfigSecretRedactedTaskLineStaysInformative(t *testing.T) {
	terminal, _ := runWithLeakyTool(t)

	line := findTaskLine(terminal, "subdomains.takeover.dnstake")
	if line == "" {
		t.Fatalf("no task line for subdomains.takeover.dnstake in the terminal "+
			"output\n%s", terminal)
	}
	if !strings.Contains(line, "[SKIP") && !strings.Contains(line, "[WARN") &&
		!strings.Contains(line, "[FAIL") {
		t.Errorf("task line carries no badge after redaction: %q", line)
	}
	if !strings.Contains(line, "dnstake") {
		t.Errorf("task line no longer names its tool after redaction: %q", line)
	}
	if strings.Contains(line, redactionSecret) {
		t.Errorf("task line still carries the secret: %q", line)
	}
}

// findTaskLine returns the first output line mentioning name, with the task-name
// truncation StageProgress applies in non-TTY mode taken into account.
func findTaskLine(terminal, name string) string {
	// Non-TTY StageProgress truncates the display name to 26 columns as
	// "<first 23 chars>...", so match on a prefix short enough to survive it.
	probe := name
	if len(probe) > 23 {
		probe = probe[:23]
	}
	for _, ln := range strings.Split(terminal, "\n") {
		if strings.Contains(ln, probe) {
			return ln
		}
	}
	return ""
}

// TestE2EConfigSecretInToolStderrNeverReachesToolLog is sink 2:
// <workspace>/logs/tools.jsonl. The existing recorder guards cover a secret on
// ARGV; this covers a secret that is only ever in the stderr tail, which is a
// second tool-controlled field on the same record.
func TestE2EConfigSecretInToolStderrNeverReachesToolLog(t *testing.T) {
	_, dataDir := runWithLeakyTool(t)

	recs := toolRecords(t, dataDir)

	var sawDnstakeEnd bool
	for _, rec := range recs {
		tail, _ := rec["stderr_tail"].(string)
		if strings.Contains(tail, redactionSecret) {
			blob, _ := json.Marshal(rec)
			t.Errorf("config secret api_keys.shodan is in logs/tools.jsonl "+
				"stderr_tail verbatim\nrecord: %s", blob)
		}
		if rec["outcome"] == "exit_non_zero" && strings.Contains(tail, redactionPlaceholder) {
			sawDnstakeEnd = true
		}
	}
	if !sawDnstakeEnd {
		var blobs []string
		for _, rec := range recs {
			b, _ := json.Marshal(rec)
			blobs = append(blobs, string(b))
		}
		t.Fatalf("the reproduction did not reproduce: no end record carrying a "+
			"redacted stderr tail, so tools.jsonl never saw the leaky bytes.\n"+
			"records:\n%s", strings.Join(blobs, "\n"))
	}
}
