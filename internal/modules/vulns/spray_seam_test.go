// spray_seam_test.go — the proof that vulns/spray.go's brutus dispatch came home
// to backend.Runner (18-04) through ExecOptions.StdinPath, with its argv
// unchanged, its failure policy unchanged, and — the reason this file exists at
// all — WITHOUT the service-fingerprint payload reaching logs/tools.jsonl.
//
// THE CONTROL IS THE PRE-MOVE SHAPE, captured from spray.go at f436d2e:
//
//	f, _ := os.Open(serviceFPPath)
//	cmd := exec.CommandContext(cmdCtx, bin, args...)   // args = --json -o <path> [-u][-p][-k]
//	cmd.Stdin = f
//
// This is the ONLY site in phase 18 whose standard input is an open FILE rather
// than a byte slice, which is exactly what ExecOptions.StdinPath was added for.
//
// XCUT-07 (T-18-04-03), IN TWO PARTS, because re-asserting the guarantee here
// rather than assuming it survived the move is what turned up that half of it
// was never true:
//
//	the service fingerprints cross on standard input, and StdinPath is not in
//	the recorder's scope — TestSprayFingerprintNotRecorded.
//
//	the credentials do NOT all cross as file paths. -k is a keyfile; -u and -p
//	are comma-separated VALUES per `brutus --help`. They are registered with the
//	run Redactor before dispatch so the recorder scrubs them —
//	TestSprayConfiguredCredentialsAreNotRecorded.
package vulns

import (
	"context"
	"encoding/json"
	"io"
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

// sprayBrutusCfg returns a config that reaches the brutus engine: DEEP on (both
// the Spray.DeepOnly gate and brutus's own independent deep gate).
func sprayBrutusCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Vulns.Spray = config.VulnSpray{Enabled: true, Engine: "brutus", DeepOnly: true}
	cfg.Advanced.Deep = true
	return cfg
}

// newSprayBrutusApp wires a Runner whose "brutus" entry points at toolPath (empty
// for the unavailable case) through the REAL LocalBackend, and seeds the gnmap
// and service-fingerprint inputs the task gates on.
func newSprayBrutusApp(t *testing.T, toolPath string) *appctx.AppContext {
	t.Helper()
	workDir := t.TempDir()
	for _, d := range []string{"hosts", "inputs", "logs", "vulns"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: brutusToolName, Path: toolPath})
	reg.Register(&backend.Tool{Name: "nerva", Path: ""})
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(&backend.LocalBackend{}, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    sprayBrutusCfg(),
	}
	writeGnmapFixture(t, app)
	writeServiceFPFixture(t, app)
	return app
}

// TestSprayStdinPathReachesBrutus asserts the service-fingerprint FILE is opened
// by the backend and delivered on brutus's standard input, and that the argv is
// the pre-move one.
func TestSprayStdinPathReachesBrutus(t *testing.T) {
	recDir := t.TempDir()
	script := writeSeamRecorderScript(t, recDir, "")
	app := newSprayBrutusApp(t, script)

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SprayTask.Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %v, want %v", res.Status, task.StatusDone)
	}

	// The argv: --json -o <vulns/brutus.jsonl>. This config has no -u/-p/-k;
	// configured -u/-p values are covered by the redaction tests below.
	got := readSeamArgv(t, recDir)
	want := []string{"--json", "-o", filepath.Join(app.Target.WorkDir, "vulns", "brutus.jsonl")}
	assertArgvExactly(t, "brutus", got, want)

	// The stdin: the service-fingerprint JSONL, byte-for-byte from the file.
	stdin, sErr := os.ReadFile(filepath.Join(recDir, "stdin.txt")) //nolint:gosec // test-owned temp path
	if sErr != nil {
		t.Fatalf("no standard input reached brutus — StdinPath did not open the file: %v", sErr)
	}
	fixture, fErr := os.ReadFile(filepath.Join(app.Target.WorkDir, "hosts", "service_fingerprints.jsonl")) //nolint:gosec // test-owned temp path
	if fErr != nil {
		t.Fatalf("read the seeded fixture: %v", fErr)
	}
	if string(stdin) != string(fixture) {
		t.Fatalf("brutus stdin is not the service-fingerprint file:\n got = %q\nwant = %q", stdin, fixture)
	}
}

// TestSprayFingerprintNotRecorded is the T-18-04-03 canary.
//
// PRESENCE FIRST, THEN ABSENCE. An absence assertion over a file nothing wrote
// passes trivially and proves nothing — which is precisely how a leak stays
// hidden. So: assert a start record naming brutus EXISTS, and only then that the
// service-fingerprint content is nowhere in the record.
func TestSprayFingerprintNotRecorded(t *testing.T) {
	recDir := t.TempDir()
	script := writeSeamRecorderScript(t, recDir, "")
	app := newSprayBrutusApp(t, script)

	// A canary inside the stdin payload: if any byte of the fingerprint file
	// reaches the record, this string comes with it.
	fpPath := filepath.Join(app.Target.WorkDir, "hosts", "service_fingerprints.jsonl")
	const canary = "CANARY-18-04-FINGERPRINT-DO-NOT-RECORD"
	if err := os.WriteFile(fpPath,
		[]byte(`{"host":"1.2.3.4","port":22,"service":"ssh","product":"`+canary+`"}`+"\n"), 0o600); err != nil {
		t.Fatalf("write canary fingerprint: %v", err)
	}

	logPath := filepath.Join(app.Target.WorkDir, "logs", "tools.jsonl")
	app.Tools.Recorder = backend.NewToolRecorder(logPath, nil)

	if _, err := (&SprayTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("SprayTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — brutus was NOT recorded, so this test's "+
			"absence assertion would have been worthless: %v", err)
	}

	// 1. PRESENCE.
	var sawStart bool
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec struct {
			Phase string `json:"phase"`
			Tool  string `json:"tool"`
		}
		if uErr := json.Unmarshal([]byte(line), &rec); uErr != nil {
			t.Fatalf("tools.jsonl line is not JSON: %v (%s)", uErr, line)
		}
		if rec.Tool == brutusToolName && rec.Phase == "start" {
			sawStart = true
		}
	}
	if !sawStart {
		t.Fatalf("no start record naming %q — brutus did not cross the recorder seam:\n%s",
			brutusToolName, data)
	}

	// 2. Only now, ABSENCE.
	if strings.Contains(string(data), canary) {
		t.Errorf("SERVICE-FINGERPRINT CONTENT LEAKED INTO logs/tools.jsonl (T-18-04-03) — the "+
			"canary %q is in the invocation record:\n%s", canary, data)
	}
	// And the fingerprint path itself must not be on argv either: it crosses as
	// StdinPath, which the recorder never sees.
	if strings.Contains(string(data), "service_fingerprints.jsonl") {
		t.Errorf("the service-fingerprint PATH is on the recorded argv — it must cross as "+
			"StdinPath only:\n%s", data)
	}
}

// TestSprayBrutusUnavailableStatusUnchanged pins the FAILURE POLICY across the
// move (T-18-04-04). Before 18-04 an absent brutus failed exec.LookPath, which
// brutusRunner turned into errBrutusNotInstalled and the task turned into
// StatusSkipped WITHOUT clearing a previous run's staging (brutusRan == false).
// After the move the same must hold, driven by the Runner's dispatch-failure
// label instead of exec.LookPath.
func TestSprayBrutusUnavailableStatusUnchanged(t *testing.T) {
	app := newSprayBrutusApp(t, "")

	// A previous run's staged findings that must survive a run in which brutus
	// never started (F3 did-not-run).
	staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.spray.jsonl")
	if err := os.WriteFile(staging, []byte(`{"vuln_class":"spray"}`+"\n"), 0o600); err != nil {
		t.Fatalf("seed staging: %v", err)
	}

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned an error for an unavailable brutus: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status on an unavailable brutus = %v, want %v — spraying is best_effort (D-V7) "+
			"and must never abort the vulns pipeline", res.Status, task.StatusDone)
	}
	data, readErr := os.ReadFile(staging) //nolint:gosec // test-owned temp path
	if readErr != nil || !strings.Contains(string(data), "spray") {
		t.Fatalf("a run in which brutus never started cleared the previous run's staging "+
			"(F3 did-not-run must preserve): err=%v content=%q", readErr, data)
	}
}

// TestSprayConfiguredCredentialsAreNotRecorded is the second half of T-18-04-03,
// and it exists because the claim it checks WAS FALSE when 18-04 started.
//
// spray.go asserted that "credential wordlists cross as FILE PATHS on -u/-p/-k,
// never as raw values". `brutus --help` on the installed build says otherwise:
//
//	-u <usernames>   Comma-separated usernames (default: "root,admin")
//	-p <passwords>   Comma-separated passwords
//	-k <keyfile>     SSH private key file
//
// so -u and -p carry VALUES. Harmless while spray.go dispatched brutus itself;
// not harmless once the dispatch goes through backend.Runner, whose recorder
// writes argv into logs/tools.jsonl. The fix registers each configured value
// with the run Redactor before dispatch, THROUGH app.Secrets — the seam Boot
// points at the same instance the recorder holds — so the values are scrubbed out
// of the record even on a non-TTY run, where app.Log's redactor is a different
// object entirely (CR-01).
//
// PRESENCE FIRST, THEN ABSENCE, for the same reason as above.
func TestSprayConfiguredCredentialsAreNotRecorded(t *testing.T) {
	recDir := t.TempDir()
	script := writeSeamRecorderScript(t, recDir, "")
	app := newSprayBrutusApp(t, script)

	const userCanary = "CANARY-USER-18-04-DO-NOT-RECORD"
	const passCanary = "CANARY-PASS-18-04-DO-NOT-RECORD"
	app.Cfg.Advanced.Tools.Brutus.Usernames = userCanary
	app.Cfg.Advanced.Tools.Brutus.Passwords = passCanary + ",second-" + passCanary

	// TWO DIFFERENT REDACTORS — because that is what appctx.Boot actually builds,
	// and the previous version of this test got it wrong.
	//
	// It used to hand ONE *log.Redactor to both sinks under a comment claiming that
	// was "exactly as appctx.Boot wires them". It is not. Boot gives the
	// ToolRecorder BootOptions.Redactor (the per-run redactor from newRunRedactor),
	// while app.Log carries the CLI logger's own instance — loglevel.go documents
	// that one as never learning runtime-registered secrets. The two converge only
	// inside `if liveUI {`, i.e. an interactive TTY.
	//
	// Sharing one pointer made the test pass no matter which sink spray.go
	// registered with, so it could not distinguish the fix from the bug. With the
	// instances separated, a registration that goes only to the LOGGER leaves the
	// canary in tools.jsonl and this test fails — which is what it is for.
	recorderRedactor := &log.Redactor{}
	loggerRedactor := &log.Redactor{}
	app.Log = slog.New(log.NewRedactingHandler(
		slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}), loggerRedactor))
	logPath := filepath.Join(app.Target.WorkDir, "logs", "tools.jsonl")
	app.Tools.Recorder = backend.NewToolRecorder(logPath, recorderRedactor)
	// The SecretRegistrar seam Boot points at the recorder's redactor (boot.go
	// <- opt.SecretRegistrar <- runSecrets). *log.Redactor satisfies it structurally.
	app.Secrets = recorderRedactor

	if _, err := (&SprayTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("SprayTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	// The process really did receive the credentials on argv — brutus requires
	// it, and a test that passed because the flags were never built would prove
	// nothing about redaction.
	got := readSeamArgv(t, recDir)
	if !sprayArgvHas(got, userCanary) {
		t.Fatalf("brutus never received -u on argv, so this test asserts nothing: %v", got)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — brutus was NOT recorded, so the absence "+
			"assertion below would be worthless: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"brutus"`) {
		t.Fatalf("no brutus record in tools.jsonl:\n%s", data)
	}

	for _, canary := range []string{userCanary, passCanary} {
		if strings.Contains(string(data), canary) {
			t.Errorf("CONFIGURED BRUTUS CREDENTIAL LEAKED INTO logs/tools.jsonl (T-18-04-03) — "+
				"%q is in the invocation record:\n%s", canary, data)
		}
	}
}

// TestSprayShortConfiguredCredentialIsOmitted pins the redactor's documented
// four-byte floor. Register silently ignores values of length <= 4, so treating
// a non-nil registrar as proof of protection would put the live value on argv
// and therefore into logs/tools.jsonl in clear text.
func TestSprayShortConfiguredCredentialIsOmitted(t *testing.T) {
	recDir := t.TempDir()
	script := writeSeamRecorderScript(t, recDir, "")
	app := newSprayBrutusApp(t, script)
	app.Cfg.Advanced.Tools.Brutus.Passwords = "pass"

	recorderRedactor := &log.Redactor{}
	logPath := filepath.Join(app.Target.WorkDir, "logs", "tools.jsonl")
	app.Tools.Recorder = backend.NewToolRecorder(logPath, recorderRedactor)
	app.Secrets = recorderRedactor

	if _, err := (&SprayTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("SprayTask.Run: %v", err)
	}
	if err := app.Tools.Recorder.Close(); err != nil {
		t.Fatalf("close recorder: %v", err)
	}

	argv := readSeamArgv(t, recDir)
	if sprayArgvHas(argv, "pass") {
		t.Fatalf("four-byte password reached brutus argv even though log.Redactor refuses to register it: %v", argv)
	}

	data, err := os.ReadFile(logPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("logs/tools.jsonl does not exist — brutus was not recorded: %v", err)
	}
	if !strings.Contains(string(data), `"tool":"brutus"`) {
		t.Fatalf("no brutus record in tools.jsonl:\n%s", data)
	}
	if strings.Contains(string(data), `"pass"`) {
		t.Fatalf("FOUR-BYTE BRUTUS PASSWORD LEAKED INTO logs/tools.jsonl:\n%s", data)
	}
}

func TestSprayCredentialListWithShortElementIsOmitted(t *testing.T) {
	recDir := t.TempDir()
	script := writeSeamRecorderScript(t, recDir, "")
	app := newSprayBrutusApp(t, script)
	app.Cfg.Advanced.Tools.Brutus.Passwords = "pass,much-longer-secret"

	recorderRedactor := &log.Redactor{}
	app.Secrets = recorderRedactor
	app.Tools.Recorder = backend.NewToolRecorder(
		filepath.Join(app.Target.WorkDir, "logs", "tools.jsonl"), recorderRedactor)

	if _, err := (&SprayTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("SprayTask.Run: %v", err)
	}

	argv := readSeamArgv(t, recDir)
	if sprayArgvHas(argv, "pass") {
		t.Fatalf("credential list containing a four-byte password reached brutus argv; the child could echo that element alone into stderr: %v", argv)
	}
}

// sprayArgvHas reports whether any argv element contains want.
func sprayArgvHas(argv []string, want string) bool {
	for _, a := range argv {
		if strings.Contains(a, want) {
			return true
		}
	}
	return false
}
