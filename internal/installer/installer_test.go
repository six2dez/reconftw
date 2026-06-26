package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// --- test helpers: save/restore the package-level seams ---

func swapLookPath(t *testing.T, fn func(string) (string, error)) {
	t.Helper()
	orig := lookPath
	lookPath = fn
	t.Cleanup(func() { lookPath = orig })
}

func swapRunOutput(t *testing.T, fn func(context.Context, string, ...string) (string, error)) {
	t.Helper()
	orig := runOutput
	runOutput = fn
	t.Cleanup(func() { runOutput = orig })
}

func swapRunCmd(t *testing.T, fn func(context.Context, string, []string, []string) error) {
	t.Helper()
	orig := runCmd
	runCmd = fn
	t.Cleanup(func() { runCmd = orig })
}

// --- BLOCKER 1: bootstrapper hash pins must be non-empty 64-char hex ---

func TestBootstrapHashPinsNonEmpty(t *testing.T) {
	pins := map[string]string{
		"goInstallerSHA256": goInstallerSHA256,
		"uvInstallerSHA256": uvInstallerSHA256,
		"rustupInitSHA256":  rustupInitSHA256,
	}
	for name, pin := range pins {
		if len(pin) != 64 {
			t.Errorf("%s: length %d, want 64 (a SHA-256 hex digest)", name, len(pin))
		}
		if _, err := hex.DecodeString(pin); err != nil {
			t.Errorf("%s: not valid hex: %v", name, err)
		}
	}
}

func TestVerifyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob")
	content := []byte("reconftw")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])

	// correct hash → nil
	if err := verifyFile(context.Background(), path, good, "https://example.com/f"); err != nil {
		t.Errorf("matching hash returned error: %v", err)
	}
	// empty pin → nil (Pattern 7 — go.sum/PyPI integrity)
	if err := verifyFile(context.Background(), path, "", "https://example.com/f"); err != nil {
		t.Errorf("empty pin returned error: %v", err)
	}
	// wrong hash → ChecksumMismatch + errors.Is(ErrChecksum)
	wrong := "1111111111111111111111111111111111111111111111111111111111111111"
	err := verifyFile(context.Background(), path, wrong, "https://example.com/f")
	if err == nil {
		t.Fatal("wrong hash returned nil")
	}
	var cm *coreerrors.ChecksumMismatch
	if !stderrors.As(err, &cm) {
		t.Fatalf("error is not *ChecksumMismatch: %T", err)
	}
	if !stderrors.Is(err, coreerrors.ErrChecksum) {
		t.Error("errors.Is(err, ErrChecksum) == false")
	}
	if cm.Expected != wrong || cm.Got != good {
		t.Errorf("ChecksumMismatch fields = {Expected:%s Got:%s}, want {Expected:%s Got:%s}", cm.Expected, cm.Got, wrong, good)
	}
}

func TestRetry(t *testing.T) {
	// succeeds on the 3rd of 3 attempts → nil
	calls := 0
	err := retry(context.Background(), 3, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return stderrors.New("transient")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Errorf("retry success: err=%v calls=%d, want nil/3", err, calls)
	}
	// always fails → last error returned after `attempts` tries
	calls = 0
	want := stderrors.New("permanent")
	err = retry(context.Background(), 2, time.Millisecond, func() error { calls++; return want })
	if !stderrors.Is(err, want) || calls != 2 {
		t.Errorf("retry exhausted: err=%v calls=%d, want permanent/2", err, calls)
	}
}

func TestDetectPkgMgrFor(t *testing.T) {
	// darwin → brew regardless of PATH
	if got := detectPkgMgrFor("darwin"); got != PkgMgrBrew {
		t.Errorf("darwin → %v, want brew", got)
	}
	// non-linux/non-darwin → unknown
	if got := detectPkgMgrFor("windows"); got != PkgMgrUnknown {
		t.Errorf("windows → %v, want unknown", got)
	}
	// linux + apt-get on PATH → apt
	swapLookPath(t, func(bin string) (string, error) {
		if bin == "apt-get" {
			return "/usr/bin/apt-get", nil
		}
		return "", stderrors.New("not found")
	})
	if got := detectPkgMgrFor("linux"); got != PkgMgrApt {
		t.Errorf("linux+apt → %v, want apt", got)
	}
	// linux + nothing on PATH → unknown
	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("not found") })
	if got := detectPkgMgrFor("linux"); got != PkgMgrUnknown {
		t.Errorf("linux+none → %v, want unknown", got)
	}
}

func TestParseGoVersionM(t *testing.T) {
	out := "/home/u/go/bin/subfinder: go1.21.5\n" +
		"\tpath\tgithub.com/projectdiscovery/subfinder/v2/cmd/subfinder\n" +
		"\tmod\tgithub.com/projectdiscovery/subfinder/v2\tv2.14.0\th1:abc=\n"
	v, err := parseGoVersionM(out)
	if err != nil || v != "v2.14.0" {
		t.Errorf("parseGoVersionM = (%q,%v), want (v2.14.0,nil)", v, err)
	}
	if _, err := parseGoVersionM("no mod line here"); err == nil {
		t.Error("parseGoVersionM with no mod line returned nil error")
	}
}

func TestParseUVToolList(t *testing.T) {
	out := "arjun v2.2.7\n- arjun\nwafw00f v0.43\n- wafw00f\n"
	got := parseUVToolList(out)
	if got["arjun"] != "2.2.7" || got["wafw00f"] != "0.43" {
		t.Errorf("parseUVToolList = %v, want arjun=2.2.7 wafw00f=0.43", got)
	}
}

func TestProbePkgMgrVersion(t *testing.T) {
	swapRunOutput(t, func(_ context.Context, name string, args ...string) (string, error) {
		if name == "dpkg-query" {
			return "1.2.3\n", nil
		}
		return "", stderrors.New("unexpected")
	})
	v, err := probePkgMgrVersion(context.Background(), PkgMgrApt, "nmap")
	if err != nil || v != "1.2.3" {
		t.Errorf("probePkgMgrVersion(apt) = (%q,%v), want (1.2.3,nil)", v, err)
	}
	if _, err := probePkgMgrVersion(context.Background(), PkgMgrUnknown, "nmap"); err == nil {
		t.Error("probePkgMgrVersion(unknown) returned nil error")
	}
}

func TestBuildUVSpec(t *testing.T) {
	cases := []struct{ pkg, ver, want string }{
		{"wafw00f", "0.43", "wafw00f==0.43"},
		{"wafw00f", "v0.43", "wafw00f==0.43"},
		{"wafw00f", "latest", "wafw00f"},
		{"git+https://github.com/x/y", "v1.0", "git+https://github.com/x/y@v1.0"},
		{"git+https://github.com/x/y", "latest", "git+https://github.com/x/y"},
	}
	for _, c := range cases {
		if got := buildUVSpec(c.pkg, c.ver); got != c.want {
			t.Errorf("buildUVSpec(%q,%q) = %q, want %q", c.pkg, c.ver, got, c.want)
		}
	}
}

func TestGoToolInstallerIdempotent(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/go/bin/subfinder", nil })
	modOut := "/go/bin/subfinder: go1.21\n\tmod\tgithub.com/projectdiscovery/subfinder/v2\t%s\t\n"
	tool := &backend.Tool{Name: "subfinder", Kind: "go", GoModule: "github.com/projectdiscovery/subfinder/v2/cmd/subfinder", Version: "v2.14.0"}

	// installed == pinned → no `go install`
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return sprintfMod(modOut, "v2.14.0"), nil
	})
	installed := false
	swapRunCmd(t, func(context.Context, string, []string, []string) error { installed = true; return nil })
	if err := NewGoToolInstaller().Install(context.Background(), tool); err != nil {
		t.Fatalf("Install (match) err: %v", err)
	}
	if installed {
		t.Error("Install ran `go install` despite version match (idempotency broken)")
	}

	// installed != pinned → runs `go install <module>@<version>`
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return sprintfMod(modOut, "v2.0.0"), nil
	})
	var gotArgs []string
	swapRunCmd(t, func(_ context.Context, name string, args, _ []string) error {
		if name == "go" {
			gotArgs = args
		}
		return nil
	})
	if err := NewGoToolInstaller().Install(context.Background(), tool); err != nil {
		t.Fatalf("Install (mismatch) err: %v", err)
	}
	want := "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.14.0"
	if len(gotArgs) != 2 || gotArgs[0] != "install" || gotArgs[1] != want {
		t.Errorf("go install args = %v, want [install %s]", gotArgs, want)
	}
}

func TestSystemToolInstallerSkipWhenPresent(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "/usr/bin/nmap", nil })
	ran := false
	swapRunCmd(t, func(context.Context, string, []string, []string) error { ran = true; return nil })
	err := NewSystemToolInstaller(PkgMgrApt).Install(context.Background(), &backend.Tool{Name: "nmap", Kind: "system"})
	if err != nil || ran {
		t.Errorf("SystemToolInstaller installed a present tool: err=%v ran=%v", err, ran)
	}
}

func TestInstallerRunUnsupportedPlatform(t *testing.T) {
	orig := detectPkgMgrFn
	detectPkgMgrFn = func() PkgMgr { return PkgMgrUnknown }
	t.Cleanup(func() { detectPkgMgrFn = orig })

	err := New(Options{Registry: backend.NewToolRegistry()}).Run(context.Background())
	if err == nil {
		t.Fatal("Run on unsupported platform returned nil")
	}
	if !stderrors.Is(err, coreerrors.ErrConfig) {
		t.Errorf("Run error is not ErrConfig: %v", err)
	}
}

func TestInstallerHealthCheck(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "subfinder", Kind: "go", Critical: true})
	reg.Register(&backend.Tool{Name: "crt", Kind: "go", Critical: false})
	inst := New(Options{Registry: reg})

	// all present → nil
	swapLookPath(t, func(string) (string, error) { return "/bin/x", nil })
	if err := inst.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck all-present returned error: %v", err)
	}

	// only non-critical missing → still nil
	swapLookPath(t, func(name string) (string, error) {
		if name == "crt" {
			return "", stderrors.New("absent")
		}
		return "/bin/x", nil
	})
	if err := inst.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck non-critical-missing returned error: %v", err)
	}

	// critical missing → non-nil
	swapLookPath(t, func(name string) (string, error) {
		if name == "subfinder" {
			return "", stderrors.New("absent")
		}
		return "/bin/x", nil
	})
	if err := inst.HealthCheck(context.Background()); err == nil {
		t.Error("HealthCheck with missing critical tool returned nil")
	}
}

// sprintfMod fills a single %s in a mod-line template (avoids importing fmt
// just for the test table).
func sprintfMod(tmpl, v string) string {
	for i := 0; i+1 < len(tmpl); i++ {
		if tmpl[i] == '%' && tmpl[i+1] == 's' {
			return tmpl[:i] + v + tmpl[i+2:]
		}
	}
	return tmpl
}
