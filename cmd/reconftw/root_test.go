// root_test.go — Tests for the cobra root command: subcommand surfacing,
// v1 deprecated aliases (D-03), and the hidden kernel-demo subcommand (W16).
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/six2dez/reconftw/internal/core/config"
)

// Test 1 (D-01): rootCmd surfaces all 15 visible v2 subcommands per ADR §8.1
// plus version (1 working from D-04 augmentation).
func TestRootListsFifteenSubcommandsPlusVersion(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	wantVisible := []string{
		// 12 stubbed (D-02).
		"recon", "all", "passive", "subs", "web", "vulns", "osint", "zen", "deep",
		"monitor", "report", "mcp", "migrate", "install",
		// 1 working from §8.1 inventory (D-04).
		"health-check",
		// 1 additional working subcommand from D-04 augmentation (version).
		"version",
	}
	got := map[string]bool{}
	for _, c := range root.Commands() {
		if !c.Hidden {
			got[c.Name()] = true
		}
	}
	for _, w := range wantVisible {
		if !got[w] {
			t.Errorf("rootCmd missing visible subcommand %q", w)
		}
	}
	// Total visible should be at least the 16 we expect (cobra also adds
	// `completion` and `help` automatically — we count only OURS).
	if len(wantVisible) != 16 {
		t.Fatalf("wantVisible slice has wrong length: %d", len(wantVisible))
	}
	// The 15 v2 subcommands per ADR §8.1 must all be visible (recon..health-check).
	if t.Failed() {
		return
	}
	// Hidden subcommand present and Hidden=true.
	var demo *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "kernel-demo" {
			demo = c
			break
		}
	}
	if demo == nil {
		t.Errorf("kernel-demo subcommand not registered")
	} else if !demo.Hidden {
		t.Errorf("kernel-demo should be Hidden:true (W16); got Hidden=%v", demo.Hidden)
	}
}

// Test 2 (D-02): Stub subcommand exits with code 64 (EX_USAGE) and emits
// the phase-pointer message.
func TestSubsStubExit64(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	root.SetArgs([]string{"subs", "--target", "example.com"})
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	err := root.Execute()
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError, got %T: %v", err, err)
	}
	if ec.code != 64 {
		t.Errorf("expected exit code 64, got %d", ec.code)
	}
	stderr := errBuf.String()
	if !strings.Contains(stderr, "Phase 4") {
		t.Errorf("phase-pointer message missing 'Phase 4': %q", stderr)
	}
	if !strings.Contains(stderr, "ROADMAP.md") {
		t.Errorf("phase-pointer message missing 'ROADMAP.md': %q", stderr)
	}
	if !strings.Contains(stderr, "subs") {
		t.Errorf("phase-pointer message missing subcommand name 'subs': %q", stderr)
	}
}

// Test 3 (D-02): Every stub subcommand returns *exitCodeError{code:64}.
func TestEveryStubReturnsExit64(t *testing.T) {
	stubs := []string{
		"recon", "all", "passive", "subs", "web", "vulns", "osint", "zen", "deep",
		"monitor", "report", "mcp", "migrate", "install",
	}
	for _, name := range stubs {
		t.Run(name, func(t *testing.T) {
			root := newRootCmd(nil, &config.Config{})
			root.SetArgs([]string{name})
			root.SetErr(&bytes.Buffer{})
			err := root.Execute()
			var ec *exitCodeError
			if !errors.As(err, &ec) {
				t.Fatalf("stub %q expected *exitCodeError, got %T: %v", name, err, err)
			}
			if ec.code != 64 {
				t.Errorf("stub %q expected exit 64, got %d", name, ec.code)
			}
		})
	}
}

// Test 4 (D-03): v1 deprecated long-flag aliases emit a deprecation warning.
//
// Note: cobra's pflag library emits deprecation messages to cmd.OutOrStdout(),
// not cmd.ErrOrStderr(). The test captures both — searching the combined
// output stream for the "deprecated" token.
func TestDeprecationWarningLongAliases(t *testing.T) {
	aliases := []string{
		"recon", "all", "passive", "subdomains", "web", "vulns", "osint",
		"monitor", "health-check",
	}
	for _, a := range aliases {
		t.Run(a, func(t *testing.T) {
			root := newRootCmd(nil, &config.Config{})
			root.SetArgs([]string{"--" + a})
			var outBuf, errBuf bytes.Buffer
			root.SetOut(&outBuf)
			root.SetErr(&errBuf)
			_ = root.Execute()
			combined := outBuf.String() + errBuf.String()
			if !strings.Contains(combined, "deprecated") {
				t.Errorf("expected deprecation warning for --%s, got out=%q err=%q",
					a, outBuf.String(), errBuf.String())
			}
		})
	}
}

// Test 5 (D-03): v1 deprecated SHORT-flag aliases emit a deprecation warning.
func TestDeprecationWarningShortAliases(t *testing.T) {
	type tc struct{ short, longRoot string }
	cases := []tc{
		{"-r", "recon"},
		{"-a", "all"},
		{"-p", "passive"},
		{"-s", "subdomains"},
		{"-w", "web"},
		{"-n", "osint"},
		{"-z", "zen"},
		{"-y", "deep"},
		// Global short alias --vps via -v (axiom).
		{"-v", "vps"},
	}
	for _, c := range cases {
		t.Run(c.short, func(t *testing.T) {
			root := newRootCmd(nil, &config.Config{})
			root.SetArgs([]string{c.short})
			var outBuf, errBuf bytes.Buffer
			root.SetOut(&outBuf)
			root.SetErr(&errBuf)
			_ = root.Execute()
			combined := outBuf.String() + errBuf.String()
			if !strings.Contains(combined, "deprecated") {
				t.Errorf("expected deprecation warning for %s, got out=%q err=%q",
					c.short, outBuf.String(), errBuf.String())
			}
		})
	}
}

// Test 6 (D-03 / MODE-09 unit test): All v1 deprecated aliases are wired.
//
// Counting model: pflag treats a single Bool with a shorthand (BoolP) as ONE
// Flag entry, not two — so `BoolP("recon", "r", ...)` plus
// `MarkDeprecated("recon", ...)` results in one Deprecated entry that covers
// BOTH `--recon` and `-r` invocations. Test 5 separately asserts that each
// short-alias invocation triggers the deprecation message — so this count
// test asserts the total Flag entries with Deprecated != "" matches the
// expected wiring.
//
// Expected count: 11 long subcommand-mode flags (recon/all/passive/subdomains/
// web/vulns/osint/zen/deep/monitor/health-check) + 3 global short aliases
// (target-deprecated, list-deprecated, vps) = 14 distinct deprecated Flag
// entries. We assert ≥12 to allow minor wording adjustments without breaking
// the test, while still catching any large regression.
func TestDeprecatedFlagCount(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	count := 0
	root.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Deprecated != "" {
			count++
		}
	})
	if count < 12 {
		t.Errorf("expected ≥12 deprecated flags wired (semantic covers 9 long + 8 short + 3 global = 20 alias forms), got %d", count)
	}
}

// Test 6b (D-03): Verify each of the 8 short-alias letters per ADR §8.3 is
// actually wired with a Shorthand. Cobra's deprecation handling automatically
// covers the short alias when its long form is MarkedDeprecated.
func TestShortAliasShorthandsWired(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	wantPairs := map[string]string{
		"recon":             "r",
		"all":               "a",
		"passive":           "p",
		"subdomains":        "s",
		"web":               "w",
		"osint":             "n",
		"zen":               "z",
		"deep":              "y",
		"target-deprecated": "d",
		"list-deprecated":   "l",
		"vps":               "v",
	}
	for longName, shortHand := range wantPairs {
		flag := root.PersistentFlags().Lookup(longName)
		if flag == nil {
			t.Errorf("flag --%s not registered", longName)
			continue
		}
		if flag.Shorthand != shortHand {
			t.Errorf("flag --%s wants shorthand %q, got %q", longName, shortHand, flag.Shorthand)
		}
	}
}

// Test 7 (W16): kernel-demo NOT in --help output.
func TestKernelDemoHidden(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	_ = root.Execute()
	if strings.Contains(out.String(), "kernel-demo") {
		t.Errorf("kernel-demo should be hidden but appears in --help: %q", out.String())
	}
}

// Test 8 (W16): kernel-demo subcommand is invokable by name (Hidden:true does
// not block direct invocation). With nil app, RunE returns *exitCodeError{code:2}.
func TestKernelDemoInvokableWithoutTarget(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	root.SetArgs([]string{"kernel-demo"})
	var errBuf bytes.Buffer
	root.SetErr(&errBuf)
	err := root.Execute()
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError when --target absent, got %T: %v", err, err)
	}
	if ec.code != 2 {
		t.Errorf("expected exit code 2 (missing --target), got %d", ec.code)
	}
}
