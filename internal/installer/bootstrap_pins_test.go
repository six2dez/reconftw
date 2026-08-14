// bootstrap_pins_test.go — guards on the toolchain pins.
//
// Two failure modes, both silent:
//
//   - goVersion drifting from go.mod, so a clean-machine bootstrap installs a
//     different toolchain than CI and Docker build with. It had already
//     drifted: go.mod and the Dockerfile moved to a patched release while the
//     installer stayed on 1.25.0.
//   - a placeholder checksum being mistaken for a real one. The pins are
//     deliberate all-zero sentinels, which is safe ONLY because nothing can
//     hash to zeros. TestZeroPinNeverValidates proves that fail-closed
//     property instead of assuming it.
package installer

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var goDirectiveRe = regexp.MustCompile(`(?m)^go\s+(\S+)`)

func TestGoVersionMatchesGoMod(t *testing.T) {
	t.Parallel()
	// Walk up to the module root.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var body []byte
	for i := 0; i < 6; i++ {
		if b, rerr := os.ReadFile(filepath.Join(dir, "go.mod")); rerr == nil {
			body = b
			break
		}
		dir = filepath.Dir(dir)
	}
	if body == nil {
		t.Skip("go.mod not found from the test working directory")
	}
	m := goDirectiveRe.FindSubmatch(body)
	if m == nil {
		t.Fatal("no `go` directive in go.mod")
	}
	want := string(m[1])
	if goVersion != want {
		t.Errorf("goVersion = %q but go.mod requires %q — a clean-machine "+
			"bootstrap would install a different toolchain than CI and Docker use",
			goVersion, want)
	}
}

func TestZeroPinNeverValidates(t *testing.T) {
	t.Parallel()
	const zero = "0000000000000000000000000000000000000000000000000000000000000000"

	path := filepath.Join(t.TempDir(), "blob")
	if err := os.WriteFile(path, []byte("any content at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(context.Background(), path, zero, "https://example/test"); err == nil {
		t.Fatal("the all-zero placeholder pin validated a real file — the " +
			"bootstrap would run an UNVERIFIED installer as root")
	}

	// And the empty file, the one input someone might expect to hash to zeros.
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(context.Background(), empty, zero, "https://example/test"); err == nil {
		t.Fatal("the all-zero pin validated an empty file")
	}
}

// TestPlaceholderPinsAreDeclared makes the outstanding work visible: it lists
// which bootstrap pins are still placeholders. It does not fail — a hard
// failure would keep CI permanently red for a known, documented gap — but the
// names are printed on every run so the gap cannot be forgotten, and the moment
// a pin becomes real it disappears from the list.
func TestPlaceholderPinsAreDeclared(t *testing.T) {
	t.Parallel()
	pins := map[string]string{
		"goInstallerSHA256": goInstallerSHA256,
		"uvInstallerSHA256": uvInstallerSHA256,
		"rustupInitSHA256":  rustupInitSHA256,
	}
	var placeholders []string
	for name, pin := range pins {
		if strings.Trim(pin, "0") == "" {
			placeholders = append(placeholders, name)
		}
	}
	if len(placeholders) > 0 {
		t.Logf("OUTSTANDING: %d bootstrap pin(s) are still all-zero placeholders "+
			"(%s) — clean-machine bootstrap of those toolchains fails closed by "+
			"design and cannot work until real vendor digests are pinned",
			len(placeholders), strings.Join(placeholders, ", "))
	}
}
