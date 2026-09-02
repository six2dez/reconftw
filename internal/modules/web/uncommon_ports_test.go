// uncommon_ports_test.go — drift guard and behaviour guard for the uncommon-port
// sweep that v2 declared and never implemented.

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestUncommonPortsMatchV1Config is the drift guard. uncommonWebPorts duplicates
// config/uncommon_ports_web.txt because //go:embed cannot reach outside the
// package directory. Duplication is only safe while something checks it, so this
// reads v1's file and compares. Without it the two silently diverge and v2 starts
// probing a different port set than the baseline it is measured against.
func TestUncommonPortsMatchV1Config(t *testing.T) {
	// internal/modules/web -> repo root is three levels up.
	p := filepath.Join("..", "..", "..", "config", "uncommon_ports_web.txt")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v — v1's port list is the source of truth for uncommonWebPorts", p, err)
	}
	want := strings.TrimSpace(strings.ReplaceAll(string(raw), "\n", ""))
	if uncommonWebPorts != want {
		t.Errorf("uncommonWebPorts has drifted from config/uncommon_ports_web.txt\n got: %s\nwant: %s",
			uncommonWebPorts, want)
	}
}

// TestProbePortsIncludesUncommonByDefault pins the actual regression: the ports
// that carried the last live-host parity gap. a.ns/b.ns.example.com serve HTTP
// on 2096 and 8443; v2 probed 80,443 only and lost both.
func TestProbePortsIncludesUncommonByDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.Web.Probe.Ports = "80,443"
	cfg.Web.Probe.UncommonEnabled = true

	got := probePorts(cfg)
	for _, want := range []string{"80", "443", "2096", "8443"} {
		if !hasPort(got, want) {
			t.Errorf("probe port set is missing %s — got %q", want, got)
		}
	}
}

// TestProbePortsRespectsDisable: the flag has to actually mean something, in both
// directions. A config-only knob is what this whole file exists to correct.
func TestProbePortsRespectsDisable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Web.Probe.Ports = "80,443"
	cfg.Web.Probe.UncommonEnabled = false

	got := probePorts(cfg)
	if got != "80,443" {
		t.Errorf("uncommon_enabled=false must probe the configured ports only; got %q", got)
	}
	if hasPort(got, "2096") {
		t.Error("uncommon ports leaked in with uncommon_enabled=false")
	}
}

// TestProbePortsDeduplicates: an operator who already lists 8443 must not get it
// twice — httpx would probe it twice and the run would pay for it.
func TestProbePortsDeduplicates(t *testing.T) {
	cfg := &config.Config{}
	cfg.Web.Probe.Ports = "80,443,8443"
	cfg.Web.Probe.UncommonEnabled = true

	got := probePorts(cfg)
	if n := countPort(got, "8443"); n != 1 {
		t.Errorf("port 8443 appears %d times in %q, want exactly 1", n, got)
	}
}

func hasPort(list, port string) bool {
	for _, p := range strings.Split(list, ",") {
		if strings.TrimSpace(p) == port {
			return true
		}
	}
	return false
}

func countPort(list, port string) int {
	n := 0
	for _, p := range strings.Split(list, ",") {
		if strings.TrimSpace(p) == port {
			n++
		}
	}
	return n
}
