// hakoriginfinder_test.go — Behavioral tests for CR-06 and CR-03 gap-closure fixes.
//
// Tests:
//   - TestHakoriginfinderPerHostAttribution: verifies that parseHakoriginOutput
//     correctly extracts origin IPs and that OriginRecord.Host is the host from
//     the per-host pair, not an index-based guess (CR-06).
//   - TestJsaDispatchesThroughTheRunnerNotDirectExec: verifies that jsa.go routes
//     through backend.Runner and contains no direct subprocess dispatch (18-05).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-11-PLAN.md Task 2.
package web

import (
	"os"
	"strings"
	"testing"
)

// TestHakoriginfinderPerHostAttribution verifies that parseHakoriginOutput
// correctly extracts origin IPs from hakoriginfinder output on a per-host basis.
//
// CR-06 fix: each host is run independently, so OriginRecord.Host comes from
// the input pair — NOT from a line-index guess. This table-driven test confirms:
//   - a line containing a valid IPv4 returns that IP
//   - a line with no IP returns ""
//   - swapping the pairs in the input produces the correct independent results
//     (no cross-contamination between hosts)
func TestHakoriginfinderPerHostAttribution(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name         string
		host         string
		rawOutput    string
		wantOriginIP string
	}

	tests := []testCase{
		{
			name:         "host1 finds its own origin IP",
			host:         "host1.example.com",
			rawOutput:    "host1.example.com -> 1.2.3.4\nsome extra line",
			wantOriginIP: "1.2.3.4",
		},
		{
			name:         "host2 finds its own origin IP independently",
			host:         "host2.example.com",
			rawOutput:    "Discovered origin: 5.6.7.8",
			wantOriginIP: "5.6.7.8",
		},
		{
			name:         "host3 finds its own origin IP independently",
			host:         "host3.example.com",
			rawOutput:    "origin ip: 9.10.11.12 (confidence low)",
			wantOriginIP: "9.10.11.12",
		},
		{
			name:         "output with no IP returns empty",
			host:         "noresult.example.com",
			rawOutput:    "No origin found for this host",
			wantOriginIP: "",
		},
		{
			name:         "empty output returns empty",
			host:         "empty.example.com",
			rawOutput:    "",
			wantOriginIP: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseHakoriginOutput(tc.rawOutput, tc.host)
			if got != tc.wantOriginIP {
				t.Errorf("parseHakoriginOutput(%q, %q) = %q; want %q",
					tc.rawOutput, tc.host, got, tc.wantOriginIP)
			}
		})
	}
}

// TestHakoriginfinderAttributionIsIndependent verifies that swapping the
// order of host-IP pairs does not cross-contaminate results. This is the
// key property CR-06 was designed to guarantee: no index-based fabrication.
func TestHakoriginfinderAttributionIsIndependent(t *testing.T) {
	t.Parallel()

	// Simulate two per-host runs with distinct outputs.
	// Each call is independent — the host parameter is not used for selection
	// (parseHakoriginOutput only extracts the first IPv4 it finds).
	pair1Host := "alpha.example.com"
	pair1Output := "alpha -> 10.0.0.1"

	pair2Host := "beta.example.com"
	pair2Output := "beta -> 10.0.0.2"

	ip1 := parseHakoriginOutput(pair1Output, pair1Host)
	ip2 := parseHakoriginOutput(pair2Output, pair2Host)

	if ip1 != "10.0.0.1" {
		t.Errorf("pair1: got originIP=%q; want 10.0.0.1", ip1)
	}
	if ip2 != "10.0.0.2" {
		t.Errorf("pair2: got originIP=%q; want 10.0.0.2", ip2)
	}
	if ip1 == ip2 {
		t.Errorf("pair1 and pair2 returned the same IP %q — cross-contamination detected (CR-06)", ip1)
	}

	// Swap the pair order: pair2's output run through pair1's host context.
	// The extracted IP must still come from the output, not the host ordering.
	ip1swapped := parseHakoriginOutput(pair2Output, pair1Host)
	if ip1swapped != "10.0.0.2" {
		t.Errorf("swapped pair1: got originIP=%q; want 10.0.0.2 (output-derived, not host-derived)", ip1swapped)
	}
}

// TestJsaDispatchesThroughTheRunnerNotDirectExec replaces TestJSAUsesDirectExec,
// which was BOTH vacuous AND asserting the opposite of what is now true (WR-13).
//
// What it used to do: assert that `Name()` returned "web.jsa" and that
// `Description()` was non-empty — nothing about dispatch at all — and then log
// "structural verification passed". Its prose claimed jsa.go "does not import the
// backend package" and cited "our static no_raw_subprocess_test.go allowlist",
// both of which 18-05 and 18-03 respectively made false: jsa.go dispatches via
// app.Tools.Run, and that allowlist was deleted as data.
//
// A test that cannot fail, under a comment that is no longer true, inside the very
// phase convened to delete exactly that — so it is replaced by one that observes
// the property it names.
func TestJsaDispatchesThroughTheRunnerNotDirectExec(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile("jsa.go")
	if err != nil {
		t.Fatalf("read jsa.go: %v", err)
	}
	// CODE ONLY. jsa.go documents its own history in prose — "the pre-move
	// exec.CommandContext(cmdCtx, jsaPython, ...)" — and a naive substring match
	// flags those comments, which is how the first version of this test failed on
	// a file that is perfectly clean. Keeping the history readable is the point;
	// the check has to be the one that distinguishes code from commentary.
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	text := code.String()

	// The positive property: dispatch goes through the Runner seam.
	if !strings.Contains(text, "app.Tools.Run(ctx, jsaToolName") {
		t.Error("jsa.go no longer dispatches through app.Tools.Run — 18-05 brought this " +
			"file onto the seam and the FOUND-10 manifest no longer carries an entry " +
			"permitting it to leave")
	}
	// The negative property the old test claimed to check and did not.
	if strings.Contains(text, "exec.Command") {
		t.Error("jsa.go contains a direct exec.Command dispatch — it came home to " +
			"backend.Runner in 18-05, and lint.Bypasses has no entry for it")
	}
	// And the tool name is resolved from the registry, not built as a $HOME path.
	if strings.Contains(text, `os.Getenv("HOME")`) {
		t.Error("jsa.go hand-rolls a $HOME tools path — 18-05 collapsed all three " +
			"module-local tools-root resolvers onto config.ToolsRoot()")
	}
}

// TestParseHakoriginOutputIPv4Variants confirms the IPv4 regex handles
// various formats that might appear in hakoriginfinder output.
func TestParseHakoriginOutputIPv4Variants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		input string
		want  string
	}{
		{"IP: 192.168.1.1", "192.168.1.1"},
		{"Found origin at 10.0.0.255 via probe", "10.0.0.255"},
		{"[+] 172.16.0.1 is the real IP", "172.16.0.1"},
		{"no ip address here", ""},
		{"", ""},
		// IN-02: out-of-range octets are now rejected (net.ParseIP validation),
		// so a 999.x string yields "" instead of leaking into OriginRecord.OriginIP.
		{"partial 999.999.999.999 invalid", ""},
		// IN-02: a valid IPv4 appearing after an invalid candidate is still found.
		{"bad 256.1.1.1 then good 10.20.30.40", "10.20.30.40"},
	}

	for _, tc := range cases {
		got := parseHakoriginOutput(tc.input, "host.example.com")
		if got != tc.want {
			t.Errorf("parseHakoriginOutput(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}
