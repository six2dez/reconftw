package main

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestScopeFileFlagsReachSubcommands: --include-file / --exclude-file are
// persistent root flags readable from every scan subcommand, and the v1 -i / -x
// short forms translate to them.
func TestScopeFileFlagsReachSubcommands(t *testing.T) {
	for _, sub := range []string{"recon", "all", "passive", "subs", "web", "vulns", "osint", "zen", "deep", "monitor"} {
		t.Run(sub, func(t *testing.T) {
			root := newRootCmd(nil, &config.Config{})
			args := translateV1Args([]string{sub, "-d", "example.com", "-i", "in.txt", "-x", "out.txt"})
			if joined := strings.Join(args, " "); !strings.Contains(joined, "--include-file in.txt") ||
				!strings.Contains(joined, "--exclude-file out.txt") {
				t.Fatalf("-i/-x not translated: %v", args)
			}
			cmd, rest, err := root.Find(args)
			if err != nil {
				t.Fatalf("Find: %v", err)
			}
			if cmd.Name() != sub {
				t.Fatalf("resolved %q, want %q", cmd.Name(), sub)
			}
			if err := cmd.ParseFlags(rest); err != nil {
				t.Fatalf("ParseFlags(%v): %v", rest, err)
			}
			inc, exc := scopeFileFlags(cmd)
			if inc != "in.txt" || exc != "out.txt" {
				t.Fatalf("scopeFileFlags = (%q, %q), want (in.txt, out.txt)", inc, exc)
			}
		})
	}
}
