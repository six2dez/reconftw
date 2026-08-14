// e2e_earlyboot_test.go — the pre-cobra boot must respect -o and --dry-run.
//
// main.run scans argv for a few flags and, when --target is present, boots a
// workspace + checkpoint store BEFORE cobra parses anything. It knew nothing
// about -o/--output or --dry-run, so:
//
//	reconftw recon --target example.com --dry-run -o ./wanted
//
// created ./wanted/example.com (the subcommand's) AND ./workspaces/example.com
// (this boot's, under the configured root) — a dry run with filesystem side
// effects, in a directory the operator never named.
package main

import "testing"

func TestE2EEarlyFlagsCaptureOutputAndDryRun(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		args       []string
		wantOut    string
		wantDryRun bool
	}{
		{"separate -o", []string{"recon", "--target", "x", "-o", "./wanted"}, "./wanted", false},
		{"separate --output", []string{"recon", "--output", "./w2"}, "./w2", false},
		{"joined --output=", []string{"recon", "--output=./w3"}, "./w3", false},
		{"dry-run", []string{"recon", "--target", "x", "--dry-run"}, "", true},
		{"both", []string{"recon", "--dry-run", "-o", "./w4"}, "./w4", true},
		{"neither", []string{"recon", "--target", "x"}, "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			efs := parseEarlyFlags(tc.args)
			if efs.outputDir != tc.wantOut {
				t.Errorf("outputDir = %q, want %q — the early boot would create a "+
					"workspace under the configured root instead", efs.outputDir, tc.wantOut)
			}
			if efs.dryRun != tc.wantDryRun {
				t.Errorf("dryRun = %v, want %v — a dry run must not boot a workspace",
					efs.dryRun, tc.wantDryRun)
			}
		})
	}
}
