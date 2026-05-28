// version.go — `reconftw version` subcommand (working per CONTEXT D-04).
//
// Source: ADR 0002 §8.1 (version subcommand inventory) + 03-CONTEXT.md D-04.
//
// Prints 5 lines to stdout, exit 0:
//
//	reconftw version <Version>
//	  commit:     <CommitSHA | vcs.revision | "unknown">
//	  built:      <BuildDate | "unknown">
//	  go version: <runtime.Version()>
//	  platform:   <runtime.GOOS>/<runtime.GOARCH>
//
// Variables Version / CommitSHA / BuildDate are set by XCUT-02 ldflags at
// `make build` time (-X main.Version=..., -X main.CommitSHA=..., -X main.BuildDate=...).
// At go-run / unit-test time they remain the "dev/unknown" defaults; commit SHA
// falls back to runtime/debug.ReadBuildInfo (which captures the vcs.revision
// embedded by `go build` since 1.18+).

package main

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// newVersionCmd creates the working version subcommand per D-04.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print binary version + commit + build info",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "reconftw version %s\n", Version)
			fmt.Fprintf(out, "  commit:     %s\n", lookupCommit())
			fmt.Fprintf(out, "  built:      %s\n", BuildDate)
			fmt.Fprintf(out, "  go version: %s\n", runtime.Version())
			fmt.Fprintf(out, "  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

// lookupCommit resolves the commit SHA via (in priority order):
//  1. The ldflag-injected main.CommitSHA (when set by `make build`).
//  2. runtime/debug.ReadBuildInfo → vcs.revision (set by go build 1.18+).
//  3. The literal string "unknown".
func lookupCommit() string {
	if CommitSHA != "unknown" && CommitSHA != "" {
		return CommitSHA
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return "unknown"
}
