// stateful_test.go — unit tests for the three stateful utility subcommands:
// gen-resolvers (MODE-08), refresh-cache (MODE-07), quick-rescan (MODE-06).
//
// Test coverage:
//   - TestQuickRescanForcesDiff: quickRescanConfigTransform sets cfg.Advanced.Diff=true
//     and does NOT set cfg.Advanced.QuickRescan (D-06 THIN assertion).
//   - TestRefreshCacheSetsForceRefreshFlag: refreshCacheConfigTransform sets
//     cfg.Cache.Refresh=true and cfg.Advanced.Diff=true (D-05).
//   - TestGenResolversDryRun: newGenResolversCmd() can be constructed without panic;
//     gen-resolvers requires no --target (D-04 standalone property).
//   - TestStatefulCmdsRegisteredInRoot: newRootCmd returns a tree that includes
//     "gen-resolvers", "refresh-cache", "quick-rescan" as findable subcommands.
package main

import (
	"bytes"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestQuickRescanForcesDiff asserts the ConfigTransform built by quick-rescan
// sets ONLY cfg.Advanced.Diff=true and does NOT mutate cfg.Advanced.QuickRescan
// (D-06 THIN: rely solely on Advanced.Diff, no new QuickRescan field).
func TestQuickRescanForcesDiff(t *testing.T) {
	cfg := config.Defaults()

	// Assert precondition: both fields are false before the transform.
	if cfg.Advanced.Diff {
		t.Fatal("precondition: cfg.Advanced.Diff should be false before transform")
	}
	quickRescanBeforeQR := cfg.Advanced.QuickRescan

	// Apply the transform that newQuickRescanCmd's RunE would apply.
	quickRescanConfigTransform(cfg)

	// Post-condition 1: Diff must be true.
	if !cfg.Advanced.Diff {
		t.Error("quickRescanConfigTransform: cfg.Advanced.Diff must be true after transform")
	}

	// Post-condition 2 (D-06 THIN): QuickRescan must NOT have been changed by the
	// transform (whatever it was before, it is the same after).
	if cfg.Advanced.QuickRescan != quickRescanBeforeQR {
		t.Errorf("quickRescanConfigTransform: cfg.Advanced.QuickRescan changed from %v to %v — D-06 says do NOT touch this field",
			quickRescanBeforeQR, cfg.Advanced.QuickRescan)
	}
}

// TestRefreshCacheSetsForceRefreshFlag asserts the ConfigTransform for
// refresh-cache sets both cfg.Cache.Refresh=true and cfg.Advanced.Diff=true.
func TestRefreshCacheSetsForceRefreshFlag(t *testing.T) {
	cfg := config.Defaults()

	// Assert preconditions.
	if cfg.Cache.Refresh {
		t.Fatal("precondition: cfg.Cache.Refresh should be false before transform")
	}
	if cfg.Advanced.Diff {
		t.Fatal("precondition: cfg.Advanced.Diff should be false before transform")
	}

	refreshCacheConfigTransform(cfg)

	if !cfg.Cache.Refresh {
		t.Error("refreshCacheConfigTransform: cfg.Cache.Refresh must be true after transform")
	}
	if !cfg.Advanced.Diff {
		t.Error("refreshCacheConfigTransform: cfg.Advanced.Diff must be true after transform")
	}
}

// TestGenResolversDryRun verifies that newGenResolversCmd() can be constructed
// without panic and that it is a standalone command (no --target required per D-04).
func TestGenResolversDryRun(t *testing.T) {
	cmd := newGenResolversCmd()
	if cmd == nil {
		t.Fatal("newGenResolversCmd() returned nil")
	}
	if cmd.Use != "gen-resolvers" {
		t.Errorf("gen-resolvers Use = %q, want %q", cmd.Use, "gen-resolvers")
	}

	// Assert no --target flag is required (standalone per D-04).
	targetFlag := cmd.Flags().Lookup("target")
	// The command inherits --target from root's persistent flags, but gen-resolvers
	// does NOT define it as a required local flag.
	if targetFlag != nil {
		// If it somehow defined a local --target, it should not be marked required.
		annotations := targetFlag.Annotations
		if _, required := annotations[cobra_required]; required {
			t.Error("gen-resolvers: --target must not be required (D-04 standalone)")
		}
	}

	// Verify the command has a RunE (not nil), meaning it is a real implementation.
	if cmd.RunE == nil {
		t.Error("newGenResolversCmd().RunE is nil — command has no implementation")
	}

	// Execute the command with --help to verify it is well-formed without panic.
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{"--help"})
	// --help should exit with nil or exitCodeError, not panic.
	// We do a no-panic assertion via recover.
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("gen-resolvers --help panicked: %v", r)
		}
	}()
	_ = cmd.Execute()
}

// cobra_required is the cobra annotation key for required flags.
// Defined here to avoid importing cobra in this test (cmd package is main).
const cobra_required = "cobra_annotation_bash_completion_one_required_flag"

// TestStatefulCmdsRegisteredInRoot verifies that the three stateful subcommands
// are accessible via newRootCmd().Find(...).
func TestStatefulCmdsRegisteredInRoot(t *testing.T) {
	root := newRootCmd(nil, config.Defaults())
	if root == nil {
		t.Fatal("newRootCmd returned nil")
	}

	for _, name := range []string{"gen-resolvers", "refresh-cache", "quick-rescan"} {
		found, _, err := root.Find([]string{name})
		if err != nil || found == nil || found.Use == "" {
			// cobra.Find may return the root itself if not found — check that the
			// found command's Use starts with the name we looked for.
			t.Errorf("root.Find(%q): subcommand not found (found.Use=%q, err=%v)",
				name, func() string {
					if found != nil {
						return found.Use
					}
					return "<nil>"
				}(), err)
			continue
		}
		// The found command's Use should start with the subcommand name.
		if found == root {
			t.Errorf("root.Find(%q) returned root itself — subcommand not registered", name)
		}
	}
}
