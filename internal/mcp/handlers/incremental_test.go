// incremental_test.go — INTEG-04 incremental re-feed tests.
//
// BootReconApp consumes opts.TargetListPath (the monitor incremental seed) by
// writing the new-asset FQDNs to inputs/resolved.incremental.txt per the
// subdomains STAGING CONTRACT (NOT app.Tree.Append). These tests prove:
//   - the seeded FQDNs reach artefacts/subdomains.jsonl through the REAL
//     subdomains.MergeStage("resolved") merge path (web.httpx's input boundary) —
//     a NON-CIRCULAR assertion, not a read-back of the raw seed file;
//   - a set TargetListPath changes the wired InputHash (so the cycle re-executes
//     instead of checkpoint-skipping — the 12-01 bridge);
//   - a missing/unreadable seed is best-effort (no abort, no staging file).
//
// Shared helpers (resumeBoot / resumeConfigPath / resumeCloseCheckpoint /
// resumeHashFor) live in resume_test.go — same handlers_test package.
package handlers_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/mcp/handlers"
	"github.com/six2dez/reconftw/internal/modules/subdomains"
)

// TestIncrementalSeed_ReachesSubdomainsViaMergeStage is the key non-circular
// proof: after BootReconApp seeds inputs/resolved.incremental.txt from
// TargetListPath, the real resolve-stage merge folds the seeded FQDNs into
// artefacts/subdomains.jsonl — the artefact web.httpx reads — not the raw seed.
func TestIncrementalSeed_ReachesSubdomainsViaMergeStage(t *testing.T) {
	dataDir := t.TempDir()
	ctx := context.Background()
	const target = "example.com"

	// Monitor-style new-asset seed: bare FQDNs, one per line, with a comment and
	// a blank line that MUST be dropped.
	seedPath := filepath.Join(t.TempDir(), "newassets.txt")
	seedBody := "# new assets from cycle 1 diff\napi.example.com\n\nstaging.example.com\n"
	if err := os.WriteFile(seedPath, []byte(seedBody), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	boot, _ := resumeBoot(t, dataDir, handlers.RunOptions{Target: target, TargetListPath: seedPath})
	defer resumeCloseCheckpoint(boot)

	// The staging file exists with the seeded FQDNs (comment/blank stripped).
	stagePath := filepath.Join(boot.WorkDir, "inputs", "resolved.incremental.txt")
	stageData, err := os.ReadFile(stagePath) //nolint:gosec
	if err != nil {
		t.Fatalf("staging file not written by BootReconApp: %v", err)
	}
	for _, want := range []string{"api.example.com", "staging.example.com"} {
		if !strings.Contains(string(stageData), want) {
			t.Errorf("staging file missing %q; got %q", want, string(stageData))
		}
	}
	if strings.Contains(string(stageData), "#") {
		t.Errorf("staging file leaked a comment line: %q", string(stageData))
	}

	// KEY ASSERTION (non-circular): run the REAL merge and read the MERGED
	// artefact, not the seed file we just wrote.
	if err := subdomains.MergeStage(ctx, boot.App, "resolved"); err != nil {
		t.Fatalf("MergeStage(resolved): %v", err)
	}
	subsPath := filepath.Join(boot.WorkDir, "artefacts", "subdomains.jsonl")
	subsData, err := os.ReadFile(subsPath) //nolint:gosec
	if err != nil {
		t.Fatalf("subdomains.jsonl not produced — seed did not reach the merge path: %v", err)
	}
	for _, want := range []string{"api.example.com", "staging.example.com"} {
		if !strings.Contains(string(subsData), want) {
			t.Errorf("merged subdomains.jsonl missing seeded FQDN %q; got %q", want, string(subsData))
		}
	}
}

// TestIncrementalSeed_ChangesInputHash proves a set TargetListPath yields a
// DIFFERENT wired InputHash than an unset one, so the incremental cycle genuinely
// re-executes rather than checkpoint-skipping (the 12-01 hash bridge).
func TestIncrementalSeed_ChangesInputHash(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := resumeConfigPath(t, dataDir)

	seedPath := filepath.Join(t.TempDir(), "newassets.txt")
	if err := os.WriteFile(seedPath, []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	base := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com", ConfigPath: cfgPath})
	seeded := resumeHashFor(t, dataDir, handlers.RunOptions{
		Target: "example.com", ConfigPath: cfgPath, TargetListPath: seedPath,
	})
	if base == seeded {
		t.Error("InputHash unchanged when TargetListPath is set — the incremental cycle would checkpoint-skip instead of re-running")
	}
}

// TestIncrementalSeed_MissingPathIsBestEffort proves a nonexistent TargetListPath
// does not abort BootReconApp and writes no staging file.
func TestIncrementalSeed_MissingPathIsBestEffort(t *testing.T) {
	dataDir := t.TempDir()

	// resumeBoot t.Fatalf's if BootReconApp errors, so reaching the body proves
	// the missing seed did not abort the boot (best-effort).
	boot, _ := resumeBoot(t, dataDir, handlers.RunOptions{
		Target:         "example.com",
		TargetListPath: filepath.Join(t.TempDir(), "does-not-exist.txt"),
	})
	defer resumeCloseCheckpoint(boot)

	stagePath := filepath.Join(boot.WorkDir, "inputs", "resolved.incremental.txt")
	if _, err := os.Stat(stagePath); !os.IsNotExist(err) {
		t.Errorf("staging file created for a missing seed (stat err=%v), want no file", err)
	}
}
