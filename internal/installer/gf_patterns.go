// SPDX-License-Identifier: MIT
//
// gf_patterns.go — post-install provisioning of the gf pattern library.
//
// WHY THIS STEP EXISTS. `go install github.com/tomnomnom/gf` puts the BINARY on
// PATH and nothing else: gf ships no patterns of its own, it reads them from
// ~/.gf/*.json at runtime. With that directory empty every `gf <class>` call
// fails with "unknown pattern", and vulns.gf treats a failed class as
// best-effort — it logs at DEBUG, writes an EMPTY bucket, and continues
// (modules/vulns/gf.go). Every downstream vuln Task then reads an empty bucket
// and returns StatusSkipped.
//
// The net effect on a clean v2 install was ZERO findings across all eight
// classes (xss/ssti/ssrf/sqli/redirect/rce/potential/lfi), reported as a
// SUCCESSFUL run, with nothing above Debug level to say otherwise. Marking gf
// `critical` in tools.lock does not fix that on its own: it proves the binary
// resolves, not that it can classify anything.
//
// v1 did this inside install.sh's repo loop (install.sh:773-785). The Go
// installer had no provisioning phase at all, so the behaviour was lost in the
// port rather than deliberately dropped.
package installer

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// GFRequiredPatterns is the set of gf classes that BOTH vulns.GFTask invokes and
// the upstream sources can actually supply. health-check gates on exactly this
// set: a class listed here and absent from ~/.gf is an install that can be fixed.
//
// Together with GFUnobtainablePatterns it must account for every entry of
// gfClasses in internal/modules/vulns/gf.go; TestGFRequiredPatternsMatchesGFClasses
// (in that package) fails on drift. The list is duplicated rather than imported
// because the installer sits below the modules layer and must not depend on it.
var GFRequiredPatterns = []string{
	"xss", "ssti", "ssrf", "sqli", "redirect", "rce", "lfi",
}

// GFUnobtainablePatterns are classes GFTask asks gf for that NO upstream source
// in gfPatternSources ships, mapped to why.
//
// They are deliberately NOT health-check failures. Gating on a pattern that
// cannot be obtained would paint every install red forever for a condition no
// operator can fix — and since gf is a critical tool, that means every
// `reconftw install` exiting non-zero.
//
// This is not a v2 regression: v1 asks for the same class (modules/web.sh:2098,
// `gf potential | cut -d: -f3-5`) and its installer clones the same three repos
// (install.sh:407-409), so on a clean v1 box `gf potential` fails with "unknown
// pattern" and writes an empty gf/potential.txt exactly as v2 does. Verified on
// 2026-09-03 by cloning all three: 39 distinct patterns, no "potential" among
// them. The class is kept in gfClasses for v1 parity — if a source for it ever
// appears, move the entry into GFRequiredPatterns and it starts being enforced.
var GFUnobtainablePatterns = map[string]string{
	"potential": "no source in gfPatternSources ships potential.json (v1 has the same gap)",
}

// gfPatternSource is one upstream repository contributing *.json patterns.
type gfPatternSource struct {
	repoURL string
	// subdir is the path WITHIN the clone holding the *.json files;
	// "" means the clone root.
	subdir string
}

// gfPatternSources mirrors the three repos v1's install.sh cloned for patterns.
// Order is significant: see provisionGFPatterns for the first-wins rule.
var gfPatternSources = []gfPatternSource{
	{repoURL: "https://github.com/tomnomnom/gf", subdir: "examples"},
	{repoURL: "https://github.com/1ndianl33t/Gf-Patterns"},
	{repoURL: "https://github.com/g0ldencybersec/sus_params", subdir: "gf-patterns"},
}

// gfPatternDir is where gf looks for its patterns. Indirected as a var so tests
// can point it at a temp dir, matching the runCmd/detectPkgMgrFn idiom in this
// package — nothing here may write into the developer's real ~/.gf.
var gfPatternDir = func() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gf")
}

// provisionGFPatterns clones each pattern source and copies its *.json files
// into ~/.gf.
//
// FIRST SOURCE WINS — a deliberate divergence from v1. v1 merged the third
// source into any existing file with `cat "$f" | anew -q "$dest"`, which appends
// unique LINES; applied to two different JSON documents that produces a file
// that is no longer valid JSON, and gf then rejects the pattern it was meant to
// enrich. Skipping a name that already exists is deterministic and can never
// corrupt a pattern file. Collisions across these three repos are name-level
// duplicates of the same class, not complementary halves of one document.
//
// A source that cannot be cloned is logged and skipped: a transient GitHub
// failure must not abort an install. The error return is reserved for the one
// outcome that matters — ending with NO usable patterns at all, which is the
// silent-zero condition this whole file exists to prevent.
func provisionGFPatterns(ctx context.Context, log *slog.Logger) error {
	dest := gfPatternDir()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return fmt.Errorf("gf patterns: mkdir %s: %w", dest, err)
	}

	var copied int
	for _, src := range gfPatternSources {
		n, err := provisionOneGFSource(ctx, src, dest)
		if err != nil {
			if log != nil {
				log.Warn("gf_patterns_source_failed",
					"repo", src.repoURL, "err", err)
			}
			continue
		}
		copied += n
		if log != nil {
			log.Info("gf_patterns_source_ok", "repo", src.repoURL, "patterns", n)
		}
	}

	missing := MissingGFPatterns()
	if len(missing) == len(GFRequiredPatterns) {
		return fmt.Errorf(
			"gf patterns: no patterns provisioned into %s from %d source(s) — "+
				"gf would classify nothing and every vuln class would silently skip",
			dest, len(gfPatternSources))
	}
	if len(missing) > 0 && log != nil {
		log.Warn("gf_patterns_incomplete",
			"dir", dest, "copied", copied, "missing", missing)
	}
	return nil
}

// provisionOneGFSource clones one source into a temp dir and copies its *.json
// files into dest, skipping names that already exist. Returns the copy count.
func provisionOneGFSource(ctx context.Context, src gfPatternSource, dest string) (int, error) {
	dir, err := os.MkdirTemp("", "reconftw-gf-patterns-")
	if err != nil {
		return 0, fmt.Errorf("mkdtemp: %w", err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup

	if err := runCmd(ctx, "git", []string{"clone", "--depth", "1", src.repoURL, dir}, nil); err != nil {
		return 0, fmt.Errorf("clone: %w", err)
	}

	from := dir
	if src.subdir != "" {
		from = filepath.Join(dir, src.subdir)
	}
	entries, err := os.ReadDir(from)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", src.subdir, err)
	}

	var n int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		target := filepath.Join(dest, e.Name())
		if _, statErr := os.Stat(target); statErr == nil {
			continue // first source wins
		}
		data, readErr := os.ReadFile(filepath.Join(from, e.Name())) //nolint:gosec // path from our own clone
		if readErr != nil {
			continue
		}
		if writeErr := os.WriteFile(target, data, 0o644); writeErr != nil { //nolint:gosec // patterns are not secret
			continue
		}
		n++
	}
	return n, nil
}

// patternPresent reports whether dir holds a pattern file for class.
func patternPresent(dir, class string) bool {
	_, err := os.Stat(filepath.Join(dir, class+".json"))
	return err == nil
}

// MissingGFPatterns returns the GFRequiredPatterns classes with no pattern file
// in ~/.gf. Exported so HealthCheck and cmd/reconftw health-check agree on what
// "gf is usable" means.
func MissingGFPatterns() []string {
	dir := gfPatternDir()
	var missing []string
	for _, class := range GFRequiredPatterns {
		if !patternPresent(dir, class) {
			missing = append(missing, class)
		}
	}
	return missing
}
