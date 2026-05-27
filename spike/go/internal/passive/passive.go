// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
// Bash reference: modules/subdomains.sh:sub_passive() (lines 507-553)
package passive

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"

	"github.com/six2dez/reconftw/spike/go/internal/output"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
	"golang.org/x/sync/errgroup"
)

// domainRe validates target domains per T-01-02-SI-01 threat mitigation.
// Mirrors validate_domain() in lib/validation.sh.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// subEntry is one line in the output subs.jsonl.
type subEntry struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// Run fans out to 4 passive sources (subfinder, crt, github-subdomains, gitlab-subdomains)
// concurrently using errgroup.SetLimit(4). Each source's stdout is parsed into subdomain strings,
// merged into a deduplicated set, then written atomically to outFile as JSONL:
// {"subdomain": "x.example.com", "source": "subfinder"}.
//
// Source pattern: bash modules/subdomains.sh:sub_passive() (lines 507-553)
// Slice locked: spike/README.md §Slice Locked
func Run(ctx context.Context, target string, outFile string) error {
	// T-01-02-SI-01: validate target before passing to subprocess.
	if !domainRe.MatchString(target) {
		return &invalidTargetError{target: target}
	}

	// Shared collection with mutex for goroutine-safe merging.
	// subdomain → first-seen source (dedup: first source wins).
	var mu sync.Mutex
	collected := make(map[string]string)

	collect := func(subdomain, source string) {
		if subdomain == "" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if _, exists := collected[subdomain]; !exists {
			collected[subdomain] = source
		}
	}

	// Fan-out: 4 sources concurrently, bounded by SetLimit(4).
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(4)

	g.Go(func() error { return subfinderRun(gctx, target, collect) })
	g.Go(func() error { return crtRun(gctx, target, collect) })
	g.Go(func() error { return githubRun(gctx, target, collect) })
	g.Go(func() error { return gitlabRun(gctx, target, collect) })

	if err := g.Wait(); err != nil {
		// Log the error but don't fail — partial results are fine for a spike.
		ui.Warn("passive: one or more sources returned an error: " + err.Error())
	}

	// Serialize the merged results.
	lines := make([][]byte, 0, len(collected))
	for subdomain, source := range collected {
		entry := subEntry{Subdomain: subdomain, Source: source}
		b, err := json.Marshal(entry)
		if err != nil {
			continue
		}
		lines = append(lines, b)
	}

	ui.Info("passive: collected " + itoa(len(lines)) + " unique subdomains")

	// Write atomically to outFile.
	return output.WriteJSONL(outFile, lines)
}

// invalidTargetError is returned when the target domain fails validation.
type invalidTargetError struct{ target string }

func (e *invalidTargetError) Error() string {
	return "invalid target: " + e.target + " (must match ^[a-zA-Z0-9.-]+$)"
}

// itoa is a tiny int-to-string helper (avoid importing strconv for 1 call).
func itoa(n int) string {
	b := make([]byte, 0, 20)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
