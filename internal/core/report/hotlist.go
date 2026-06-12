package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// HotlistItem is a ranked finding entry in the hotlist report.
type HotlistItem struct {
	Rank      int     `json:"rank"`
	Score     float64 `json:"score"`
	Severity  string  `json:"severity"`
	Title     string  `json:"title"`
	MatchedAt string  `json:"matched_at"`
	Asset     string  `json:"asset"`
}

// severityWeights maps severity labels to numeric weights per D-08.
// Weight table is documented here as the canonical source.
var severityWeights = map[string]float64{
	"critical": 10,
	"high":     7,
	"medium":   4,
	"low":      2,
	"info":     1,
}

// critKeywords are hostname substrings that indicate elevated asset criticality per D-08.
var critKeywords = []string{
	"admin", "api", "vpn", "internal", "staging", "git", "dev", "corp", "auth", "login",
}

// critPorts are port numbers that indicate elevated asset criticality per D-08.
var critPorts = map[int64]bool{
	22: true, 3389: true, 5432: true, 6379: true, 9200: true, 27017: true, 8080: true,
}

// assetCriticality computes an asset criticality multiplier for a given fqdn and open ports.
//
// Scoring rules (D-08):
//   - Base score: 1.0
//   - Any critKeyword in toLower(fqdn): multiply by 2.0
//   - Any critPort in openPorts: multiply by 1.5
func assetCriticality(fqdn string, openPorts []int64) float64 {
	score := 1.0
	lc := strings.ToLower(fqdn)
	for _, kw := range critKeywords {
		if strings.Contains(lc, kw) {
			score *= 2.0
			break // one keyword is sufficient
		}
	}
	for _, port := range openPorts {
		if critPorts[port] {
			score *= 1.5
			break // one critical port is sufficient
		}
	}
	return score
}

// ScoreFinding computes a hotlist score for a single finding.
//
// score = severityWeight × confidenceWeight × assetCriticality(fqdn, openPorts)
//
// confidenceWeight:
//   - 0.5 when CVSSScore is nil (no CVSS assigned)
//   - 1.0 when CVSSScore is non-nil
func ScoreFinding(f *sqlcgen.Finding, fqdn string, openPorts []int64) float64 {
	sw := severityWeights[strings.ToLower(f.Severity)]
	if sw == 0 {
		sw = 1
	}
	cw := 0.5
	if f.CVSSScore != nil {
		cw = 1.0
	}
	return sw * cw * assetCriticality(fqdn, openPorts)
}

// BuildHotlist scores all findings, sorts by score descending, and returns
// the top topN entries with assigned ranks.
//
// hostMap maps fqdn → *sqlcgen.Host for asset criticality lookups.
// A nil or empty hostMap is valid — findings will use an empty fqdn.
// topN <= 0 returns all items.
func BuildHotlist(findings []*sqlcgen.Finding, hostMap map[string]*sqlcgen.Host, topN int) []HotlistItem {
	type scoredItem struct {
		score   float64
		finding *sqlcgen.Finding
		fqdn    string
	}

	scored := make([]scoredItem, 0, len(findings))
	for _, f := range findings {
		fqdn := f.MatchedAt
		// If hostMap provided, try to look up the host for richer FQDN.
		if hostMap != nil {
			if h, ok := hostMap[f.MatchedAt]; ok {
				fqdn = h.FQDN
			}
		}
		scored = append(scored, scoredItem{
			score:   ScoreFinding(f, fqdn, nil),
			finding: f,
			fqdn:    fqdn,
		})
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	if topN > 0 && len(scored) > topN {
		scored = scored[:topN]
	}

	items := make([]HotlistItem, len(scored))
	for i, s := range scored {
		items[i] = HotlistItem{
			Rank:      i + 1,
			Score:     s.score,
			Severity:  s.finding.Severity,
			Title:     s.finding.Title,
			MatchedAt: s.finding.MatchedAt,
			Asset:     s.fqdn,
		}
	}
	return items
}

// WriteHotlist serialises the hotlist items to destPath via output.WriteFile.
func WriteHotlist(destPath string, items []HotlistItem) error {
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("report/hotlist: marshal: %w", err)
	}
	return output.WriteFile(destPath, data, 0o644)
}
