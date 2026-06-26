// filter.go — module-level task filtering helpers.
//
// FilterByModuleAndEnabled and MatchesAnyPrefix are exported from
// internal/core/task so that both cmd/reconftw (CLI) and
// internal/mcp/handlers (MCP tool handlers) can call them without
// a package-visibility barrier.
//
// Source: .planning/phases/08-mcp-server/08-00-PLAN.md Task 1
// (Pitfall 7 resolution: filterByModuleAndEnabled was package-private in
// cmd/reconftw; moved here per RESEARCH.md §Pattern 6 recommendation).
package task

import (
	"strings"

	"github.com/six2dez/reconftw/internal/core/config"
)

// FilterByModuleAndEnabled returns the subset of tasks where:
//   - t.Module() == module
//   - t.Enabled(cfg) == true  (gate: scheduler never calls Enabled; caller must)
//   - MatchesAnyPrefix(t.Name(), prefixes) == true
//
// Nil tasks input returns nil. Empty prefixes returns an empty slice
// because no task name can match zero prefixes.
//
// This is the canonical REVIEWS finding #4 fix: the Scheduler never calls
// Enabled() before Run(), so the command layer MUST gate tasks here.
func FilterByModuleAndEnabled(tasks []Task, module string, cfg *config.Config, prefixes []string) []Task {
	var result []Task
	for _, t := range tasks {
		if t.Module() != module {
			continue
		}
		if !t.Enabled(cfg) {
			continue
		}
		if MatchesAnyPrefix(t.Name(), prefixes) {
			result = append(result, t)
		}
	}
	return result
}

// MatchesAnyPrefix reports whether name has any of the given prefixes.
// Returns false for an empty or nil prefixes slice.
func MatchesAnyPrefix(name string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
