// appctx_init.go — helpers for newSubsCmd RunE wiring.
//
// filterByModuleAndEnabled: filters tasks by module + t.Enabled(cfg) + prefix match.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-06-PLAN.md Task 2.
package main

import (
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/core/ui"
)

// badgeForStatus maps a task.Status to the corresponding ui.Badge for progress display.
// Used by the StageProgress TaskDone callback wired in runSubsCmd.
//
// task.StatusDone → BadgeOK (tool completed successfully)
// task.StatusSkipped → BadgeSKIP (task disabled or dependency not met)
// task.StatusErrored / StatusCancelled → BadgeFAIL (tool failed or run cancelled)
func badgeForStatus(s task.Status) ui.Badge {
	switch s {
	case task.StatusDone:
		return ui.BadgeOK
	case task.StatusSkipped:
		return ui.BadgeSKIP
	default:
		return ui.BadgeFAIL
	}
}

// filterByModuleAndEnabled is a package-private forwarding shim.
// The implementation lives in internal/core/task.FilterByModuleAndEnabled
// so that internal/mcp/handlers (which cannot import cmd/reconftw) can
// call it directly.
//
// Source: .planning/phases/08-mcp-server/08-00-PLAN.md Task 1 (Pitfall 7 resolution).
func filterByModuleAndEnabled(tasks []task.Task, module string, cfg *config.Config, prefixes []string) []task.Task {
	return task.FilterByModuleAndEnabled(tasks, module, cfg, prefixes)
}

// matchesAnyPrefix is a package-private forwarding shim.
// The implementation lives in internal/core/task.MatchesAnyPrefix.
func matchesAnyPrefix(name string, prefixes []string) bool {
	return task.MatchesAnyPrefix(name, prefixes)
}
