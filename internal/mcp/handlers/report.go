// report.go — shared report rendering for the CLI and the MCP `report` tool.
//
// The MCP tool used to be a stub answering {"status":"not_implemented"}. Rather
// than duplicate the CLI's rendering path (which is how the CLI and MCP drift
// apart, the thing MCP-02 exists to prevent), both now call this.
package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
)

// RenderReportsForTarget renders every report format for target's latest
// completed scan and returns the paths written.
//
// It resolves the data directory from the loaded config, exactly as the CLI
// does, so both surfaces read the same store and write to the same place.
func RenderReportsForTarget(ctx context.Context, target string) ([]string, error) {
	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		return nil, fmt.Errorf("report: config load: %w", err)
	}
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		dataDir = "data"
	}

	rdct := &log.Redactor{}
	renderer, err := report.NewReportRenderer(dataDir, cfg, slog.Default(), rdct)
	if err != nil {
		return nil, fmt.Errorf("report: open renderer: %w", err)
	}
	defer renderer.Close() //nolint:errcheck

	// allowPartial=false: an MCP client asking for "the report" means the
	// finished one. Rendering an unfinished scan as though it were complete is
	// the failure mode --allow-partial exists to make explicit, and there is no
	// way for a tool caller to opt in yet.
	if err := renderer.RenderAll(ctx, target, "", false, false); err != nil {
		return nil, fmt.Errorf("report: render: %w", err)
	}

	reportsDir := filepath.Join(dataDir, "reports")
	entries, err := os.ReadDir(reportsDir)
	if err != nil {
		// Rendering succeeded, so report the directory even if it cannot be
		// listed — the caller still needs to know where to look.
		return []string{reportsDir}, nil //nolint:nilerr // path is the useful answer
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			paths = append(paths, filepath.Join(reportsDir, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}
