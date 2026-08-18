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

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
)

// RenderReportsForTarget renders every report format for target's scan and
// returns the render manifest — the files THIS call wrote.
//
// cfg is the caller's RESOLVED configuration. This function used to load a
// DEFAULT config of its own here, which discarded the --config and the
// --secrets the server was started with: the render then read a different data
// directory and built its redactor from a config that had registered none of
// the operator's secrets, so redaction silently degraded in the one artefact
// most likely to be shared outside the engagement (T-15-11-05, F7). A nil cfg
// is tolerated (the data dir falls back to "data") but is never a substitute
// for the caller's own configuration.
//
// The returned paths come from report.RenderResult, not from listing the
// reports directory: a directory listing answers "what is here", which returned
// a previous run's Faraday export, an AI report from a run when AI was still
// enabled, and on a shared data dir another engagement's files (T-15-11-02).
func RenderReportsForTarget(
	ctx context.Context,
	cfg *config.Config,
	rdct *log.Redactor,
	target, scanID string,
	includeHistorical bool,
) (report.RenderResult, error) {
	dataDir := "data"
	if cfg != nil && cfg.Paths.DataDir != "" {
		dataDir = cfg.Paths.DataDir
	}
	if rdct == nil {
		rdct = &log.Redactor{}
	}

	renderer, err := report.NewReportRenderer(dataDir, cfg, slog.Default(), rdct)
	if err != nil {
		return report.RenderResult{}, fmt.Errorf("report: open renderer: %w", err)
	}
	defer renderer.Close() //nolint:errcheck

	// allowPartial=false: an MCP client asking for "the report" means the
	// finished one. Rendering an unfinished scan as though it were complete is
	// the failure mode --allow-partial exists to make explicit, and there is no
	// way for a tool caller to opt in yet.
	res, err := renderer.RenderAll(ctx, target, scanID, false, includeHistorical)
	if err != nil {
		return report.RenderResult{}, fmt.Errorf("report: render: %w", err)
	}
	return res, nil
}
