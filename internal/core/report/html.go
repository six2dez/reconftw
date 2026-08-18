package report

import (
	"bytes"
	"fmt"
	"io"
	"time"

	// CRITICAL: MUST be html/template — NOT text/template.
	// html/template provides contextual auto-escape which is the REPORT-02
	// guarantee: user-controlled finding titles cannot inject raw HTML.
	"html/template"

	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// FindingRow is a template-safe representation of a finding for HTML rendering.
type FindingRow struct {
	ID        int64
	Severity  string
	Title     string
	MatchedAt string
	Tool      string
}

// HostRow is a template-safe representation of a host for HTML rendering.
type HostRow struct {
	FQDN      string
	IPCurrent string
	Status    string
}

// URLRow is a template-safe representation of a URL for HTML rendering.
type URLRow struct {
	URL        string
	Scheme     string
	StatusCode string
	Title      string
}

// ReportData is the data struct passed to the HTML template.
// All fields that come from store data are typed as plain strings/ints
// so html/template will HTML-escape them automatically when rendered
// in a text context.
type ReportData struct {
	Target          string
	ScanID          string
	StartedAt       string
	FinishedAt      string
	ReconftwVersion string
	FindingsCount   int
	SubdomainCount  int
	URLCount        int
	HotlistTop      int
	HotlistItems    []HotlistItem
	Findings        []FindingRow
	Hosts           []HostRow
	URLs            []URLRow
	ConfigSnapshot  string // from scans.config_overrides_json
	ToolVersions    string // from scans.tool_versions_json
	// ScopeNotice is rendered as a banner above the report metadata when the
	// report's scope is wider than the scan it names — currently only the
	// includeHistorical opt-in sets it (report.HistoricalNotice).
	ScopeNotice string
}

// FindingsToRows converts a slice of sqlcgen.Finding to FindingRow for template use.
func FindingsToRows(findings []*sqlcgen.Finding) []FindingRow {
	rows := make([]FindingRow, 0, len(findings))
	for _, f := range findings {
		rows = append(rows, FindingRow{
			ID:        f.ID,
			Severity:  f.Severity,
			Title:     f.Title,
			MatchedAt: f.MatchedAt,
			Tool:      f.Tool,
		})
	}
	return rows
}

// HostsToRows converts a slice of sqlcgen.Host to HostRow for template use.
func HostsToRows(hosts []*sqlcgen.Host) []HostRow {
	rows := make([]HostRow, 0, len(hosts))
	for _, h := range hosts {
		ip := ""
		if h.IpCurrent != nil {
			ip = *h.IpCurrent
		}
		rows = append(rows, HostRow{
			FQDN:      h.FQDN,
			IPCurrent: ip,
			Status:    h.Status,
		})
	}
	return rows
}

// URLsToRows converts a slice of sqlcgen.URL to URLRow for template use.
func URLsToRows(urls []*sqlcgen.URL) []URLRow {
	rows := make([]URLRow, 0, len(urls))
	for _, u := range urls {
		sc := ""
		if u.StatusCode != nil {
			sc = fmt.Sprintf("%d", *u.StatusCode)
		}
		title := ""
		if u.Title != nil {
			title = *u.Title
		}
		rows = append(rows, URLRow{
			URL:        u.URL,
			Scheme:     u.Scheme,
			StatusCode: sc,
			Title:      title,
		})
	}
	return rows
}

// reportTemplateStr is the single self-contained HTML template with inline CSS.
// Uses <details>/<summary> for collapsible sections per the plan spec.
// No external resources are referenced (offline-compatible).
const reportTemplateStr = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>reconFTW Report — {{.Target}}</title>
  <style>
    body{font-family:monospace;max-width:1200px;margin:0 auto;padding:1em;background:#1a1a2e;color:#e0e0e0}
    h1{color:#e94560;border-bottom:2px solid #e94560;padding-bottom:.3em}
    h2{color:#0f3460;background:#16213e;padding:.4em .6em;margin-top:1em}
    details{border:1px solid #0f3460;padding:.5em;margin:.5em 0;background:#16213e}
    summary{cursor:pointer;font-weight:bold;color:#e94560;padding:.2em 0}
    summary:hover{color:#c94050}
    .meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.5em;margin:1em 0}
    .meta-item{background:#0f3460;padding:.5em;border-radius:4px}
    .meta-label{color:#a0a0c0;font-size:.85em}
    .meta-value{color:#e0e0e0;font-weight:bold}
    table{border-collapse:collapse;width:100%;margin-top:.5em}
    td,th{border:1px solid #0f3460;padding:.3em .5em;text-align:left}
    th{background:#0f3460;color:#e94560}
    tr:nth-child(even){background:#1a1a2e}
    .critical{color:#ff4444;font-weight:bold}
    .high{color:#ff8800;font-weight:bold}
    .medium{color:#ffcc00}
    .low{color:#66aaff}
    .info{color:#aaaaaa}
    .badge{display:inline-block;padding:.1em .4em;border-radius:3px;font-size:.85em}
    .badge-critical{background:#ff4444;color:#fff}
    .badge-high{background:#ff8800;color:#fff}
    .badge-medium{background:#ffcc00;color:#000}
    .badge-low{background:#66aaff;color:#000}
    .badge-info{background:#555;color:#fff}
    .count{font-size:1.5em;font-weight:bold;color:#e94560}
    .empty{color:#666;font-style:italic}
    .scope-notice{background:#e94560;color:#fff;padding:10px 14px;margin:0 0 16px;
      border-radius:4px;font-weight:bold}
  </style>
</head>
<body>
  <h1>reconFTW Scan Report</h1>
{{if .ScopeNotice}}
  <div class="scope-notice">{{.ScopeNotice}}</div>
{{end}}

  <div class="meta">
    <div class="meta-item">
      <div class="meta-label">Target</div>
      <div class="meta-value">{{.Target}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Scan ID</div>
      <div class="meta-value">{{.ScanID}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Started</div>
      <div class="meta-value">{{.StartedAt}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Finished</div>
      <div class="meta-value">{{.FinishedAt}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Findings</div>
      <div class="meta-value count">{{.FindingsCount}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Subdomains</div>
      <div class="meta-value count">{{.SubdomainCount}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">URLs</div>
      <div class="meta-value count">{{.URLCount}}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">reconFTW Version</div>
      <div class="meta-value">{{.ReconftwVersion}}</div>
    </div>
  </div>

  <details open>
    <summary>Hotlist (top {{.HotlistTop}} by risk score)</summary>
    {{if .HotlistItems}}
    <table>
      <tr><th>Rank</th><th>Score</th><th>Severity</th><th>Title</th><th>Asset</th></tr>
      {{range .HotlistItems}}
      <tr>
        <td>{{.Rank}}</td>
        <td>{{printf "%.1f" .Score}}</td>
        <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Title}}</td>
        <td>{{.Asset}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}<p class="empty">No hotlist items.</p>{{end}}
  </details>

  <details>
    <summary>Findings ({{.FindingsCount}})</summary>
    {{if .Findings}}
    <table>
      <tr><th>ID</th><th>Severity</th><th>Title</th><th>Matched At</th><th>Tool</th></tr>
      {{range .Findings}}
      <tr>
        <td>{{.ID}}</td>
        <td><span class="badge badge-{{.Severity}}">{{.Severity}}</span></td>
        <td>{{.Title}}</td>
        <td>{{.MatchedAt}}</td>
        <td>{{.Tool}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}<p class="empty">No findings recorded for this scan.</p>{{end}}
  </details>

  <details>
    <summary>Hosts / Subdomains ({{.SubdomainCount}})</summary>
    {{if .Hosts}}
    <table>
      <tr><th>FQDN</th><th>IP</th><th>Status</th></tr>
      {{range .Hosts}}
      <tr>
        <td>{{.FQDN}}</td>
        <td>{{.IPCurrent}}</td>
        <td>{{.Status}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}<p class="empty">No hosts recorded for this scan.</p>{{end}}
  </details>

  <details>
    <summary>URLs ({{.URLCount}})</summary>
    {{if .URLs}}
    <table>
      <tr><th>URL</th><th>Scheme</th><th>Status</th><th>Title</th></tr>
      {{range .URLs}}
      <tr>
        <td>{{.URL}}</td>
        <td>{{.Scheme}}</td>
        <td>{{.StatusCode}}</td>
        <td>{{.Title}}</td>
      </tr>
      {{end}}
    </table>
    {{else}}<p class="empty">No URLs recorded for this scan.</p>{{end}}
  </details>

  <details>
    <summary>Scan Metadata</summary>
    <h2>Tool Versions</h2>
    <pre>{{.ToolVersions}}</pre>
    <h2>Config Overrides</h2>
    <pre>{{.ConfigSnapshot}}</pre>
  </details>

  <footer style="margin-top:2em;color:#555;font-size:.8em">
    Generated by reconFTW v2 &mdash; {{.StartedAt}}
  </footer>
</body>
</html>`

// reportTmpl is the compiled HTML template. Using html/template guarantees
// contextual auto-escaping for all {{.Field}} expressions (REPORT-02 guarantee).
var reportTmpl = template.Must(template.New("report").Parse(reportTemplateStr))

// RenderHTML renders ReportData to destPath using html/template.
// Uses output.WriteFile for atomic 4-step write guarantee (ADR §3.5).
func RenderHTML(data ReportData, destPath string) error {
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("report/html: template execute: %w", err)
	}
	return output.WriteFile(destPath, buf.Bytes(), 0o644)
}

// RenderHTMLWriter renders ReportData to an io.Writer (used by tests).
func RenderHTMLWriter(data ReportData, w io.Writer) error {
	if err := reportTmpl.Execute(w, data); err != nil {
		return fmt.Errorf("report/html: template execute: %w", err)
	}
	return nil
}

// formatUnixTS formats a Unix timestamp (int64) for display. Zero → "N/A".
func formatUnixTS(ts int64) string {
	if ts == 0 {
		return "N/A"
	}
	return time.Unix(ts, 0).UTC().Format(time.RFC3339)
}
