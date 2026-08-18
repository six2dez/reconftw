package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"time"

	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// WriteCSV writes header + rows to w using encoding/csv.
func WriteCSV(w io.Writer, header []string, rows [][]string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteFindingsCSV writes findings in the canonical column order.
// Header: id, severity, title, matched_at, tool, template_signature, cvss_score
func WriteFindingsCSV(w io.Writer, findings []*sqlcgen.Finding) error {
	header := []string{"id", "severity", "title", "matched_at", "tool", "template_signature", "cvss_score"}
	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		cvss := ""
		if f.CVSSScore != nil {
			cvss = strconv.FormatFloat(*f.CVSSScore, 'f', 2, 64)
		}
		rows = append(rows, []string{
			strconv.FormatInt(f.ID, 10),
			f.Severity,
			f.Title,
			f.MatchedAt,
			f.Tool,
			f.TemplateSignature,
			cvss,
		})
	}
	return WriteCSV(w, header, rows)
}

// WriteHostsCSV writes hosts in the canonical column order.
// Header: fqdn, ip_current, asn_org, cdn, status, first_seen_at
func WriteHostsCSV(w io.Writer, hosts []*sqlcgen.Host) error {
	header := []string{"fqdn", "ip_current", "asn_org", "cdn", "status", "first_seen_at"}
	rows := make([][]string, 0, len(hosts))
	for _, h := range hosts {
		ip := ""
		if h.IpCurrent != nil {
			ip = *h.IpCurrent
		}
		asnOrg := ""
		if h.ASNOrg != nil {
			asnOrg = *h.ASNOrg
		}
		cdn := ""
		if h.CDN != nil {
			cdn = *h.CDN
		}
		rows = append(rows, []string{
			h.FQDN,
			ip,
			asnOrg,
			cdn,
			h.Status,
			time.Unix(h.FirstSeenAt, 0).UTC().Format(time.RFC3339),
		})
	}
	return WriteCSV(w, header, rows)
}

// WriteURLsCSV writes URLs in the canonical column order.
// Header: url, scheme, status_code, content_type, title, first_seen_at
func WriteURLsCSV(w io.Writer, urls []*sqlcgen.URL) error {
	header := []string{"url", "scheme", "status_code", "content_type", "title", "first_seen_at"}
	rows := make([][]string, 0, len(urls))
	for _, u := range urls {
		sc := ""
		if u.StatusCode != nil {
			sc = strconv.FormatInt(*u.StatusCode, 10)
		}
		ct := ""
		if u.ContentType != nil {
			ct = *u.ContentType
		}
		title := ""
		if u.Title != nil {
			title = *u.Title
		}
		rows = append(rows, []string{
			u.URL,
			u.Scheme,
			sc,
			ct,
			title,
			time.Unix(u.FirstSeenAt, 0).UTC().Format(time.RFC3339),
		})
	}
	return WriteCSV(w, header, rows)
}

// csvFileNames is every file WriteAllCSV writes, in write order. The render
// manifest enumerates the CSV outputs from this list rather than repeating the
// names, so a new CSV cannot be added to the writer and silently omitted from
// the manifest that claims to list what the render produced.
var csvFileNames = []string{"findings.csv", "hosts.csv", "urls.csv", "subdomains.csv"}

// WriteAllCSV writes per-category CSV files to reportsDir using output.WriteFile.
func WriteAllCSV(reportsDir string, findings []*sqlcgen.Finding, hosts []*sqlcgen.Host, urls []*sqlcgen.URL) error {
	writeOne := func(name string, writeFn func(io.Writer) error) error {
		var buf bytes.Buffer
		if err := writeFn(&buf); err != nil {
			return fmt.Errorf("report/csv: %s: %w", name, err)
		}
		return output.WriteFile(filepath.Join(reportsDir, name), buf.Bytes(), 0o644)
	}

	// Keyed by csvFileNames so the writer and the manifest cannot disagree:
	// subdomains.csv mirrors hosts.csv (subdomains are a subset of hosts).
	writers := map[string]func(io.Writer) error{
		"findings.csv":   func(w io.Writer) error { return WriteFindingsCSV(w, findings) },
		"hosts.csv":      func(w io.Writer) error { return WriteHostsCSV(w, hosts) },
		"urls.csv":       func(w io.Writer) error { return WriteURLsCSV(w, urls) },
		"subdomains.csv": func(w io.Writer) error { return WriteHostsCSV(w, hosts) },
	}
	for _, name := range csvFileNames {
		writeFn, ok := writers[name]
		if !ok {
			return fmt.Errorf("report/csv: %s is listed in csvFileNames but has no writer", name)
		}
		if err := writeOne(name, writeFn); err != nil {
			return err
		}
	}
	return nil
}
