package report

// Faraday fplugin JSON import format — host-centric structure per fplugin importer docs.

import (
	"encoding/json"
	"fmt"

	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// faradayExport is the top-level Faraday fplugin JSON export structure.
type faradayExport struct {
	Hosts []faradayHost `json:"hosts"`
}

// faradayHost represents a single host in the Faraday fplugin format.
type faradayHost struct {
	IP              string        `json:"ip"`
	OS              string        `json:"os"`
	Hostnames       []string      `json:"hostnames"`
	Services        []any         `json:"services"`
	Vulnerabilities []faradayVuln `json:"vulnerabilities"`
}

// faradayVuln represents a single vulnerability in the Faraday fplugin format.
type faradayVuln struct {
	Name       string `json:"name"`
	Desc       string `json:"desc"`
	Severity   string `json:"severity"`
	Refs       []any  `json:"refs"`
	Resolution string `json:"resolution"`
	Data       string `json:"data"`
	Status     string `json:"status"`
	Website    string `json:"website"`
}

// buildFaradayExport groups findings by host and builds the Faraday export structure.
func buildFaradayExport(findings []*sqlcgen.Finding, hosts []*sqlcgen.Host) faradayExport {
	// Build a lookup from FQDN → host.
	hostByFQDN := make(map[string]*sqlcgen.Host, len(hosts))
	for _, h := range hosts {
		hostByFQDN[h.FQDN] = h
	}

	// Group findings by MatchedAt (domain).
	type hostEntry struct {
		host  *sqlcgen.Host
		vulns []faradayVuln
	}
	grouped := make(map[string]*hostEntry)

	for _, f := range findings {
		key := f.MatchedAt
		if _, ok := grouped[key]; !ok {
			grouped[key] = &hostEntry{host: hostByFQDN[key]}
		}
		grouped[key].vulns = append(grouped[key].vulns, faradayVuln{
			Name:     f.Title,
			Desc:     f.Description,
			Severity: f.Severity,
			Refs:     []any{},
			Status:   "open",
			Website:  f.MatchedAt,
		})
	}

	hostList := make([]faradayHost, 0, len(grouped))
	for fqdn, entry := range grouped {
		fh := faradayHost{
			Hostnames:       []string{fqdn},
			Services:        []any{},
			Vulnerabilities: entry.vulns,
		}
		if entry.host != nil {
			if entry.host.IpCurrent != nil {
				fh.IP = *entry.host.IpCurrent
			}
		}
		if fh.IP == "" {
			fh.IP = fqdn // fallback: use fqdn as IP when not resolved
		}
		hostList = append(hostList, fh)
	}

	return faradayExport{Hosts: hostList}
}

// WriteFaraday writes a Faraday fplugin-compatible JSON export to destPath.
// Uses output.WriteFile for atomic 4-step write guarantee (ADR §3.5).
func WriteFaraday(destPath string, findings []*sqlcgen.Finding, hosts []*sqlcgen.Host) error {
	export := buildFaradayExport(findings, hosts)
	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("report/faraday: marshal: %w", err)
	}
	return output.WriteFile(destPath, data, 0o644)
}
