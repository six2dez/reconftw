// ip_info.go — IPInfoTask: CIDR + ASN org + geo (OSINT-02).
//
// IPInfoTask resolves the root domain to its A-record IPs (via dnsx), then for
// the resolved IP set runs mapcidr for CIDR ranges, asnmap for the ASN org, and
// an ipinfo.io geo lookup (mirroring subdomains/geo.go's raw http.Client). Each
// CIDR/ASN/geo datum becomes an informational OSINTFindingRecord (D-O4) written
// to inputs/findings.ip_info.jsonl per the multi-writer staging contract
// (doc.go — D-O3). The whois/relations text per IP is preserved as the
// single-writer human file osint/ip_<ip>_whois.txt (D-O5, v1 osint.sh:741).
//
// SEEDING (D-O1): root-domain-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — every step logs Debug + continues.
// PD TOOLS (D-O7): dnsx + asnmap args include -duc.
//
// SECRET HANDLING (XCUT-07): the PDCP key (cfg.APIKeys.PDCP, a log.Secret type)
// is cast to a raw string ONLY into the ipinfo.io Authorization header, never
// into any log line (mirrors subdomains/geo.go:97-100).
//
// THREAT MODEL (T-07-02-01): domain/IP strings cross into dnsx/mapcidr/asnmap
// argv via Backend.Run's []string arg-vector (never a shell string).
//
// Source: .planning/phases/07-osint-e2e/07-02-PLAN.md Task 1.
package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ipInfoBaseURL is the ipinfo.io base, overridable for tests.
const ipInfoDefaultBaseURL = "https://ipinfo.io"

func ipInfoBaseURL() string {
	if u := os.Getenv("RECONFTW_IPINFO_BASE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return ipInfoDefaultBaseURL
}

// IPInfoTask runs mapcidr + asnmap + geo for OSINT-02.
type IPInfoTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *IPInfoTask) Name() string { return "osint.ip_info" }

// Module returns the owning module group.
func (t *IPInfoTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *IPInfoTask) Description() string { return "CIDR + ASN org + geo (OSINT-02)" }

// Enabled reports whether ip_info is configured.
func (t *IPInfoTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.IPInfo.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *IPInfoTask) DependsOn() []string { return nil }

// Run executes the IP info pipeline.
//
// Steps:
//  1. Resolve the root domain → A-record IPs via dnsx (-duc).
//  2. mapcidr per IP → CIDR records (CIDREnabled gate).
//  3. asnmap per IP (-duc) → ASN org records (ASNEnabled gate).
//  4. ipinfo.io geo per IP → geo records; preserve osint/ip_<ip>_whois.txt (D-O5).
//  5. Write inputs/findings.ip_info.jsonl (multi-writer staging).
func (t *IPInfoTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.ip_info: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	cfg := app.Cfg
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.ip_info: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	// Step 1: resolve domain → A-record IPs via dnsx (-duc, D-O7).
	ips := t.resolveIPs(ctx, app, root)
	if len(ips) == 0 {
		if app.Log != nil {
			app.Log.Info("osint.ip_info: no resolved IPs — completed", "findings", 0)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"findings": 0}}, nil
	}

	var records []OSINTFindingRecord

	// Step 2: mapcidr per IP (CIDREnabled gate, D-O8).
	if cfg.OSINT.IPInfo.CIDREnabled {
		for _, ip := range ips {
			if ctx.Err() != nil {
				break
			}
			// v1 arg vector: mapcidr -silent -cidr <ip>/24 (aggregate /24 around the host).
			res, err := app.Tools.Run(ctx, "mapcidr", []string{"-silent", "-aggregate", "-cidr", ip + "/24"})
			if err != nil {
				if app.Log != nil {
					app.Log.Debug("osint.ip_info: mapcidr run failed (best_effort)", "err", err)
				}
				continue
			}
			for _, cidr := range splitNonEmptyLines(res.Stdout) {
				records = append(records, OSINTFindingRecord{
					Severity:    "informational",
					Class:       "osint",
					Source:      "ip_info",
					Category:    "cidr",
					PoCRedacted: cidr,
				})
			}
		}
	}

	// Step 3: asnmap per IP (-duc, ASNEnabled gate, D-O8).
	if cfg.OSINT.IPInfo.ASNEnabled {
		for _, ip := range ips {
			if ctx.Err() != nil {
				break
			}
			// v1 arg vector: asnmap -duc -silent -i <ip>
			res, err := app.Tools.Run(ctx, "asnmap", []string{"-duc", "-silent", "-i", ip})
			if err != nil {
				if app.Log != nil {
					app.Log.Debug("osint.ip_info: asnmap run failed (best_effort)", "err", err)
				}
				continue
			}
			for _, org := range splitNonEmptyLines(res.Stdout) {
				records = append(records, OSINTFindingRecord{
					Severity:    "informational",
					Class:       "osint",
					Source:      "ip_info",
					Category:    "asn",
					PoCRedacted: org,
				})
			}
		}
	}

	// Step 4: ipinfo.io geo per IP + preserve osint/ip_<ip>_whois.txt (D-O5).
	// XCUT-07: PDCP key used only in the Authorization header, never logged.
	pdcpKey := string(cfg.APIKeys.PDCP)
	client := &http.Client{Timeout: 2 * time.Second}
	base := ipInfoBaseURL()
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		body, geoStr := lookupIPInfoGeo(ctx, client, base, pdcpKey, ip, app)
		if geoStr != "" {
			records = append(records, OSINTFindingRecord{
				Severity:    "informational",
				Class:       "osint",
				Source:      "ip_info",
				Category:    "geo",
				PoCRedacted: geoStr,
			})
		}
		// D-O5 single-writer human file: osint/ip_<ip>_whois.txt (raw geo JSON).
		if len(strings.TrimSpace(body)) > 0 {
			whoisFile := filepath.Join(osintDir, "ip_"+sanitizeIPForFilename(ip)+"_whois.txt")
			if wErr := os.WriteFile(whoisFile, []byte(body), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
				app.Log.Debug("osint.ip_info: write ip whois.txt failed", "err", wErr)
			}
		}
	}

	// Step 5: write staging JSONL (multi-writer contract).
	writeOSINTStaging(app, inputsDir, "findings.ip_info.jsonl", records)

	if app.Log != nil {
		app.Log.Info("osint.ip_info: completed", "findings", len(records), "ips", len(ips))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "ips": len(ips)},
	}, nil
}

// resolveIPs runs dnsx -a -resp-only to resolve the root domain to A-record IPs.
// Best_effort: a tool failure returns nil and the caller short-circuits.
func (t *IPInfoTask) resolveIPs(ctx context.Context, app *appctx.AppContext, root string) []string {
	// v1 arg vector: dnsx -duc -silent -a -resp-only -d <domain>
	res, err := app.Tools.Run(ctx, "dnsx", []string{"-duc", "-silent", "-a", "-resp-only", "-d", root})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: dnsx resolve failed (best_effort)", "err", err)
		}
		return nil
	}
	seen := make(map[string]struct{})
	var ips []string
	for _, ip := range splitNonEmptyLines(res.Stdout) {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		ips = append(ips, ip)
	}
	return ips
}

// lookupIPInfoGeo queries ipinfo.io/<ip>/json and returns (rawBody, "city, country, org").
// All responses/errors logged at Debug ONLY (XCUT-07, mirrors subdomains/geo.go).
func lookupIPInfoGeo(ctx context.Context, client *http.Client, baseURL, pdcpKey, ip string, app *appctx.AppContext) (string, string) {
	url := fmt.Sprintf("%s/%s/json", baseURL, ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: geo request build failed", "ip", ip, "err", err)
		}
		return "", ""
	}
	// PDCP key only in header, never logged (XCUT-07).
	if pdcpKey != "" {
		req.Header.Set("Authorization", "Bearer "+pdcpKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: geo request failed", "ip", ip, "err", err)
		}
		return "", ""
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: geo read failed", "ip", ip, "err", err)
		}
		return "", ""
	}
	if app.Log != nil {
		app.Log.Debug("osint.ip_info: geo response", "ip", ip, "status", resp.StatusCode)
	}
	var data struct {
		Org     string `json:"org"`
		Country string `json:"country"`
		City    string `json:"city"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return string(body), ""
	}
	parts := make([]string, 0, 3)
	for _, p := range []string{data.City, data.Country, data.Org} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	return string(body), strings.Join(parts, ", ")
}

// sanitizeIPForFilename replaces filesystem-unsafe characters in an IP literal
// (e.g. IPv6 colons) so it is safe to embed in osint/ip_<ip>_whois.txt.
func sanitizeIPForFilename(ip string) string {
	r := strings.NewReplacer(":", "_", "/", "_", " ", "_")
	return r.Replace(strings.TrimSpace(ip))
}

// init self-registers IPInfoTask with the Default task registry.
func init() { task.Register(&IPInfoTask{}) }
