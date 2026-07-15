// ip_info.go — IPInfoTask: CIDR + ASN org + geo (domain targets) and WHOISXML
// reverse-IP relations + WHOIS + geolocation (IP targets) (OSINT-02 / PAR-03).
//
// TWO TARGET PATHS mirror bash:
//
//   - DOMAIN target: resolve the root domain to its A-record IPs (via dnsx),
//     then run mapcidr for CIDR ranges, asnmap for the ASN org, and an ipinfo.io
//     geo lookup (mirroring subdomains/geo.go's raw http.Client). The ipinfo.io
//     substitution remains for this path.
//   - IP target (v1 ip_info() osint.sh:741 runs ONLY when the target IS an IP):
//     WHOISXML reverse-IP relations + WHOIS + geolocation, key-gated on
//     cfg.APIKeys.WhoisXML. This restored a PAR-03 gap: the Go task previously
//     REJECTED IP-shaped targets (rootDomain reject) and lost the reverse-IP
//     relations entirely.
//
// Each CIDR/ASN/geo/relation datum becomes an OSINTFindingRecord (D-O4) written
// to inputs/findings.ip_info.jsonl per the multi-writer staging contract
// (doc.go — D-O3). Per-IP human files are preserved single-writer (D-O5): the
// domain path writes osint/ip_<ip>_whois.txt; the IP path writes the v1 trio
// osint/ip_<ip>_relations.txt / _whois.txt / _location.txt (osint.sh:755-768).
//
// SEEDING (D-O1): root-domain / IP-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort — every step logs Debug + continues.
// PD TOOLS (D-O7): dnsx + asnmap args include -duc.
//
// SECRET HANDLING (XCUT-07): the PDCP key (cfg.APIKeys.PDCP) is cast to a raw
// string ONLY into the ipinfo.io Authorization header (mirrors subdomains/geo.go:97).
// The WHOISXML key (cfg.APIKeys.WhoisXML) travels ONLY in the outbound HTTPS
// query string of a NATIVE http.Get (never argv / never a subprocess) and is
// registered with the log Redactor so an accidental URL log is scrubbed
// (T-13-05-01); key unset → the WHOISXML path skips with a warning (D-O2).
//
// THREAT MODEL (T-07-02-01): domain/IP strings cross into dnsx/mapcidr/asnmap
// argv via Backend.Run's []string arg-vector (never a shell string).
//
// Source: .planning/phases/07-osint-e2e/07-02-PLAN.md Task 1;
//
//	.planning/phases/13-domain-parity/13-05-PLAN.md Task 3 (WHOISXML restore).
package osint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// Run executes the IP info pipeline, branching on the target shape.
//
// IP target (v1 ip_info() osint.sh:741) → WHOISXML reverse-IP + WHOIS + geo
// (see runWhoisXML). DOMAIN target → the resolve→enrichment pipeline:
//  1. Resolve the root domain → A-record IPs via dnsx (-duc).
//  2. mapcidr per IP → CIDR records (CIDREnabled gate).
//  3. asnmap per IP (-duc) → ASN org records (ASNEnabled gate).
//  4. ipinfo.io geo per IP → geo records; preserve osint/ip_<ip>_whois.txt (D-O5).
//  5. Write inputs/findings.ip_info.jsonl (multi-writer staging).
func (t *IPInfoTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	if app == nil || app.Target == nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}

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

	// IP-target path: WHOISXML reverse-IP relations + WHOIS + geolocation
	// (v1 ip_info() osint.sh:741 runs ONLY when the target IS an IP). This restores
	// the reverse-IP relations + IP-target support the domain-only substitution
	// lost (previously an IP-shaped target was rejected by the rootDomain guard).
	if app.Target.IsIP {
		return t.runWhoisXML(ctx, app, strings.TrimSpace(app.Target.Domain), inputsDir, osintDir)
	}

	// DOMAIN-target path (existing): resolve → mapcidr/asnmap/ipinfo.io enrichment.
	// The ipinfo.io substitution remains for the DOMAIN path; WHOISXML (above)
	// restores the IP-target path bash had.
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.ip_info: no valid root domain or IP target — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	cfg := app.Cfg

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
	// XCUT-07 L2 (IN-13-01): register the PDCP key with the Redactor ONCE before the
	// per-IP loop — mirroring the WHOISXML-key registration in runWhoisXML — so any
	// accidental header/URL log line is scrubbed. Defense-in-depth consistency with
	// the WHOISXML path in this same file.
	if pdcpKey != "" {
		registerSecret(app.Log, pdcpKey)
	}
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

// -------------------------------------------------------------------------
// WHOISXML IP-target path (13-05 Task 3 — v1 ip_info() osint.sh:741-775).
// -------------------------------------------------------------------------

// whoisXMLEndpoints holds the three WHOISXML API base URLs (v1 osint.sh:755-768).
// Overridable via RECONFTW_WHOISXML_BASE_URL for tests (a single httptest server
// serving /reverse-ip, /whois, /geo).
type whoisXMLEndpoints struct {
	reverseIP   string
	whois       string
	geolocation string
}

// whoisXMLEndpointsFor returns the production WHOISXML endpoints, or test
// endpoints derived from RECONFTW_WHOISXML_BASE_URL when set.
func whoisXMLEndpointsFor() whoisXMLEndpoints {
	if base := strings.TrimRight(os.Getenv("RECONFTW_WHOISXML_BASE_URL"), "/"); base != "" {
		return whoisXMLEndpoints{
			reverseIP:   base + "/reverse-ip",
			whois:       base + "/whois",
			geolocation: base + "/geo",
		}
	}
	return whoisXMLEndpoints{
		reverseIP:   "https://reverse-ip.whoisxmlapi.com/api/v1",
		whois:       "https://www.whoisxmlapi.com/whoisserver/WhoisService",
		geolocation: "https://ip-geolocation.whoisxmlapi.com/api/v1",
	}
}

// runWhoisXML restores the v1 ip_info() IP-target path (osint.sh:741-775):
// WHOISXML reverse-IP relations + WHOIS + geolocation on an IP target.
//
// Key-gated on cfg.APIKeys.WhoisXML (D-O2: unset → warning + StatusSkipped).
// XCUT-07 / T-13-05-01: the apiKey travels ONLY in the outbound HTTPS query
// string of a NATIVE http.Get (never argv / never a subprocess), and is
// registered with the Redactor BEFORE any request so an accidental URL log is
// scrubbed; the full URL is never logged. Writes the v1 trio
// osint/ip_<ip>_relations.txt / _whois.txt / _location.txt (single-writer human
// files) and emits the reverse-IP relation names as OSINTFindingRecords →
// inputs/findings.ip_info.jsonl.
func (t *IPInfoTask) runWhoisXML(ctx context.Context, app *appctx.AppContext, ip, inputsDir, osintDir string) (task.Result, error) {
	if ip == "" {
		return task.Result{Status: task.StatusSkipped}, nil
	}
	key := ""
	if app.Cfg != nil {
		key = strings.TrimSpace(string(app.Cfg.APIKeys.WhoisXML))
	}
	if key == "" {
		if app.Log != nil {
			app.Log.Warn("osint.ip_info: WHOISXML_API (cfg.api_keys.whoisxml) not set — skipping IP-target lookups")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// XCUT-07 L2: register the key BEFORE any request/log so any accidental URL
	// log line is scrubbed.
	registerSecret(app.Log, key)

	ep := whoisXMLEndpointsFor()
	client := &http.Client{Timeout: 10 * time.Second}
	fnameIP := sanitizeIPForFilename(ip)
	var records []OSINTFindingRecord

	// 1. Reverse-IP relations → osint/ip_<ip>_relations.txt + findings.
	relations := t.whoisXMLReverseIP(ctx, client, ep.reverseIP, key, ip, app)
	if len(relations) > 0 {
		var b strings.Builder
		for _, name := range relations {
			// v1 sed appends " <ip>" to each relation name (osint.sh:757).
			b.WriteString(name + " " + ip + "\n")
			records = append(records, OSINTFindingRecord{
				Severity:    "informational",
				Class:       "osint",
				Source:      "ip_info",
				Category:    "reverse-ip-relation",
				PoCRedacted: name,
			})
		}
		writeIPInfoTextFile(app, filepath.Join(osintDir, "ip_"+fnameIP+"_relations.txt"), b.String())
	}

	// 2. WHOIS → osint/ip_<ip>_whois.txt (pretty JSON, v1 `jq`, osint.sh:761-763).
	if body := t.whoisXMLGet(ctx, client, ep.whois, url.Values{
		"apiKey":           {key},
		"domainName":       {ip},
		"outputFormat":     {"json"},
		"da":               {"2"},
		"registryRawText":  {"1"},
		"registrarRawText": {"1"},
		"ignoreRawTexts":   {"1"},
	}, "whois", app); len(bytes.TrimSpace(body)) > 0 {
		writeIPInfoTextFile(app, filepath.Join(osintDir, "ip_"+fnameIP+"_whois.txt"), whoisXMLPrettyJSON(body))
	}

	// 3. Geolocation → osint/ip_<ip>_location.txt (v1 `jq -r '.ip,.location'`, osint.sh:766-768).
	if body := t.whoisXMLGet(ctx, client, ep.geolocation, url.Values{
		"apiKey":    {key},
		"ipAddress": {ip},
	}, "geolocation", app); len(bytes.TrimSpace(body)) > 0 {
		writeIPInfoTextFile(app, filepath.Join(osintDir, "ip_"+fnameIP+"_location.txt"), whoisXMLFormatGeo(body))
	}

	writeOSINTStaging(app, inputsDir, "findings.ip_info.jsonl", records)
	if app.Log != nil {
		app.Log.Info("osint.ip_info: completed (WHOISXML IP-target)",
			"ip", ip, "relations", len(relations), "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "relations": len(relations)},
	}, nil
}

// whoisXMLReverseIP performs the reverse-IP GET and returns the deduped relation
// hostnames from the WHOISXML `{"result":[{"name":...}]}` shape (v1 jq
// `.result[].name`). Best_effort: any failure logs Debug and returns nil.
func (t *IPInfoTask) whoisXMLReverseIP(ctx context.Context, client *http.Client, base, key, ip string, app *appctx.AppContext) []string {
	body := t.whoisXMLGet(ctx, client, base, url.Values{"apiKey": {key}, "ip": {ip}}, "reverse-ip", app)
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var data struct {
		Result []struct {
			Name string `json:"name"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: reverse-ip parse failed (best_effort)", "err", err)
		}
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, r := range data.Result {
		name := strings.TrimSpace(r.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

// whoisXMLGet issues a native GET to base with the given query values and returns
// the raw response body (capped at 1 MiB). XCUT-07: the apiKey is ONLY in the
// query string of this native request (never argv); the full URL is NEVER logged
// — only the endpoint label + HTTP status at Debug. Best_effort: any failure logs
// Debug and returns nil.
func (t *IPInfoTask) whoisXMLGet(ctx context.Context, client *http.Client, base string, q url.Values, label string, app *appctx.AppContext) []byte {
	full := base + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: whoisxml request build failed", "endpoint", label, "err", err)
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: whoisxml request failed", "endpoint", label, "err", err)
		}
		return nil
	}
	defer resp.Body.Close() //nolint:errcheck
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.ip_info: whoisxml read failed", "endpoint", label, "err", err)
		}
		return nil
	}
	if app.Log != nil {
		// XCUT-07: log ONLY the endpoint label + status, NEVER the full URL (carries the key).
		app.Log.Debug("osint.ip_info: whoisxml response", "endpoint", label, "status", resp.StatusCode)
	}
	return body
}

// whoisXMLPrettyJSON pretty-prints a JSON body (v1 `jq`), falling back to the raw
// body when it is not valid JSON.
func whoisXMLPrettyJSON(body []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, body, "", "  "); err != nil {
		return string(body)
	}
	return buf.String()
}

// whoisXMLFormatGeo formats a geolocation body as the v1 `jq -r '.ip,.location'`
// output: the ip on the first line, then the location object. Falls back to the
// raw body when it is not the expected shape.
func whoisXMLFormatGeo(body []byte) string {
	var data struct {
		IP       string          `json:"ip"`
		Location json.RawMessage `json:"location"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return string(body)
	}
	var b strings.Builder
	if data.IP != "" {
		b.WriteString(data.IP + "\n")
	}
	if loc := bytes.TrimSpace(data.Location); len(loc) > 0 {
		b.Write(loc)
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		return string(body)
	}
	return b.String()
}

// writeIPInfoTextFile writes a single-writer human file (D-O5) under osint/,
// logging at Debug on error (best_effort). A no-op for empty content.
func writeIPInfoTextFile(app *appctx.AppContext, path, content string) {
	if strings.TrimSpace(content) == "" {
		return
	}
	if wErr := os.WriteFile(path, []byte(content), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
		app.Log.Debug("osint.ip_info: write human file failed", "file", filepath.Base(path), "err", wErr)
	}
}
