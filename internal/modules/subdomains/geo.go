// geo.go — SubGeoTask: per-subdomain geo enrichment via ipinfo.io HTTP API.
//
// PDCP SECRET REGISTRATION (W2 fix):
// app.Log.RegisterSecret is not available on *slog.Logger. Instead, we guard
// the PDCP key by: (1) ensuring it is ONLY used in HTTP request headers after
// being read from cfg.APIKeys.PDCP; (2) ALL ipinfo.io responses are logged at
// Debug level ONLY — never Info/Warn/Error; (3) the key value is never
// interpolated into log messages.
//
// NOTE: In production, cfg.APIKeys.PDCP is a log.Secret type which auto-redacts
// in structured log output (Layer 1 ADR §10). The Redactor.Register() call for
// Layer 2 is performed at Boot time (Plan 06 main.go) per ADR §10.3 build order.
// This Task does not need to call RegisterSecret again — it is already registered
// by the time any Task.Run is invoked.
//
// SubGeoTask.Enabled uses cfg.Subdomains.Enabled (parent flag). There is NO
// cfg.Subdomains.Geo struct — per doc.go W5 note.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md Task 2.
package subdomains

import (
	"bufio"
	"bytes"
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

// ipinfoBaseURL is the base URL for ipinfo.io API calls.
// Overridable via RECONFTW_IPINFO_BASE_URL environment variable for testing.
const defaultIPInfoBaseURL = "https://ipinfo.io"

func ipinfoBaseURL() string {
	if u := os.Getenv("RECONFTW_IPINFO_BASE_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return defaultIPInfoBaseURL
}

// SubGeoTask enriches resolved subdomains with geo data (City, Country, ASN)
// via ipinfo.io HTTP API. Writes HostRecord JSONL to artefacts/hosts.jsonl
// via single direct app.Tree.Append (only writer for "hosts" artefact).
//
// Enabled: returns cfg.Subdomains.Enabled (parent flag — no separate Geo flag).
type SubGeoTask struct{}

// Name returns the task identifier.
func (SubGeoTask) Name() string { return "subdomains.geo" }

// Module returns the owning module.
func (SubGeoTask) Module() string { return "subdomains" }

// Description returns a short description.
func (SubGeoTask) Description() string {
	return "Per-subdomain geo enrichment (City+Country+ASN) via ipinfo.io HTTP API"
}

// Enabled returns cfg.Subdomains.Enabled — geo always runs when the subdomains
// module is enabled. There is NO separate Geo flag (doc.go W5 invariant).
func (SubGeoTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (SubGeoTask) DependsOn() []string { return nil }

// geoResult caches ipinfo.io lookup results per IP.
type geoResult struct {
	ASN     string
	Country string
	City    string
}

// Run executes the geo enrichment pipeline:
//  1. Run httpx to get IP per subdomain.
//  2. For each unique IP, query ipinfo.io (with IP dedup cache).
//  3. Construct HostRecord{Host, IP, ASN, Country, City} per subdomain.
//  4. Call app.Tree.Append("hosts", records) once (single writer).
//
// PDCP key is only used in HTTP Authorization header, not in any log output.
// All ipinfo.io responses are logged at Debug level only (W2 fix).
func (SubGeoTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "httpx"
	cfg := app.Cfg

	// W2 fix: The PDCP key is already registered as a secret at Boot time
	// (ADR §10.3). We do NOT log it here. We use it only in the HTTP
	// Authorization header constructed below, never in any log.* call.
	pdcpKey := string(cfg.APIKeys.PDCP)

	resolvedFile := filepath.Join(app.Target.WorkDir, "inputs", "resolved.merged.txt")

	// Step 1: httpx to get IP per subdomain.
	httpxArgs := []string{
		"-l", resolvedFile,
		"-ip",
		"-json",
		"-silent",
	}

	res, err := app.Tools.Run(ctx, toolName, httpxArgs)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("geo: httpx run failed or tool not registered",
				"tool", toolName, "err", err.Error())
		}
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"hosts_enriched": 0},
		}, nil
	}

	// Parse httpx JSON output.
	// httpx -ip -json emits: {"host":"api.example.com","ip":"1.2.3.4",...}
	type httpxEntry struct {
		Host string `json:"host"`
		IP   string `json:"ip"`
	}

	var entries []httpxEntry
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e httpxEntry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		if e.Host == "" || e.IP == "" {
			continue
		}
		entries = append(entries, e)
	}

	// Step 2: query ipinfo.io per unique IP (dedup cache).
	geoCache := make(map[string]geoResult)
	httpClient := &http.Client{Timeout: 2 * time.Second}
	base := ipinfoBaseURL()

	uniqueIPs := make(map[string]struct{})
	for _, e := range entries {
		uniqueIPs[e.IP] = struct{}{}
	}

	// Rate-limit: sleep 100ms between requests when > 100 unique IPs.
	ipCount := 0
	for ip := range uniqueIPs {
		if ctx.Err() != nil {
			break
		}
		geo := lookupIPInfo(ctx, httpClient, base, pdcpKey, ip, app)
		geoCache[ip] = geo
		ipCount++
		if len(uniqueIPs) > 100 && ipCount%10 == 0 {
			// Brief sleep to respect free-tier rate limits.
			select {
			case <-ctx.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	// Step 3: build HostRecord per subdomain.
	var records [][]byte
	for _, e := range entries {
		geo := geoCache[e.IP]
		rec := HostRecord{
			Host:    e.Host,
			IP:      e.IP,
			ASN:     geo.ASN,
			Country: geo.Country,
			City:    geo.City,
		}
		encoded, encErr := json.Marshal(rec)
		if encErr != nil {
			continue
		}
		records = append(records, encoded)
	}

	// Step 4: direct Append, GUARDED — this task must NOT empty-publish.
	//
	// The comment that used to sit here asserted this task was the sole writer
	// of the "hosts" artefact. That was FALSE, and it was load-bearing in the
	// wrong direction. There are TWO direct writers of artefacts/hosts.jsonl:
	// this one and web/httpx.go, which additionally passes the artefact itself
	// as its httpx -o target.
	//
	// The real ordering, verified on the tree: subdomains.geo runs in the
	// "subs-enrichment" stage group, the LAST subdomains group, and web.httpx
	// runs in "web-probe", the FIRST web group, with webStageGroups() appended
	// after the subs groups (internal/mcp/handlers/composite.go). geo therefore
	// runs strictly BEFORE httpx, and because Tree.Append REPLACES rather than
	// appends, geo's ASN/country/city enrichment does not survive httpx in any
	// run that probes. (That loss is a pre-existing defect, out of scope for the
	// F3 work in phase 15 and recorded rather than silently fixed here.)
	//
	// Consequence for F3: httpx (web/httpx.go) is the authoritative "hosts"
	// writer and owns the empty publish. geo KEEPS this len(records) > 0 guard,
	// because in a subs-only or passive run httpx never runs, and an empty
	// publish from geo would erase a previous web run's hosts that no producer
	// in this run ever looked at — strictly worse than leaving them.
	if len(records) > 0 {
		if err := app.Tree.Append("hosts", records); err != nil {
			if app.Log != nil {
				app.Log.Debug("geo: Tree.Append(hosts) failed",
					"err", err.Error(), "records", len(records))
			}
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("geo: Tree.Append(hosts): %w", err)
		}
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"hosts_enriched": len(records)},
	}, nil
}

// lookupIPInfo queries ipinfo.io/{ip}/json and returns a geoResult.
// Uses pdcpKey in the Authorization header if non-empty.
// ALL responses and errors logged at Debug level ONLY (W2 fix).
func lookupIPInfo(ctx context.Context, client *http.Client, baseURL, pdcpKey, ip string, app *appctx.AppContext) geoResult {
	url := fmt.Sprintf("%s/%s/json", baseURL, ip)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("geo: ipinfo request build failed", "ip", ip, "err", err.Error())
		}
		return geoResult{}
	}

	// PDCP key used only in Authorization header (W2 fix: never logged).
	if pdcpKey != "" {
		req.Header.Set("Authorization", "Bearer "+pdcpKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		if app.Log != nil {
			// Log at Debug ONLY — response may contain key traces (W2 fix).
			app.Log.Debug("geo: ipinfo request failed", "ip", ip, "err", err.Error())
		}
		return geoResult{}
	}
	defer resp.Body.Close() //nolint:errcheck // read/cleanup path

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("geo: ipinfo response read failed", "ip", ip, "err", err.Error())
		}
		return geoResult{}
	}

	// Log response body at Debug ONLY (W2 fix — never Info/Warn/Error).
	if app.Log != nil {
		app.Log.Debug("geo: ipinfo response", "ip", ip, "status", resp.StatusCode)
	}

	var data struct {
		Org     string `json:"org"`     // e.g. "AS15133 Edgecast Inc."
		Country string `json:"country"` // e.g. "US"
		City    string `json:"city"`    // e.g. "Norwell"
	}
	if err := json.Unmarshal(body, &data); err != nil {
		if app.Log != nil {
			app.Log.Debug("geo: ipinfo parse failed", "ip", ip, "err", err.Error())
		}
		return geoResult{}
	}

	return geoResult{
		ASN:     data.Org,
		Country: data.Country,
		City:    data.City,
	}
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(SubGeoTask{}) }
