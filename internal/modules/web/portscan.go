// portscan.go — WebPortscanTask: active-recon port scanning (PAR-04).
//
// Name: "web.portscan"  DependsOn: nil (sequential stage; reads workspace files)
//
// This task closes the biggest web parity gap: active port scanning was
// entirely MISSING in v2. The cfg.Web.Portscan config (config.go:338,
// WebNaabu :351, WebServiceFingerprint :357, defaults.go:156) was fully
// scaffolded but read by ZERO tasks — naabu, nmap, and nerva were never
// invoked. WebPortscanTask reads that previously-dead config and ports the
// bash portscan + service_fingerprint flow (modules/web.sh:600-923):
//
//	IP-seed (subdomains/subdomains_ips.txt, 13-01) → cdncheck CDN filter →
//	passive (smap + shodan internetdb) → active (naabu discovers ports →
//	nmap targeted service scan) → nmapurls feedback → nerva fingerprint.
//
// It produces the standard host artefacts AND hosts/portscan_active.gnmap
// (the spray input PAR-02/13-07 depends on) plus the nerva fingerprint
// output. hakoriginfinder (CDN bypass) + cdncheck already exist as Go
// tasks/tools — this task REUSES their output, it does NOT re-implement them.
//
// PRIVILEGE NOTE (T-13-03-01): the active nmap SYN scan needs root/setcap
// (Docker setcap for naabu/nmap added in Phase 11). On an unprivileged host
// the ACTIVE path degrades (StatusDone + warning); the PASSIVE path (smap +
// shodan internetdb) works without privileges and is the default-safe target.
// A missing tool NEVER fails the web pipeline (D-O2 opportunistic).
//
// WIRING NOTE: this file IMPLEMENTS WebPortscanTask (self-registered) but does
// NOT edit stage lists — plan 13-08 adds a "web.portscan" stage to
// web.go/composite.go/stub_subcommands.go and wires web.MergeStage(ctx, app,
// "hosts") after it so the HostRecord staging files reach the store.
//
// Source: .planning/phases/13-domain-parity/13-03-PLAN.md Task 1 + Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// portscanHostPort is a single open host:port result (ip + numeric port).
type portscanHostPort struct {
	ip   string
	port string
}

// shodanHTTPClient is the bounded client for the keyless shodan internetdb
// GET (XCUT-07: no secret — the IP is the scan target, not sensitive).
var shodanHTTPClient = &http.Client{Timeout: 15 * time.Second}

// shodanInternetDBGet fetches https://internetdb.shodan.io/<ip>. It is a
// package var so unit tests can inject a canned response WITHOUT real network
// I/O (mirrors 13-01's hakip2hostRunner seam). Best-effort: a per-IP error is
// swallowed by the caller.
var shodanInternetDBGet = func(ctx context.Context, ip string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://internetdb.shodan.io/"+ip, nil)
	if err != nil {
		return nil, err
	}
	resp, err := shodanHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// WebPortscanTask does passive + active port scanning from the subdomains_ips
// seed, producing the gnmap that spraying consumes plus a nerva fingerprint.
type WebPortscanTask struct{}

func (t *WebPortscanTask) Name() string   { return "web.portscan" }
func (t *WebPortscanTask) Module() string { return "web" }
func (t *WebPortscanTask) Description() string {
	return "Port scan (passive smap/shodan + active naabu→nmap + nerva fingerprint)"
}
func (t *WebPortscanTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Portscan.Enabled
}

// DependsOn returns nil: portscan is a sequential stage that reads workspace
// files (subdomains/subdomains_ips.txt, hosts/cdn_providers.txt,
// hosts/origin_ips.txt); plan 13-08 places it in the stage order.
func (t *WebPortscanTask) DependsOn() []string { return nil }

// Run implements the bash portscan flow (web.sh:600-817) via app.Tools.
func (t *WebPortscanTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	ps := app.Cfg.Web.Portscan
	workDir := app.Target.WorkDir
	hostsDir := filepath.Join(workDir, "hosts")
	tmpDir := filepath.Join(workDir, ".tmp")
	for _, d := range []string{hostsDir, tmpDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("web.portscan: mkdir %s: %w", d, err)
		}
	}

	// 1. IP-seed from subdomains/subdomains_ips.txt (13-01) + IP-literal target.
	ips := portscanReadIPSeed(app)
	if len(ips) == 0 {
		if app.Log != nil {
			app.Log.Info("web.portscan: no IP seed (subdomains_ips.txt empty / no IP target) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	ipsFile := filepath.Join(hostsDir, "ips.txt")
	_ = os.WriteFile(ipsFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644) //nolint:gosec,errcheck

	// 2. CDN filter → non-CDN IP set (comm -23 equivalent).
	ipsNoCDN := append([]string(nil), ips...)
	if ps.CDNCheck {
		cdnIPs := portscanCDNIPs(ctx, app, ips, hostsDir)
		ipsNoCDN = portscanSubtract(ips, cdnIPs)
	}
	// 2b. Optional CDN bypass: fold origin IPs recovered by web.hakoriginfinder
	// (do NOT re-run it — consume its output if present).
	if ps.CDNBypass {
		if origins := portscanOriginIPs(app); len(origins) > 0 {
			ipsNoCDN = portscanUnion(ipsNoCDN, origins)
			ips = portscanUnion(ips, origins)
			_ = os.WriteFile(ipsFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644) //nolint:gosec,errcheck
		}
	}
	ipsNoCDNFile := filepath.Join(tmpDir, "ips_nocdn.txt")
	_ = os.WriteFile(ipsNoCDNFile, []byte(strings.Join(ipsNoCDN, "\n")+"\n"), 0o644) //nolint:gosec,errcheck
	if app.Log != nil {
		app.Log.Debug("web.portscan: resolved IPs", "total", len(ips), "no_cdn", len(ipsNoCDN))
	}

	// 3. Passive (unprivileged): smap + shodan internetdb.
	if ps.PassiveEnabled {
		portscanPassiveSmap(ctx, app, ipsNoCDN, ipsNoCDNFile, hostsDir)
		portscanPassiveShodan(ctx, app, ips, hostsDir)
	}

	// 4. Active (naabu→nmap or legacy nmap). Degrades on missing tool/privilege.
	var openPorts []portscanHostPort
	if ps.ActiveEnabled {
		openPorts = portscanActive(ctx, app, ps, ipsNoCDN, ipsNoCDNFile, hostsDir)
	}

	// 5. nmapurls feedback: derive web URLs from the nmap XML and feed them back
	// into the web target set so downstream web tasks see port-scan services.
	portscanNmapURLsFeedback(app, hostsDir)

	// 6. Emit HostRecord JSONL (open host:port) to the "hosts" staging file so it
	// reaches the store via web.MergeStage(ctx, app, "hosts") (wired in 13-08).
	portscanWriteHostRecords(app, openPorts, "portscan")

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"ips": len(ips), "ips_no_cdn": len(ipsNoCDN), "open_ports": len(openPorts)},
	}, nil
}

// -------------------------------------------------------------------------
// IP seed
// -------------------------------------------------------------------------

// portscanReadIPSeed extracts the public-IPv4 seed from
// subdomains/subdomains_ips.txt ("host - ip", bash `cut -d ' ' -f3`) plus the
// target itself when it is an IP literal. Private/reserved ranges are dropped.
func portscanReadIPSeed(app *appctx.AppContext) []string {
	seen := make(map[string]bool)
	var ips []string
	add := func(cand string) {
		cand = strings.TrimSpace(cand)
		if cand == "" || seen[cand] || !portscanIsPublicIPv4(cand) {
			return
		}
		seen[cand] = true
		ips = append(ips, cand)
	}

	if app.Target != nil && app.Target.IsIP {
		add(app.Target.Domain)
	}

	path := filepath.Join(app.Target.WorkDir, "subdomains", "subdomains_ips.txt")
	f, err := os.Open(path) //nolint:gosec // path within WorkDir
	if err != nil {
		return ips
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		switch {
		case len(fields) >= 3:
			add(fields[2]) // bash `cut -d ' ' -f3`
		case len(fields) == 1:
			add(fields[0]) // bare-IP line
		}
	}
	return ips
}

// portscanIsPublicIPv4 reports whether s is a routable public IPv4 address.
// Mirrors the bash grep-out of 127/10/169.254/172.16-31/192.168 ranges.
func portscanIsPublicIPv4(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false // not IPv4 (bash portscan seeds IPv4 only)
	}
	if ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsLinkLocalUnicast() ||
		ip4.IsLinkLocalMulticast() || ip4.IsUnspecified() {
		return false
	}
	return true
}

// -------------------------------------------------------------------------
// CDN filter
// -------------------------------------------------------------------------

// portscanCDNIPs returns the set of CDN/WAF IPs to exclude from active scanning.
// It reuses hosts/cdn_providers.txt if present, else invokes cdncheck. On any
// error it returns an empty set (fail-open: scan all IPs, matching bash comm).
func portscanCDNIPs(ctx context.Context, app *appctx.AppContext, ips []string, hostsDir string) map[string]bool {
	cdn := make(map[string]bool)

	cdnFile := filepath.Join(hostsDir, "cdn_providers.txt")
	if data, err := os.ReadFile(cdnFile); err == nil && len(bytes.TrimSpace(data)) > 0 { //nolint:gosec
		for _, ip := range portscanParseCDNLines(data) {
			cdn[ip] = true
		}
		return cdn
	}

	// Run cdncheck: cdncheck -silent -resp -cdn -waf -nc -i <ips_file>.
	ipsFile := filepath.Join(app.Target.WorkDir, "inputs", "portscan.cdncheck.ips.txt")
	if err := os.MkdirAll(filepath.Dir(ipsFile), 0o755); err != nil {
		return cdn
	}
	if err := os.WriteFile(ipsFile, []byte(strings.Join(ips, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return cdn
	}
	args := []string{"-silent", "-resp", "-cdn", "-waf", "-nc", "-i", ipsFile}
	res, err := app.Tools.Run(ctx, "cdncheck", args)
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.portscan: cdncheck absent/failed — scanning all IPs", "err", err)
		}
		return cdn
	}
	if res != nil && len(res.Stdout) > 0 {
		// Persist the bash-contract file for downstream reuse.
		_ = os.WriteFile(cdnFile, res.Stdout, 0o644) //nolint:gosec,errcheck
		for _, ip := range portscanParseCDNLines(res.Stdout) {
			cdn[ip] = true
		}
	}
	return cdn
}

// portscanParseCDNLines extracts the leading IP from cdncheck -resp lines of the
// form "1.2.3.4 [cloudflare]" (bash `cut -d'[' -f1`).
func portscanParseCDNLines(data []byte) []string {
	var out []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.IndexByte(line, '['); idx >= 0 {
			line = line[:idx]
		}
		if f := strings.Fields(line); len(f) > 0 {
			if net.ParseIP(f[0]) != nil {
				out = append(out, f[0])
			}
		}
	}
	return out
}

// portscanOriginIPs consumes origin IPs recovered by web.hakoriginfinder. It
// reads hosts/origin_ips.txt (bash-contract) if present, else falls back to the
// origin_ip fields of artefacts/origins.jsonl (what the Go task actually writes).
func portscanOriginIPs(app *appctx.AppContext) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(ip string) {
		ip = strings.TrimSpace(ip)
		if ip != "" && !seen[ip] && portscanIsPublicIPv4(ip) {
			seen[ip] = true
			out = append(out, ip)
		}
	}

	txt := filepath.Join(app.Target.WorkDir, "hosts", "origin_ips.txt")
	if data, err := os.ReadFile(txt); err == nil { //nolint:gosec
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			add(scanner.Text())
		}
		if len(out) > 0 {
			return out
		}
	}

	jsonl := filepath.Join(app.Target.WorkDir, "artefacts", "origins.jsonl")
	f, err := os.Open(jsonl) //nolint:gosec
	if err != nil {
		return out
	}
	defer f.Close() //nolint:errcheck
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var rec struct {
			OriginIP string `json:"origin_ip"`
		}
		if json.Unmarshal(scanner.Bytes(), &rec) == nil {
			add(rec.OriginIP)
		}
	}
	return out
}

// -------------------------------------------------------------------------
// Passive
// -------------------------------------------------------------------------

// portscanPassiveSmap runs `smap -iL <ips_nocdn>` and writes stdout to
// hosts/portscan_passive.txt. Best-effort: a missing smap logs and returns.
func portscanPassiveSmap(ctx context.Context, app *appctx.AppContext, ipsNoCDN []string, ipsNoCDNFile, hostsDir string) {
	if len(ipsNoCDN) == 0 {
		return
	}
	res, err := app.Tools.Run(ctx, "smap", []string{"-iL", ipsNoCDNFile})
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.portscan: smap absent/failed — skipping passive scan", "err", err)
		}
		return
	}
	if res != nil {
		_ = os.WriteFile(filepath.Join(hostsDir, "portscan_passive.txt"), res.Stdout, 0o644) //nolint:gosec,errcheck
	}
}

// portscanPassiveShodan GETs https://internetdb.shodan.io/<ip> per IP and writes
// the JSON array to hosts/portscan_shodan.txt (bash PORTSCAN_PASSIVE, keyless).
func portscanPassiveShodan(ctx context.Context, app *appctx.AppContext, ips []string, hostsDir string) {
	if len(ips) == 0 || shodanInternetDBGet == nil {
		return
	}
	var parts []string
	for _, ip := range ips {
		body, err := shodanInternetDBGet(ctx, ip)
		if err != nil {
			if app.Log != nil {
				app.Log.Debug("web.portscan: shodan internetdb fetch failed", "ip", ip, "err", err)
			}
			continue
		}
		parts = append(parts, strings.ReplaceAll(strings.TrimSpace(string(body)), "\n", ""))
	}
	if len(parts) == 0 {
		return
	}
	out := "[" + strings.Join(parts, ", ") + "]"
	_ = os.WriteFile(filepath.Join(hostsDir, "portscan_shodan.txt"), []byte(out), 0o644) //nolint:gosec,errcheck
}

// -------------------------------------------------------------------------
// Active
// -------------------------------------------------------------------------

// portscanActive runs the naabu_nmap strategy (naabu discovers ports → nmap
// targeted service scan) or the legacy plain-nmap fallback. It returns the open
// host:port pairs discovered (naabu output or nmap gnmap). Missing tools /
// insufficient privilege degrade gracefully — never StatusErrored.
func portscanActive(ctx context.Context, app *appctx.AppContext, ps config.WebPortscan, ipsNoCDN []string, ipsNoCDNFile, hostsDir string) []portscanHostPort {
	if len(ipsNoCDN) == 0 {
		return nil
	}
	var openPorts []portscanHostPort
	usedTargeted := false

	if ps.Strategy == "naabu_nmap" && ps.Naabu.Enabled {
		naabuOpen := filepath.Join(hostsDir, "naabu_open.txt")
		args := []string{"-list", ipsNoCDNFile, "-silent", "-rate", strconv.Itoa(ps.Naabu.Rate)}
		// Naabu.Ports is a multi-token string ("--top-ports 1000") — split into
		// argv, NEVER pass as a single arg (T-13-03-02).
		args = append(args, strings.Fields(ps.Naabu.Ports)...)
		// -duc: disable-update-check — PD-tool hang guard on blocked DNS (T-13-03-03).
		args = append(args, "-duc", "-o", naabuOpen)

		res, err := app.Tools.Run(ctx, "naabu", args)
		if err != nil {
			if app.Log != nil {
				app.Log.Info("web.portscan: naabu absent/failed — falling back to legacy nmap", "err", err)
			}
		} else {
			raw := portscanReadOrStdout(naabuOpen, res)
			// Ensure the bash-contract file exists even when the backend streamed
			// to stdout (nerva + spray read hosts/naabu_open.txt).
			if info, statErr := os.Stat(naabuOpen); (statErr != nil || info.Size() == 0) && len(bytes.TrimSpace(raw)) > 0 {
				_ = os.WriteFile(naabuOpen, raw, 0o644) //nolint:gosec,errcheck
			}
			openPorts = portscanParseNaabuOpen(raw)
			if csv := portscanPortsCSV(openPorts); csv != "" {
				targetedBase := filepath.Join(hostsDir, "portscan_active_targeted")
				nmapArgs := []string{"-p", csv, "-iL", ipsNoCDNFile, "-oA", targetedBase}
				if _, nerr := app.Tools.Run(ctx, "nmap", nmapArgs); nerr != nil {
					if app.Log != nil {
						app.Log.Info("web.portscan: nmap targeted scan failed (privilege/absent) — degrading", "err", nerr)
					}
				} else {
					usedTargeted = true
					portscanCopyTargetedOutputs(hostsDir)
				}
			}
		}
	}

	// Legacy fallback: plain nmap over the non-CDN IPs.
	if !usedTargeted {
		base := filepath.Join(hostsDir, "portscan_active")
		if _, err := app.Tools.Run(ctx, "nmap", []string{"-iL", ipsNoCDNFile, "-oA", base}); err != nil {
			if app.Log != nil {
				app.Log.Info("web.portscan: legacy nmap failed (privilege/absent) — degrading", "err", err)
			}
		}
	}

	// Merge open ports parsed from the nmap gnmap (covers the legacy path where
	// there is no naabu output).
	if gnmap, err := os.ReadFile(filepath.Join(hostsDir, "portscan_active.gnmap")); err == nil { //nolint:gosec
		openPorts = portscanMergeHostPorts(openPorts, portscanParseGnmap(gnmap))
	}
	return openPorts
}

// portscanReadOrStdout returns the -o file contents when present+non-empty,
// else the buffered stdout (favirecon.go precedent for backend stubs).
func portscanReadOrStdout(path string, res *backend.Result) []byte {
	if data, err := os.ReadFile(path); err == nil && len(bytes.TrimSpace(data)) > 0 { //nolint:gosec
		return data
	}
	if res != nil && len(res.Stdout) > 0 {
		return res.Stdout
	}
	return nil
}

// portscanParseNaabuOpen parses naabu "ip:port" lines into host:port pairs.
func portscanParseNaabuOpen(raw []byte) []portscanHostPort {
	var out []portscanHostPort
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		idx := strings.LastIndexByte(line, ':')
		if idx <= 0 || idx == len(line)-1 {
			continue
		}
		ip, port := line[:idx], line[idx+1:]
		if _, err := strconv.Atoi(port); err != nil {
			continue
		}
		out = append(out, portscanHostPort{ip: ip, port: port})
	}
	return out
}

// portscanPortsCSV returns a sorted, unique, comma-joined port list (bash
// `cut -d':' -f2 | sort -un | paste -sd, -`).
func portscanPortsCSV(pairs []portscanHostPort) string {
	seen := make(map[int]bool)
	var ports []int
	for _, p := range pairs {
		n, err := strconv.Atoi(p.port)
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		ports = append(ports, n)
	}
	sort.Ints(ports)
	strs := make([]string, len(ports))
	for i, n := range ports {
		strs[i] = strconv.Itoa(n)
	}
	return strings.Join(strs, ",")
}

// portscanCopyTargetedOutputs copies portscan_active_targeted.{xml,gnmap,nmap}
// to the portscan_active.* compatibility names (bash web.sh:783-787) so the
// spray chain + nmapurls feedback find the canonical filenames.
func portscanCopyTargetedOutputs(hostsDir string) {
	for _, ext := range []string{"xml", "gnmap", "nmap"} {
		src := filepath.Join(hostsDir, "portscan_active_targeted."+ext)
		dst := filepath.Join(hostsDir, "portscan_active."+ext)
		data, err := os.ReadFile(src) //nolint:gosec
		if err != nil || len(data) == 0 {
			continue
		}
		if info, err := os.Stat(dst); err == nil && info.Size() > 0 {
			continue // do not clobber an existing canonical output
		}
		_ = os.WriteFile(dst, data, 0o644) //nolint:gosec,errcheck
	}
}

// -------------------------------------------------------------------------
// nmapurls feedback (native nmap-XML parse — nmapurls is stdin-only)
// -------------------------------------------------------------------------

// portscanNmapURLsFeedback parses hosts/portscan_active.xml for open web
// services and appends the derived URLs to hosts/webs.txt AND the web target
// set webs/webs.txt (bash `nmapurls < xml | anew`). Native XML parsing replaces
// the stdin-only nmapurls binary (app.Tools has no stdin seam), mirroring the
// keyless-HTTP treatment of shodan internetdb.
func portscanNmapURLsFeedback(app *appctx.AppContext, hostsDir string) {
	xmlPath := filepath.Join(hostsDir, "portscan_active.xml")
	data, err := os.ReadFile(xmlPath) //nolint:gosec
	if err != nil || len(data) == 0 {
		return
	}
	urls := portscanNmapXMLURLs(data)
	if len(urls) == 0 {
		return
	}
	// hosts/webs.txt (dedup append).
	portscanAppendLines(filepath.Join(hostsDir, "webs.txt"), urls)
	// Feed back into the web target set webs/webs.txt.
	websDir := filepath.Join(app.Target.WorkDir, "webs")
	if err := os.MkdirAll(websDir, 0o755); err == nil {
		portscanAppendLines(filepath.Join(websDir, "webs.txt"), urls)
	}
	if app.Log != nil {
		app.Log.Debug("web.portscan: nmapurls feedback", "urls", len(urls))
	}
}

// nmapXMLRun is the minimal nmap -oX schema needed to derive web URLs.
type nmapXMLRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
			Type string `xml:"addrtype,attr"`
		} `xml:"address"`
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name   string `xml:"name,attr"`
					Tunnel string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// portscanNmapXMLURLs derives scheme://ip:port URLs for open http/https services
// (replicates nmapurls). https when the service name/tunnel is TLS-ish or the
// port is 443/8443; http otherwise.
func portscanNmapXMLURLs(data []byte) []string {
	var run nmapXMLRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil
	}
	seen := make(map[string]bool)
	var urls []string
	for _, h := range run.Hosts {
		addr := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" {
				addr = a.Addr
				break
			}
			if addr == "" {
				addr = a.Addr
			}
		}
		if addr == "" {
			continue
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" || p.Protocol != "tcp" {
				continue
			}
			name := strings.ToLower(p.Service.Name)
			isHTTPS := p.Service.Tunnel == "ssl" || strings.Contains(name, "https") ||
				p.PortID == "443" || p.PortID == "8443"
			isHTTP := isHTTPS || strings.Contains(name, "http")
			if !isHTTP {
				continue
			}
			scheme := "http"
			if isHTTPS {
				scheme = "https"
			}
			u := scheme + "://" + addr + ":" + p.PortID
			if !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}
	return urls
}

// -------------------------------------------------------------------------
// HostRecord staging (open host:port → store via web.MergeStage "hosts")
// -------------------------------------------------------------------------

// portscanWriteHostRecords writes the open host:port results as HostRecord JSONL
// to inputs/hosts.<producer>.jsonl (the web "hosts" single-writer staging file);
// plan 13-08 wires web.MergeStage(ctx, app, "hosts") to consolidate to the store.
func portscanWriteHostRecords(app *appctx.AppContext, pairs []portscanHostPort, producer string) {
	if len(pairs) == 0 {
		return
	}
	var lines [][]byte
	for _, p := range pairs {
		rec := HostRecord{Host: p.ip, IP: p.ip, Port: p.port}
		if b, err := json.Marshal(rec); err == nil {
			lines = append(lines, b)
		}
	}
	if len(lines) == 0 {
		return
	}
	staging := filepath.Join(app.Target.WorkDir, "inputs", "hosts."+producer+".jsonl")
	if err := output.WriteJSONL(staging, lines); err != nil && app.Log != nil {
		app.Log.Debug("web.portscan: hosts staging write failed", "path", staging, "err", err)
	}
}

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

// portscanSubtract returns the elements of a not present in the b set.
func portscanSubtract(a []string, b map[string]bool) []string {
	var out []string
	for _, x := range a {
		if !b[x] {
			out = append(out, x)
		}
	}
	return out
}

// portscanUnion appends extras to base, preserving order and dropping dups.
func portscanUnion(base, extras []string) []string {
	seen := make(map[string]bool, len(base))
	out := make([]string, 0, len(base)+len(extras))
	for _, x := range base {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	for _, x := range extras {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// portscanMergeHostPorts merges two host:port slices, dropping ip:port dups.
func portscanMergeHostPorts(a, b []portscanHostPort) []portscanHostPort {
	seen := make(map[string]bool)
	var out []portscanHostPort
	for _, p := range append(append([]portscanHostPort(nil), a...), b...) {
		key := p.ip + ":" + p.port
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}

// portscanParseGnmap ports bash _build_service_fp_targets_from_nmap: extracts
// open host:port pairs from an nmap .gnmap file ("Host: <ip> ... Ports:
// <port>/open/tcp/...").
func portscanParseGnmap(data []byte) []portscanHostPort {
	var out []portscanHostPort
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Host: ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		host := fields[1]
		idx := strings.Index(line, "Ports: ")
		if idx < 0 {
			continue
		}
		portsSection := line[idx+len("Ports: "):]
		if tab := strings.IndexByte(portsSection, '\t'); tab >= 0 {
			portsSection = portsSection[:tab]
		}
		for _, entry := range strings.Split(portsSection, ",") {
			parts := strings.Split(strings.TrimSpace(entry), "/")
			if len(parts) < 2 || parts[1] != "open" {
				continue
			}
			if _, err := strconv.Atoi(parts[0]); err != nil {
				continue
			}
			out = append(out, portscanHostPort{ip: host, port: parts[0]})
		}
	}
	return out
}

// portscanAppendLines appends new lines to path, deduplicating against existing
// content (bash `anew -q`).
func portscanAppendLines(path string, lines []string) {
	existing := make(map[string]bool)
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec
		s := bufio.NewScanner(bytes.NewReader(data))
		for s.Scan() {
			existing[strings.TrimSpace(s.Text())] = true
		}
	}
	var buf bytes.Buffer
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec
		buf.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
	}
	added := false
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || existing[l] {
			continue
		}
		existing[l] = true
		buf.WriteString(l + "\n")
		added = true
	}
	if added {
		_ = os.WriteFile(path, buf.Bytes(), 0o644) //nolint:gosec,errcheck
	}
}

func init() { task.Register(&WebPortscanTask{}) }
