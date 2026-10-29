// lab/parity/httpd — the deterministic HTTP target of the offline parity lab.
//
// One binary, stdlib only, no external dependencies. It serves several virtual
// hosts selected by the Host header (all under lab.test) so that the recon
// engines under test (bash v1 and Go v2) exercise known code paths against a
// target whose content never changes and never rate-limits:
//
//	www.lab.test / lab.test  — normal site: ~15 linkable paths, robots.txt,
//	                           sitemap.xml, a CSP header naming other lab hosts
//	                           (csprecon pivot), HTML links to other lab hosts
//	                           (crawler pivot), a small JS file with host names.
//	soft404.lab.test         — answers 200 to EVERY path with a near-identical
//	                           body (ffuf auto-calibration / soft-404 handling).
//	misconfig.lab.test       — deliberately detectable misconfigurations that
//	                           nuclei's default templates flag: exposed
//	                           .git/HEAD + .git/config, a phpinfo-like page, an
//	                           open directory listing, a verbose Server header,
//	                           an exposed .env, and a reflected parameter echo.
//	api.lab.test             — trivial JSON API (/api, /api/users/1,
//	                           /api/health) plus a minimal /openapi.json.
//	any other *.lab.test     — a generic landing page naming the host, so every
//	                           A record in the zone is a live web host.
//
// TLS: a self-signed certificate is generated in memory at start-up whose SAN
// list names a SUBSET of the lab hosts (see tlsSANs). tlsx-style certificate
// pivoting discovers exactly that subset — a known, fixed ground truth.
//
// Every response is deterministic (no timestamps, no random IDs) so byte-level
// comparisons between runs are meaningful. Binds to the addresses given by
// -http / -https (defaults :80 / :443 inside the container; docker-compose maps
// them to 127.0.0.1 on the host only).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

const zone = "lab.test"

// tlsSANs is the certificate's Subject Alternative Name list. Keep it in sync
// with lab/parity/README.md ("Discovery path: TLS SAN") and expected/*.txt.
var tlsSANs = []string{
	"lab.test",
	"www.lab.test",
	"api.lab.test",
	"shop.lab.test",
	"portal.lab.test",
	"auth.lab.test",
	"assets.lab.test",
	"status.lab.test",
	"app.lab.test",
}

// The normal site's Content-Security-Policy header (see serveNormal) names
// static, cdn and beta: CSP pivoting discovers exactly these three hosts.

// linkedHosts are the hosts reachable ONLY by following HTML links from the
// normal site (crawler / scraping pivot). They are the "bonus" tier of the
// ground truth: a pass-1 recon in v2 does not crawl before probing.
var linkedHosts = []string{
	"intranet.lab.test", "git.lab.test", "ci.lab.test", "monitor.lab.test", "help.lab.test",
}

// sitePaths are the linkable paths of the normal site (index links to all).
var sitePaths = []string{
	"/about", "/contact", "/products", "/products/widget", "/products/gadget",
	"/blog", "/blog/first-post", "/blog/second-post", "/team", "/careers",
	"/pricing", "/faq", "/terms", "/privacy", "/login",
}

func main() {
	httpAddr := flag.String("http", ":80", "plain HTTP listen address")
	httpsAddr := flag.String("https", ":443", "TLS listen address (empty = disabled)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", dispatch)

	srvHTTP := &http.Server{
		Addr:              *httpAddr,
		Handler:           withCommonHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	var srvHTTPS *http.Server
	if *httpsAddr != "" {
		cert, err := selfSignedCert(tlsSANs)
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		srvHTTPS = &http.Server{
			Addr:              *httpsAddr,
			Handler:           withCommonHeaders(mux),
			ReadHeaderTimeout: 10 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}
	}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("httpd: HTTP on %s", *httpAddr)
		errCh <- srvHTTP.ListenAndServe()
	}()
	if srvHTTPS != nil {
		go func() {
			log.Printf("httpd: HTTPS on %s (SANs: %s)", *httpsAddr, strings.Join(tlsSANs, ","))
			errCh <- srvHTTPS.ListenAndServeTLS("", "")
		}()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		log.Fatalf("httpd: %v", err)
	case s := <-sig:
		log.Printf("httpd: %s — shutting down", s)
	}
}

// withCommonHeaders tags every response so the lab is recognisable in any
// capture, and keeps the Date header deterministic-ish (it is set by net/http;
// we cannot remove it, and no comparison in the lab reads it).
func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Lab", "reconftw-parity")
		next.ServeHTTP(w, r)
	})
}

// hostOf returns the request host without port, lower-cased.
func hostOf(r *http.Request) string {
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return strings.ToLower(strings.TrimSuffix(h, "."))
}

func dispatch(w http.ResponseWriter, r *http.Request) {
	host := hostOf(r)
	switch {
	case r.URL.Path == "/healthz":
		// Health probe for docker-compose / run.sh, any vhost.
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintln(w, "ok")
	case host == zone || host == "www."+zone:
		serveNormal(w, r)
	case host == "soft404."+zone:
		serveSoft404(w, r)
	case host == "misconfig."+zone:
		serveMisconfig(w, r)
	case host == "api."+zone:
		serveAPI(w, r)
	case strings.HasSuffix(host, "."+zone):
		serveGeneric(w, r, host)
	default:
		// Requests by IP or an unknown name: still answer (a probe by IP is a
		// legitimate recon step) but make it obviously the default vhost.
		serveGeneric(w, r, "default."+zone)
	}
}

// ---------------------------------------------------------------- normal site

func serveNormal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' https://static.lab.test https://cdn.lab.test; "+
			"connect-src 'self' https://api.lab.test https://beta.lab.test; img-src 'self' https://cdn.lab.test")
	w.Header().Set("Server", "lab-httpd")

	switch r.URL.Path {
	case "/":
		var b strings.Builder
		b.WriteString("<!doctype html><html><head><title>Lab Corp — home</title>")
		b.WriteString(`<script src="/static/app.js"></script></head><body>`)
		b.WriteString("<h1>Lab Corp</h1><p>Deterministic target for the reconFTW parity lab.</p><ul>")
		for _, p := range sitePaths {
			_, _ = fmt.Fprintf(&b, `<li><a href="%s">%s</a></li>`, p, strings.TrimPrefix(p, "/"))
		}
		b.WriteString("</ul><h2>Our other sites</h2><ul>")
		for _, h := range append([]string{"shop.lab.test", "blog.lab.test", "docs.lab.test", "support.lab.test", "api.lab.test"}, linkedHosts...) {
			_, _ = fmt.Fprintf(&b, `<li><a href="http://%s/">%s</a></li>`, h, h)
		}
		b.WriteString("</ul></body></html>")
		writeHTML(w, http.StatusOK, b.String())
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /private-area\nDisallow: /old-site\nSitemap: http://www.lab.test/sitemap.xml\n")
	case "/sitemap.xml":
		w.Header().Set("Content-Type", "application/xml")
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
		for _, p := range sitePaths {
			_, _ = fmt.Fprintf(&b, "<url><loc>http://www.lab.test%s</loc></url>", p)
		}
		b.WriteString("</urlset>")
		_, _ = fmt.Fprint(w, b.String())
	case "/static/app.js":
		w.Header().Set("Content-Type", "application/javascript")
		// Host names inside JS: the js-scraping pivot (subjs/jsluice) finds these.
		_, _ = fmt.Fprint(w, "// lab app bundle\nconst API_BASE = \"https://api.lab.test/api\";\nconst ASSETS = \"https://assets.lab.test/\";\nconst BETA = \"https://beta.lab.test/\";\nfetch(API_BASE + \"/health\").then(r => r.json());\n")
	case "/login":
		writeHTML(w, http.StatusOK, `<!doctype html><html><head><title>Login</title></head><body><form method="post" action="/login"><input name="user"><input name="pass" type="password"><button>Sign in</button></form></body></html>`)
	case "/admin", "/private-area", "/old-site":
		writeHTML(w, http.StatusForbidden, "<!doctype html><html><head><title>403</title></head><body><h1>Forbidden</h1></body></html>")
	default:
		for _, p := range sitePaths {
			if p == r.URL.Path {
				writeHTML(w, http.StatusOK, fmt.Sprintf("<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>Static page.</p><a href=\"/\">home</a></body></html>", html.EscapeString(strings.TrimPrefix(p, "/")), html.EscapeString(p)))
				return
			}
		}
		writeHTML(w, http.StatusNotFound, "<!doctype html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
	}
}

// ---------------------------------------------------------------- soft-404

// serveSoft404 answers 200 to everything with a body that differs only in the
// echoed path. ffuf's auto-calibration (-ac) must learn that shape and drop it.
func serveSoft404(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "lab-httpd")
	writeHTML(w, http.StatusOK, fmt.Sprintf("<!doctype html><html><head><title>Soft 404</title></head><body><h1>We could not find that page</h1><p>The page you requested does not exist, but here is a 200 anyway.</p><!-- %s --></body></html>", html.EscapeString(r.URL.Path)))
}

// ---------------------------------------------------------------- misconfig

func serveMisconfig(w http.ResponseWriter, r *http.Request) {
	// Verbose, version-leaking Server header (technology detection + info).
	w.Header().Set("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/7.4.3")
	w.Header().Set("X-Powered-By", "PHP/7.4.3")

	switch r.URL.Path {
	case "/":
		writeHTML(w, http.StatusOK, `<!doctype html><html><head><title>misconfig host</title></head><body><h1>Deliberately misconfigured host</h1><ul><li><a href="/backup/">backup/</a></li><li><a href="/phpinfo.php">phpinfo.php</a></li><li><a href="/search?q=test">search</a></li></ul></body></html>`)
	case "/.git/HEAD":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ref: refs/heads/master\n")
	case "/.git/config":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = git@git.lab.test:labcorp/website.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
	case "/.env":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "APP_ENV=production\nAPP_DEBUG=true\nDB_HOST=db.internal\nDB_USERNAME=labuser\nDB_PASSWORD=lab-not-a-real-secret\nMAIL_HOST=mail.lab.test\n")
	case "/phpinfo.php", "/info.php":
		writeHTML(w, http.StatusOK, `<!doctype html><html><head><title>phpinfo()</title></head><body><div class="center"><table><tr class="h"><td><h1 class="p">PHP Version 7.4.3</h1></td></tr></table><h2>PHP License</h2><table><tr><td class="e">System </td><td class="v">Linux misconfig 5.15.0 x86_64</td></tr><tr><td class="e">Configuration File (php.ini) Path </td><td class="v">/etc/php/7.4/apache2</td></tr><tr><td class="e">PHP Extension </td><td class="v">20190902</td></tr><tr><td class="e">PHP Extension Build </td><td class="v">API20190902,NTS</td></tr></table></div></body></html>`)
	case "/backup/", "/backup":
		// Classic Apache-style index page.
		writeHTML(w, http.StatusOK, `<!doctype html><html><head><title>Index of /backup</title></head><body><h1>Index of /backup</h1><pre><a href="?C=N;O=D">Name</a> <a href="?C=M;O=A">Last modified</a> <a href="?C=S;O=A">Size</a><hr><a href="/">Parent Directory</a>                             -
<a href="site-2024.tar.gz">site-2024.tar.gz</a>        2024-01-01 00:00  1.2M
<a href="db-dump.sql">db-dump.sql</a>             2024-01-01 00:00  340K
<hr></pre><address>Apache/2.4.49 (Unix) Server at misconfig.lab.test Port 80</address></body></html>`)
	case "/backup/site-2024.tar.gz", "/backup/db-dump.sql":
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = fmt.Fprint(w, "LAB-PLACEHOLDER-NOT-A-REAL-DUMP\n")
	case "/search":
		// Reflected parameter echo, unencoded on purpose (Gxss / dalfox / DAST
		// reflection probes). Scope: the lab only; it never leaves localhost.
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<!doctype html><html><head><title>search</title></head><body><h1>Results for: %s</h1><p>No results.</p></body></html>", q)
	case "/server-status":
		writeHTML(w, http.StatusOK, `<!doctype html><html><head><title>Apache Status</title></head><body><h1>Apache Server Status for misconfig.lab.test (via 127.0.0.1)</h1><dl><dt>Server Version: Apache/2.4.49 (Unix)</dt><dt>Server MPM: event</dt><dt>Server Built: 2024-01-01</dt></dl></body></html>`)
	default:
		writeHTML(w, http.StatusNotFound, "<!doctype html><html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><hr><address>Apache/2.4.49 (Unix) Server at misconfig.lab.test Port 80</address></body></html>")
	}
}

// ---------------------------------------------------------------- api

func serveAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "lab-api")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/", "/api", "/api/":
		_, _ = fmt.Fprint(w, `{"service":"lab-api","version":"1.0.0","endpoints":["/api/health","/api/users/1","/openapi.json"]}`+"\n")
	case "/api/health":
		_, _ = fmt.Fprint(w, `{"status":"ok"}`+"\n")
	case "/api/users/1":
		_, _ = fmt.Fprint(w, `{"id":1,"name":"Ada Lab","email":"ada@lab.test","role":"user"}`+"\n")
	case "/openapi.json", "/swagger.json":
		_, _ = fmt.Fprint(w, `{"openapi":"3.0.0","info":{"title":"Lab API","version":"1.0.0"},"paths":{"/api/health":{"get":{"responses":{"200":{"description":"ok"}}}},"/api/users/{id}":{"get":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{"200":{"description":"user"}}}}}}`+"\n")
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"error":"not found"}`+"\n")
	}
}

// ---------------------------------------------------------------- generic

func serveGeneric(w http.ResponseWriter, r *http.Request, host string) {
	w.Header().Set("Server", "lab-httpd")
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		writeHTML(w, http.StatusNotFound, "<!doctype html><html><head><title>404</title></head><body><h1>Not Found</h1></body></html>")
		return
	}
	writeHTML(w, http.StatusOK, fmt.Sprintf("<!doctype html><html><head><title>%s</title></head><body><h1>%s</h1><p>Generic lab host.</p><a href=\"http://www.lab.test/\">main site</a></body></html>", html.EscapeString(host), html.EscapeString(host)))
}

func writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = fmt.Fprint(w, body)
}

// ---------------------------------------------------------------- tls

// selfSignedCert builds an in-memory ECDSA P-256 certificate whose SAN list is
// sans (sorted, deduplicated). The key never touches disk.
func selfSignedCert(sans []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	names := append([]string(nil), sans...)
	sort.Strings(names)
	names = dedupe(names)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "www." + zone, Organization: []string{"Lab Corp (reconftw parity lab)"}},
		NotBefore:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2034, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
