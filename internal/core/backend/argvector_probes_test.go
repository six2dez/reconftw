// argvector_probes_test.go — the subdomain + web probe table, WITHOUT a build tag.
//
// It was inside TestRealToolArgVectors in smoke_test.go, behind
// //go:build realtools. That placement made it unreadable to any hermetic test,
// which is why nothing ever checked the claim its own comment makes: "Each entry
// uses the EXACT arg vector from internal/modules/web/*.go". Nothing enforced
// it, so a module could change a flag and the probe would keep validating the
// old vector forever, green.
//
// Moving the data out of the tagged file is what lets argvector_drift_test.go
// compare a probe against the Task it names, on a CI runner with no toolchain.
//
// THE `mirrors` FIELD IS REQUIRED. A blank one is indistinguishable from an
// unfilled one, so entries that mirror no single Task say
// probeMirrorsNoTask explicitly and TestProbeTableDeclaresMirrors fails on a
// blank.
package backend_test

// probeMirrorsNoTask marks a probe that deliberately mirrors no single Task:
// a repo-clone tool, or a synthetic vector built for the probe itself.
const probeMirrorsNoTask = "(no single task)"

// toolProbe pairs a tool name with the representative real arg vector its Task
// uses. {F}=hosts file, {R}=resolvers file, {W}=wordlist file, {J}=JS file,
// {O}=output file path — substituted with throwaway temp paths at runtime.
type toolProbe struct {
	name string
	args []string
	// stdin, when true, feeds empty stdin (for stdin-reading tools).
	stdin bool
	// mirrors names the Task whose arg vector this probe copies, or
	// probeMirrorsNoTask. REQUIRED — see the file header. A blank value fails
	// TestProbeTableDeclaresMirrors, because a blank is indistinguishable from an
	// entry nobody got round to filling in.
	mirrors string
}

// subdomainWebProbes mirrors the real Task invocations in
// internal/modules/{subdomains,web}/*.go.
var subdomainWebProbes = []toolProbe{
	{name: "subfinder", args: []string{"-all", "-d", "example.com", "-max-time", "1", "-silent"}, mirrors: probeMirrorsNoTask},
	{name: "crt", args: []string{"-s", "-json", "example.com"}, mirrors: probeMirrorsNoTask},
	{name: "urlfinder", args: []string{"-d", "example.com", "-silent"}, mirrors: probeMirrorsNoTask},
	{name: "github-subdomains", args: []string{"-d", "example.com", "-t", "dummytoken"}, mirrors: probeMirrorsNoTask},
	{name: "gitlab-subdomains", args: []string{"-d", "example.com", "-t", "dummytoken"}, mirrors: probeMirrorsNoTask},
	{name: "httpx", args: []string{"-silent", "-u", "https://example.com"}, mirrors: probeMirrorsNoTask},
	{name: "puredns", args: []string{"resolve", "{F}", "-r", "{R}", "--wildcard-tests", "1", "--wildcard-batch", "1", "--rate-limit", "1", "--rate-limit-trusted", "1", "--resolvers-trusted", "{R}", "--quiet"}, mirrors: probeMirrorsNoTask},
	{name: "puredns", args: []string{"bruteforce", "{W}", "example.com", "-r", "{R}", "--quiet"}, mirrors: probeMirrorsNoTask},
	{name: "tlsx", args: []string{"-l", "{F}", "-san", "-cn", "-silent", "-ro"}, mirrors: probeMirrorsNoTask},
	{name: "dnsx", args: []string{"-l", "{F}", "-ns", "-resp", "-silent"}, mirrors: probeMirrorsNoTask},
	{name: "gotator", args: []string{"-sub", "{F}", "-depth", "1", "-numbers", "3", "-md"}, mirrors: probeMirrorsNoTask},
	{name: "regulator", args: []string{"{F}", "example.com"}, mirrors: probeMirrorsNoTask},
	{name: "dnscewl", args: []string{"-f", "{F}"}, mirrors: probeMirrorsNoTask},
	{name: "subwiz", args: []string{"-i", "{F}", "--no-resolve"}, mirrors: probeMirrorsNoTask},
	{name: "subzy", args: []string{"run", "--targets", "{F}", "--verify-ssl", "--output", "{O}"}, mirrors: "subdomains.takeover.subzy"},
	{name: "dnstake", args: []string{"-t", "{F}", "-s"}, mirrors: probeMirrorsNoTask},
	{name: "s3scanner", args: []string{"--bucket-file", "{F}"}, mirrors: probeMirrorsNoTask},
	{name: "asnmap", args: []string{"-d", "example.com", "-json", "-silent"}, mirrors: probeMirrorsNoTask},
	{name: "favirecon", args: []string{"-u", "example.com", "-timeout", "5"}, mirrors: probeMirrorsNoTask},
	{name: "analyticsrelationships", args: []string{"-u", "https://example.com", "--chain-mode"}, mirrors: probeMirrorsNoTask},
	{name: "jsluice", args: []string{"urls", "-i", "{J}"}, mirrors: probeMirrorsNoTask},
	{name: "subjs", args: []string{"-i", "-"}, stdin: true, mirrors: probeMirrorsNoTask},

	// Phase 5 additions — web pipeline (DoD-1)
	// Each entry uses the EXACT arg vector from internal/modules/web/*.go (D-W9).
	// A wrong flag is caught even when the binary is absent (golden is checked unconditionally).

	// nuclei: scan mode (NucleiTask — nuclei.go)
	{name: "nuclei", args: []string{"-u", "https://example.com", "-id", "http-missing-security-headers", "-silent", "-j", "-o", "{O}"}, mirrors: probeMirrorsNoTask},

	// nuclei: screenshot mode (ScreenshotTask — screenshot.go)
	// -V dir={O}: nuclei variable sets screenshot output directory.
	{name: "nuclei", args: []string{"-headless", "-id", "screenshot", "-V", "dir={O}", "-l", "{F}", "-silent"}, mirrors: probeMirrorsNoTask},

	// ffuf: web directory fuzzer (FfufTask — ffuf.go)
	{name: "ffuf", args: []string{"-mc", "all", "-fc", "404", "-sf", "-noninteractive", "-of", "json", "-w", "{W}", "-maxtime", "5", "-u", "https://example.com/FUZZ", "-o", "{O}"}, mirrors: probeMirrorsNoTask},

	// katana: web crawler (KatanaTask — katana.go: -silent -list {F} -jc -kf all -c N -d 2 -fs rdn)
	{name: "katana", args: []string{"-silent", "-list", "{F}", "-jc", "-kf", "all", "-c", "1", "-d", "2", "-fs", "rdn"}, mirrors: probeMirrorsNoTask},

	// urlfinder: passive URL discovery (UrlfindlerTask — urlfinder.go: -d domain -all -o {O})
	{name: "urlfinder", args: []string{"-d", "example.com", "-all", "-o", "{O}"}, mirrors: probeMirrorsNoTask},

	// waymore: passive URL archive (WaymoreTask — waymore.go: -i domain -mode U -oU {O})
	{name: "waymore", args: []string{"-i", "example.com", "-mode", "U", "-oU", "{O}"}, mirrors: probeMirrorsNoTask},

	// urless: URL deduplication (reads stdin, UrldedupTask — urldedup.go)
	{name: "urless", args: []string{}, stdin: true, mirrors: probeMirrorsNoTask},

	// p1radup: URL deduplication (-i {F} -o {O} -s, UrldedupTask — urldedup.go)
	{name: "p1radup", args: []string{"-i", "{F}", "-o", "{O}", "-s"}, mirrors: probeMirrorsNoTask},

	// subjs: JS URL extraction (-ua <ua> -c 40 -i {F}, SubjsTask — subjs.go)
	{name: "subjs", args: []string{"-ua", "Mozilla/5.0", "-c", "40", "-i", "{F}"}, mirrors: probeMirrorsNoTask},

	// jsluice: URL extraction mode (JsluiceTask — jsluice.go: jsluice urls {file...})
	{name: "jsluice", args: []string{"urls", "{J}"}, mirrors: probeMirrorsNoTask},

	// jsluice: secrets mode (JsluiceTask — jsluice.go: jsluice secrets -j {file...})
	{name: "jsluice", args: []string{"secrets", "-j", "{J}"}, mirrors: probeMirrorsNoTask},

	// mantra: JS secret scanner (-ua <ua> -s via stdin, MantraTask — mantra.go)
	// [A5-fix: mantra reads from stdin; no -i flag exists]
	{name: "mantra", args: []string{"-ua", "Mozilla/5.0", "-s"}, stdin: true, mirrors: probeMirrorsNoTask},

	// sourcemapper: source map extractor (-jsurl <url> -output {O}, SourcemapperTask — sourcemapper.go)
	{name: "sourcemapper", args: []string{"-jsurl", "https://example.com/app.js", "-output", "{O}"}, mirrors: probeMirrorsNoTask},

	// wafw00f: WAF detection (-i {F} -o {O}, Wafw00fTask — wafw00f.go)
	{name: "wafw00f", args: []string{"-i", "{F}", "-o", "{O}"}, mirrors: probeMirrorsNoTask},

	// cdncheck: CDN/WAF IP classification (-silent -resp -nc -i {F}, CdncheckTask — cdncheck.go)
	{name: "cdncheck", args: []string{"-silent", "-resp", "-nc", "-i", "{F}"}, mirrors: probeMirrorsNoTask},

	// hakoriginfinder: origin IP discovery (reads IPs from stdin + -h <url>, HakoriginfinderTask — hakoriginfinder.go)
	// [A14-fix: tool reads IPs from stdin, not -i flag; -h specifies target URL]
	{name: "hakoriginfinder", args: []string{"-h", "https://example.com"}, stdin: true, mirrors: probeMirrorsNoTask},

	// csprecon: CSP hostname extraction (-s -l {F}, CspreconTask — csprecon.go)
	// [A15-fix: csprecon uses -l/-list for file input, not -i]
	{name: "csprecon", args: []string{"-s", "-l", "{F}"}, mirrors: probeMirrorsNoTask},

	// favirecon: favicon tech recon (-l {F} -c N -t N -s -j -o {O}, FavireconTask — favirecon.go)
	{name: "favirecon", args: []string{"-l", "{F}", "-c", "5", "-t", "5", "-s", "-j", "-o", "{O}"}, mirrors: probeMirrorsNoTask},

	// VhostFinder: virtual host discovery (-ips {F} -wordlist {F} -verify, VhostFinderTask — vhostfinder.go)
	{name: "VhostFinder", args: []string{"-ips", "{F}", "-wordlist", "{F}", "-verify"}, mirrors: probeMirrorsNoTask},

	// shortscan: IIS short filename scanner (positional URL -F -s -p 1, ShortscanTask — shortscan.go)
	{name: "shortscan", args: []string{"https://example.com", "-F", "-s", "-p", "1"}, mirrors: probeMirrorsNoTask},

	// Gxss: XSS reflection scanner (-c 100 -p Xss via stdin, GxssTask — gxss.go)
	{name: "Gxss", args: []string{"-c", "100", "-p", "Xss"}, stdin: true, mirrors: probeMirrorsNoTask},

	// arjun: parameter discovery (-i {F} -t N -oT {O}, ArjunTask — arjun.go)
	{name: "arjun", args: []string{"-i", "{F}", "-t", "5", "-oT", "{O}"}, mirrors: probeMirrorsNoTask},
}
