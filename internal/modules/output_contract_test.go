// output_contract_test.go — every parser of a THIRD-PARTY tool's output must
// have met that tool's REAL output.
//
// # ORIGIN
//
// Plan 16-04 hardened the tool contract on the way IN — the arg vector v2 hands
// a tool. This file hardens it on the way OUT: what v2 believes the tool hands
// back. Both broke in the 2026-08-20 live run, and the output side cost more.
//
// internal/modules/web/httpx.go's httpxRaw declared `Port int` while httpx emits
// `"port":"80"` — a STRING. json.Unmarshal failed on every line,
// parseHTTPXOutput returned "all 20 lines failed to parse",
// artefacts/hosts.jsonl was truncated to 0 bytes, and every downstream web task
// correctly skipped with "no hosts in hosts.jsonl". The run scored 0 live hosts
// against v1's 12 and 2 finding classes against v1's 50 — while every badge read
// OK.
//
// # THE RULE, AND WHY IT IS ABOUT EVIDENCE RATHER THAN TESTS
//
// A HAND-WRITTEN FIXTURE FOR A THIRD-PARTY FORMAT AGREES WITH THE STRUCT AND
// DISAGREES WITH THE TOOL. It is written by reading the Go struct, so it can
// only ever confirm what the struct already believes. Only captured output can
// falsify a struct.
//
// The proof that this is not theoretical: testdata/fixtures/httpx/
// httpx_hackerone.jsonl has been in the repo since 2026-06-02 and contains
// `"port":"443"` — the exact evidence that falsifies httpxRaw. It sat there for
// two and a half months because TestWebParityHTTPX, whose doc-comment said it
// "verifies that httpx JSONL output feeds through parseHTTPXOutput", declared
// its own anonymous struct inline and never called that function. The fixture
// was real; nothing passed it through the parser.
//
// So this file asserts two things a passing test suite did not:
//
//  1. every fixture says WHERE IT CAME FROM, so a hand-written one cannot pass
//     as evidence;
//  2. every parser of third-party output is reached by a test in its own package
//     that also references the fixture tree — or is named on an allowlist with a
//     reason, and that allowlist's size is asserted.
//
// # THE CLASSIFICATION IS A JUDGEMENT CALL, MADE PER PARSER
//
// A parser that decodes V2'S OWN artefact schema cannot suffer this defect: v2
// writes those files and v2 reads them, so both sides move together. A parser
// that decodes a THIRD-PARTY tool's output can, because the other side belongs
// to someone else and changes on their release schedule.
//
// Getting the split wrong in the permissive direction hides a real gap; getting
// it wrong in the strict direction demands captured fixtures for schemas v2
// defines itself, which nobody will maintain and which would get the guard
// deleted. So every decoding function is classified explicitly, with a reason,
// and an UNCLASSIFIED one is a failure — a new parser cannot arrive unjudged.
//
// # BLIND SPOTS
//
//   - STALE EVIDENCE. A fixture captured from a tool version that has since
//     changed its output format is wrong, and nothing here can see that. The
//     provenance date is the only signal, which is exactly why the header is
//     mandatory rather than nice-to-have.
//   - THE WRONG-DESTINATION-FIELD CLASS. A parser can decode a line perfectly
//     and then map it into the wrong field of the output record. Phase 15's F19
//     is the standing example. This detector sees that a parser is exercised,
//     not that its mapping is right.
//   - COVERAGE IS FILE-GRANULAR. "A test in the same package calls this parser
//     AND that test file references testdata/fixtures" is the coverage test. A
//     file where one test calls the parser and a DIFFERENT test reads a fixture
//     counts as covered. Tightening it means matching call to fixture within a
//     single test function, which is a real dataflow problem, not a drive-by.
//   - A PARSER REACHED ONLY THROUGH A MOCK. The call is what is detected, not
//     what was fed to it.
package modules_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type parserClass string

const (
	// classThirdParty decodes output produced by a tool or API v2 does not own.
	classThirdParty parserClass = "third-party"
	// classOwnSchema decodes an artefact or staging file v2 itself wrote.
	classOwnSchema parserClass = "own-schema"
)

type classification struct {
	class  parserClass
	reason string
}

// parserClassification classifies EVERY JSON-decoding function under
// internal/modules. An unclassified one fails TestOutputContractCensusIsComplete,
// so a new parser cannot arrive unjudged.
//
// Keys are "<repo-relative-file>:<func>", methods qualified by receiver.
var parserClassification = map[string]classification{
	// ---- third party: a tool's or an API's own output format ----
	"internal/modules/osint/favirecon.go:parseFaviReconOutput":           {classThirdParty, "favirecon -j output"},
	"internal/modules/osint/github_actions.go:parseGatoOutput":           {classThirdParty, "gato JSON report"},
	"internal/modules/osint/github_leaks.go:parseGhleaksReport":          {classThirdParty, "ghleaks JSON report"},
	"internal/modules/osint/github_leaks.go:parseTrufflehogOutput":       {classThirdParty, "trufflehog --json output"},
	"internal/modules/osint/github_repos.go:githubReposExtractSecrets":   {classThirdParty, "titus/trufflehog secret records"},
	"internal/modules/osint/github_repos.go:parseEnumerepoOutput":        {classThirdParty, "enumerepo JSON output"},
	"internal/modules/osint/ip_info.go:IPInfoTask.whoisXMLReverseIP":     {classThirdParty, "WhoisXML reverse-IP API response"},
	"internal/modules/osint/ip_info.go:lookupIPInfoGeo":                  {classThirdParty, "ipinfo.io API response"},
	"internal/modules/osint/ip_info.go:whoisXMLFormatGeo":                {classThirdParty, "WhoisXML geo API response"},
	"internal/modules/osint/postman.go:parsePostleaksJSON":               {classThirdParty, "postleaksNg JSON output"},
	"internal/modules/subdomains/asn.go:SubASNTask.Run":                  {classThirdParty, "asnmap -json output"},
	"internal/modules/subdomains/buckets.go:SubBucketsTask.Run":          {classThirdParty, "s3scanner JSON output"},
	"internal/modules/subdomains/geo.go:SubGeoTask.Run":                  {classThirdParty, "geo provider API response"},
	"internal/modules/subdomains/geo.go:lookupIPInfo":                    {classThirdParty, "ipinfo.io API response"},
	"internal/modules/subdomains/passive.go:parseCrtJSON":                {classThirdParty, "crt -json output"},
	"internal/modules/subdomains/resolve.go:parseDNSRegs":                {classThirdParty, "dnsx -json record output"},
	"internal/modules/subdomains/takeover.go:TakeoverDNSTakeTask.Run":    {classThirdParty, "dnstake JSON output"},
	"internal/modules/subdomains/takeover.go:TakeoverSubzyTask.Run":      {classThirdParty, "subzy --output JSON"},
	"internal/modules/vulns/fray.go:parseFrayOutput":                     {classThirdParty, "fray JSON output"},
	"internal/modules/vulns/fuzzparams.go:parseFuzzparamsOutput":         {classThirdParty, "nuclei -j fuzzing output"},
	"internal/modules/vulns/graphql.go:parseGQLSpectionOutput":           {classThirdParty, "gqlspection JSON output"},
	"internal/modules/vulns/llm.go:parseLLMProbeOutput":                  {classThirdParty, "julius LLM-probe JSON output"},
	"internal/modules/vulns/nuclei_dast.go:parseNucleiDAST":              {classThirdParty, "nuclei -j DAST output"},
	"internal/modules/vulns/second_order.go:parseSecondOrderOutput":      {classThirdParty, "second-order JSON output"},
	"internal/modules/vulns/smuggling.go:parseSmugglingOutput":           {classThirdParty, "smugglex JSON output"},
	"internal/modules/vulns/spray.go:parseBrutusHits":                    {classThirdParty, "brutus JSON hit records"},
	"internal/modules/vulns/ssti.go:parseTInjAReports":                   {classThirdParty, "TInjA JSON report"},
	"internal/modules/vulns/websocket.go:parseWebsocketOutput":           {classThirdParty, "httpx -json output (websocket probe)"},
	"internal/modules/web/ffuf.go:parseFFUFJSONL":                        {classThirdParty, "ffuf JSONL output"},
	"internal/modules/web/ffuf.go:parseFFUFOutput":                       {classThirdParty, "ffuf JSON output"},
	"internal/modules/web/httpx.go:parseHTTPXOutput":                     {classThirdParty, "httpx -json output — THE 2026-08-21 bug"},
	"internal/modules/web/nuclei.go:parseNucleiOutput":                   {classThirdParty, "nuclei -jsonl output"},
	"internal/modules/web/nuclei_coverage.go:NucleiCoverage.observeLine": {classThirdParty, "nuclei -stats -sj accounting object; every value is a STRING"},
	"internal/modules/web/portscan.go:portscanWriteFingerprintRecords":   {classThirdParty, "nerva service-fingerprint JSON"},

	// ---- own schema: v2 wrote the file it is reading ----
	"internal/modules/osint/github_leaks.go:trufflehogLocator":          {classOwnSchema, "reads v2's own staged finding records to locate a hit"},
	"internal/modules/osint/swagger.go:parseHostLines":                  {classOwnSchema, "reads v2's own host lines"},
	"internal/modules/subdomains/scraping.go:scrapingSubjsInput":        {classOwnSchema, "reads v2's artefacts/hosts.jsonl|urls.jsonl for the subjs input file (17-04)"},
	"internal/modules/vulns/bypass4xx.go:read4xxURLsFromVulnsFuzzJSONL": {classOwnSchema, "reads v2's inputs/*.jsonl"},
	"internal/modules/vulns/graphql.go:readURLsJSONL":                   {classOwnSchema, "reads v2's artefacts/urls.jsonl"},
	"internal/modules/vulns/spray.go:sprayHostsByIP":                    {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/vulns/spray.go:sprayRegisterBrutusCreds":          {classOwnSchema, "reads v2's own staged credential records"},
	"internal/modules/vulns/testssl.go:resolveTestSSLInput":             {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/arjun.go:readAllURLsFromJSONL":                {classOwnSchema, "reads v2's artefacts/urls.jsonl"},
	"internal/modules/web/cdncheck.go:readIPsFromHostsJSONL":            {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/gxss.go:readParamURLsFromJSONL":               {classOwnSchema, "reads v2's artefacts/urls.jsonl"},
	"internal/modules/web/hakoriginfinder.go:readHostIPPairsFromJSONL":  {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/hakoriginfinder.go:readHostnamesFromJSONL":    {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/httpx.go:extractHostsFromSubdomainsJSONL":     {classOwnSchema, "reads v2's artefacts/subdomains.jsonl"},
	"internal/modules/web/httpx.go:extractHostsFromHostsJSONL":          {classOwnSchema, "reads v2's own artefacts/hosts.jsonl (D-W11) to derive httpx's -l host list; the artefact must never be passed to httpx directly (CR-02, 17-06)"},
	"internal/modules/web/merge.go:hostRecordRank":                      {classOwnSchema, "ranks v2's own HostRecord"},
	"internal/modules/web/merge.go:hostsDedupKey":                       {classOwnSchema, "keys v2's own HostRecord"},
	"internal/modules/web/nomore403.go:read4xxURLsFromFuzzJSONL":        {classOwnSchema, "reads v2's inputs/*.jsonl"},
	"internal/modules/web/nuclei.go:readHostURLsFromJSONL":              {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/nuclei.go:readWAFHostsSet":                    {classOwnSchema, "reads v2's own WAF staging"},
	"internal/modules/web/portscan.go:portscanOriginIPs":                {classOwnSchema, "reads v2's own origin-IP staging"},
	"internal/modules/web/screenshot.go:readScreenshotHosts":            {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
	"internal/modules/web/shortscan.go:readIISTargetsFromNucleiStaging": {classOwnSchema, "reads v2's own nuclei staging records"},
	"internal/modules/web/urldedup.go:extractURLStringsAndSources":      {classOwnSchema, "reads v2's artefacts/urls.jsonl"},
	"internal/modules/web/vhostfinder.go:buildVhostWordlist":            {classOwnSchema, "reads v2's artefacts/subdomains.jsonl"},
	"internal/modules/web/wellknown.go:wellknownExtractHosts":           {classOwnSchema, "reads v2's artefacts/hosts.jsonl"},
}

// outputContractAllowlist names THIRD-PARTY parsers with no real-fixture test
// yet. Each entry is a parser that has never met the output it claims to read.
//
// SEEDED by plan 16-07 Task 2's census. Plan 16-07 Task 3 closes the
// highest-value subset; the rest is named debt with a number attached, because a
// rushed fixture is worse than an allowlist entry — it LOOKS like coverage.
//
// DELETE an entry when you add a real captured fixture and a test that passes it
// through the parser. NEVER add one to silence a new parser.
var outputContractAllowlist = map[string]string{
	"internal/modules/osint/favirecon.go:parseFaviReconOutput":         "favirecon -j; no captured fixture yet",
	"internal/modules/osint/github_repos.go:githubReposExtractSecrets": "titus/trufflehog secret records; no captured fixture yet",
	"internal/modules/osint/ip_info.go:IPInfoTask.whoisXMLReverseIP":   "WhoisXML API; capture needs a paid key — see SUMMARY",
	"internal/modules/osint/ip_info.go:lookupIPInfoGeo":                "ipinfo.io API; no captured fixture yet",
	"internal/modules/subdomains/geo.go:lookupIPInfo":                  "ipinfo.io API; no captured fixture yet",
	"internal/modules/subdomains/resolve.go:parseDNSRegs":              "dnsx -json records; HIGH VALUE — feeds the subdomain spine",
	"internal/modules/vulns/graphql.go:parseGQLSpectionOutput":         "gqlspection JSON; no captured fixture yet",
	"internal/modules/vulns/llm.go:parseLLMProbeOutput":                "julius JSON; no captured fixture yet",
	"internal/modules/vulns/second_order.go:parseSecondOrderOutput":    "second-order JSON; no captured fixture yet",
	"internal/modules/vulns/ssti.go:parseTInjAReports":                 "TInjA JSON report; no captured fixture yet",
	"internal/modules/vulns/websocket.go:parseWebsocketOutput":         "httpx -json; SAME TOOL as the 2026-08-21 bug, different parser",
	"internal/modules/web/portscan.go:portscanWriteFingerprintRecords": "nerva fingerprint JSON; no captured fixture yet",
	"internal/modules/web/ffuf.go:parseFFUFJSONL":                      "ffuf JSONL; reached ONLY as parseFFUFOutput's fallback for non-document output, so no test calls it directly. Closing it needs a captured ffuf JSONL stream, which -of json does not produce — do not hand-write one.",
}

// outputContractAllowlistSize is pinned so the debt cannot grow unnoticed.
var outputContractAllowlistSize = len(outputContractAllowlist)

// fixtureProvenanceAllowlist names fixture files that predate the provenance
// rule and whose true origin is unknown.
//
// THESE ARE NOT EXEMPT BECAUSE THEY ARE FINE. They are exempt because inventing
// a `# captured-from:` line for a file whose origin nobody recorded would be
// FABRICATING the very evidence this rule exists to demand — a worse outcome
// than an honest gap. Re-capture and delete the entry.
var fixtureProvenanceAllowlist = map[string]string{
	"internal/modules/osint/testdata/fixtures/domain_info/whois_fixture.txt":             "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/github_actions/gato_fixture.txt":           "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/github_leaks/ghleaks_fixture.txt":          "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/github_leaks/trufflehog_fixture.txt":       "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/ip_info/asnmap_fixture.txt":                "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/postman/porchpirate_fixture.txt":           "predates the rule; true origin unrecorded",
	"internal/modules/osint/testdata/fixtures/swagger/swagger_fixture.txt":               "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/passive/hackerone.com.crt.txt":        "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/passive/hackerone.com.subfinder.txt":  "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/passive/maintainer.subfinder.txt":     "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/passive/tesla.com.crt.txt":            "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/passive/tesla.com.subfinder.txt":      "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/resolved/hackerone.com.puredns.txt":   "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/resolved/maintainer.puredns.txt":      "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/resolved/tesla.com.puredns.txt":       "predates the rule; true origin unrecorded",
	"internal/modules/subdomains/testdata/fixtures/takeover/hackerone.com.dnstake.jsonl": "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/crlfuzz/crlfuzz_fixture.txt":               "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/dalfox/dalfox_poc_fixture.txt":             "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/gf/gf_lfi_fixture.txt":                     "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/gf/gf_sqli_fixture.txt":                    "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/gf/gf_xss_fixture.txt":                     "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/spray/portscan_active.gnmap":               "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/spray/service_fingerprints.jsonl":          "predates the rule; true origin unrecorded",
	"internal/modules/vulns/testdata/fixtures/sqlmap/sqlmap_output_fixture.txt":          "predates the rule; true origin unrecorded",
	"internal/modules/web/testdata/fixtures/ffuf/ffuf_hackerone.json":                    "predates the rule; true origin unrecorded",
	"internal/modules/web/testdata/fixtures/js/jsluice_secrets.jsonl":                    "predates the rule; true origin unrecorded",
	"internal/modules/web/testdata/fixtures/js/jsluice_urls.jsonl":                       "predates the rule; true origin unrecorded",
	"internal/modules/web/testdata/fixtures/urls/katana_hackerone.txt":                   "predates the rule; true origin unrecorded",
	"internal/modules/web/testdata/fixtures/waf/wafw00f_hackerone.txt":                   "predates the rule; true origin unrecorded",
}

func TestOutputContractCensusIsComplete(t *testing.T) {
	found := discoverJSONDecoders(t, ".")
	if len(found) == 0 {
		t.Fatal("discovered ZERO JSON-decoding functions — the walker is broken, and a broken walker " +
			"makes every assertion in this file vacuously true")
	}

	for _, key := range found {
		if _, ok := parserClassification[key]; !ok {
			t.Errorf("UNCLASSIFIED JSON decoder: %s\n"+
				"  Every decoding function must be judged third-party or own-schema, because only the\n"+
				"  third-party ones can disagree with a format v2 does not control. Add it to\n"+
				"  parserClassification with a one-line reason — the judgement is the point, and a\n"+
				"  parser that arrives unjudged is how httpxRaw stayed wrong for two and a half months.",
				key)
		}
	}

	live := map[string]bool{}
	for _, k := range found {
		live[k] = true
	}
	for key := range parserClassification {
		if !live[key] {
			t.Errorf("STALE classification: %s no longer decodes JSON (renamed, deleted, or rewritten).\n"+
				"  Delete the entry so the census keeps describing the tree.", key)
		}
	}
	t.Logf("OUTPUT_CONTRACT_CENSUS decoders=%d third_party=%d own_schema=%d",
		len(found), countClass(classThirdParty), countClass(classOwnSchema))
}

func TestOutputContractThirdPartyParsersAreFixtureCovered(t *testing.T) {
	covered := discoverFixtureCoveredFuncs(t, ".")

	var uncovered []string
	for key, c := range parserClassification {
		if c.class != classThirdParty {
			continue
		}
		fn := key[strings.LastIndex(key, ":")+1:]
		if idx := strings.LastIndex(fn, "."); idx >= 0 {
			fn = fn[idx+1:] // methods are called by their bare method name
		}
		pkgDir := filepath.Dir(key)
		if covered[pkgDir+":"+fn] {
			continue
		}
		if _, listed := outputContractAllowlist[key]; listed {
			continue
		}
		uncovered = append(uncovered, key)
	}
	sort.Strings(uncovered)
	for _, key := range uncovered {
		t.Errorf("THIRD-PARTY parser with no real-fixture test: %s (%s)\n"+
			"  Nothing in its package passes captured output from that tool through this function, so\n"+
			"  its struct has never been falsifiable. Add a fixture with provenance and a test that\n"+
			"  calls the parser — or add an allowlist entry with the reason and raise the size.",
			key, parserClassification[key].reason)
	}

	// Stale direction: an allowlist entry that IS covered is dead weight, and dead
	// weight is what lets the next genuine gap hide behind a familiar name.
	for key := range outputContractAllowlist {
		c, known := parserClassification[key]
		if !known {
			t.Errorf("allowlist names %s, which is not in the census — the entry asserts nothing", key)
			continue
		}
		if c.class != classThirdParty {
			t.Errorf("allowlist names %s, classified %s — only third-party parsers need fixtures", key, c.class)
			continue
		}
		fn := key[strings.LastIndex(key, ":")+1:]
		if idx := strings.LastIndex(fn, "."); idx >= 0 {
			fn = fn[idx+1:]
		}
		if covered[filepath.Dir(key)+":"+fn] {
			t.Errorf("STALE allowlist entry: %s now HAS a real-fixture test. Delete it and lower "+
				"outputContractAllowlistSize.", key)
		}
	}

	if got := len(outputContractAllowlist); got != outputContractAllowlistSize {
		t.Errorf("allowlist size %d, constant says %d — the debt moved without the number moving",
			got, outputContractAllowlistSize)
	}
}

func TestFixturesCarryProvenance(t *testing.T) {
	var missing []string
	for _, onDisk := range discoverFixtures(t, ".") {
		key := repoRelPath(onDisk)
		if _, listed := fixtureProvenanceAllowlist[key]; listed {
			continue
		}
		if fixtureHasProvenance(t, onDisk) {
			continue
		}
		missing = append(missing, key)
	}
	sort.Strings(missing)
	for _, f := range missing {
		t.Errorf("fixture without provenance: %s\n"+
			"  Add a first-line `# captured-from: <argv> | date: <date> | version: <v>` comment, or a\n"+
			"  `%s.provenance` sidecar for formats where a comment is not legal.\n"+
			"  A fixture for a third-party format is evidence only if it came FROM that tool; a\n"+
			"  hand-written one agrees with the struct by construction and cannot falsify it.", f, f)
	}
	onDiskByKey := map[string]string{}
	for _, onDisk := range discoverFixtures(t, ".") {
		onDiskByKey[repoRelPath(onDisk)] = onDisk
	}
	for key := range fixtureProvenanceAllowlist {
		onDisk, exists := onDiskByKey[key]
		if !exists {
			t.Errorf("STALE provenance allowlist entry: %s no longer exists (renamed, deleted, or emptied)", key)
			continue
		}
		if fixtureHasProvenance(t, onDisk) {
			t.Errorf("STALE provenance allowlist entry: %s now HAS provenance. Delete the entry — a list "+
				"that outlives its reason quietly excuses the next fixture that arrives without any.", key)
		}
	}
}

// --- discovery ----------------------------------------------------------------

func countClass(c parserClass) int {
	n := 0
	for _, v := range parserClassification {
		if v.class == c {
			n++
		}
	}
	return n
}

// discoverJSONDecoders returns "<file>:<func>" for every non-test function under
// root that calls json.Unmarshal or json.NewDecoder.
func discoverJSONDecoders(t *testing.T, root string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || d.Name() == "vendor" || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		rel := repoRelPath(p)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if !bodyDecodesJSON(fn.Body) {
				continue
			}
			out = append(out, rel+":"+declName(fn))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(out)
	return out
}

func bodyDecodesJSON(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "json" {
			return true
		}
		if sel.Sel.Name == "Unmarshal" || sel.Sel.Name == "NewDecoder" {
			found = true
		}
		return true
	})
	return found
}

// discoverFixtureCoveredFuncs returns "<pkgdir>:<func>" for every function
// CALLED by a _test.go file in a package whose test files also reference the
// fixtures tree.
//
// File-granular by design — see the header's blind-spot note.
func discoverFixtureCoveredFuncs(t *testing.T, root string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	calls := map[string]bool{}
	pkgHasFixtureRef := map[string]bool{}
	var testFiles []struct {
		dir  string
		file *ast.File
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(p) //nolint:gosec
		if rerr != nil {
			return rerr
		}
		f, perr := parser.ParseFile(fset, p, src, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		dir := repoRelPath(filepath.Dir(p))
		if strings.Contains(string(src), "fixtures") {
			pkgHasFixtureRef[dir] = true
		}
		testFiles = append(testFiles, struct {
			dir  string
			file *ast.File
		}{dir, f})
		return nil
	})
	if err != nil {
		t.Fatalf("walk tests: %v", err)
	}

	for _, tf := range testFiles {
		if !pkgHasFixtureRef[tf.dir] {
			continue
		}
		ast.Inspect(tf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.Ident:
				calls[tf.dir+":"+fun.Name] = true
			case *ast.SelectorExpr:
				calls[tf.dir+":"+fun.Sel.Name] = true
			}
			return true
		})
	}
	return calls
}

// discoverFixtures returns every regular file under a testdata/fixtures tree.
func discoverFixtures(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		norm := filepath.ToSlash(p)
		if !strings.Contains(norm, "/testdata/fixtures/") {
			return nil
		}
		base := d.Name()
		if base == ".gitkeep" || strings.HasSuffix(base, ".provenance") {
			return nil
		}
		info, ierr := d.Info()
		if ierr == nil && info.Size() == 0 {
			return nil // an empty stub is not yet a fixture
		}
		// The ON-DISK path, not the repo-relative display form. The test's cwd is
		// the package directory, so reading a repo-relative path here silently
		// fails and every fixture reads as "no provenance" — which is exactly what
		// the first version of this test reported for two fixtures that have had
		// correct headers since June.
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	sort.Strings(out)
	return out
}

// fixtureHasProvenance accepts a leading `# captured-from:` comment or a
// `<file>.provenance` sidecar. The sidecar exists for formats where a leading
// comment is not legal — a single JSON document, for instance — so those are
// handled rather than silently exempted.
func fixtureHasProvenance(t *testing.T, onDisk string) bool {
	t.Helper()
	if _, err := os.Stat(onDisk + ".provenance"); err == nil {
		return true
	}
	data, err := os.ReadFile(onDisk) //nolint:gosec
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			if strings.Contains(line, "captured-from:") {
				return true
			}
			continue
		}
		return false
	}
	return false
}

// --- the detector's own proof ---------------------------------------------------

// TestOutputContractDetector proves the detector works against fixtures, in both
// directions.
//
// THIS IS THE ASSERTION THAT MAKES THE REST NON-VACUOUS. Reduce
// discoverJSONDecoders to `return nil` and every other test in this file stays
// green: no decoders found means nothing unclassified, nothing uncovered,
// nothing stale. A detector that can be neutered by one edit while the suite
// reports success is the exact shape this plan exists to close — it would just
// be living inside the thing built to close it.
func TestOutputContractDetector(t *testing.T) {
	root := filepath.Join("testdata", "outputcontract")

	t.Run("discovers exactly the decoding functions", func(t *testing.T) {
		got := discoverJSONDecoders(t, root)
		var names []string
		for _, g := range got {
			names = append(names, g[strings.LastIndex(g, ":")+1:])
		}
		sort.Strings(names)
		want := []string{"fixtureTask.methodDecoder", "nestedDecoder", "streamDecoder", "unmarshalDecoder"}
		if !equalStringSlices(names, want) {
			t.Fatalf("discovered %v, want exactly %v\n"+
				"  MISSING names mean a real parser would go unclassified and unguarded — and an EMPTY\n"+
				"  result makes every other assertion in this file vacuously true.\n"+
				"  EXTRA names mean json.Marshal or a bare mention is being counted as a decode, which\n"+
				"  would demand fixtures for functions that read nothing.", names, want)
		}
	})

	t.Run("does not flag marshalling or unrelated functions", func(t *testing.T) {
		for _, g := range discoverJSONDecoders(t, root) {
			for _, bad := range []string{"notADecoder", "alsoNotADecoder"} {
				if strings.HasSuffix(g, ":"+bad) {
					t.Errorf("%s was reported as a JSON decoder — it is not one, and a detector that "+
						"flags correct code gets deleted by the first person it inconveniences", bad)
				}
			}
		}
	})

	t.Run("provenance: header, sidecar, and absence", func(t *testing.T) {
		base := filepath.Join(root, "fixtures")
		cases := []struct {
			file string
			want bool
			why  string
		}{
			{"with_provenance.jsonl", true, "a leading # captured-from: comment"},
			{"sidecar_covered.json", true, "a .provenance sidecar, for formats where a comment is not legal"},
			{"without_provenance.jsonl", false, "nothing recording where it came from"},
		}
		for _, c := range cases {
			got := fixtureHasProvenance(t, filepath.Join(base, c.file))
			if got != c.want {
				t.Errorf("fixtureHasProvenance(%s) = %v, want %v — %s", c.file, got, c.want, c.why)
			}
		}
	})
}

// TestOutputContractSkipsOwnTestdata asserts the real-tree walk does not pick up
// the detector's own fixtures, whose decoders would otherwise appear as
// unclassified parsers and make the census permanently red.
func TestOutputContractSkipsOwnTestdata(t *testing.T) {
	for _, g := range discoverJSONDecoders(t, ".") {
		if strings.Contains(g, "/testdata/") {
			t.Errorf("the real-tree walk reported a fixture: %s", g)
		}
	}
}

func equalStringSlices(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
