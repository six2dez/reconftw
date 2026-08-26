// nuclei_coverage.go — template-execution accounting for every nuclei group.
//
// WHY THIS FILE EXISTS. On 2026-08-24 the parity verdict was signed BLOCKED
// because two known-good templates (`keycloak-openid-config`, `oidc-detect`) did
// not fire in v2's full nuclei run and fired instantly in a targeted two-template
// probe against the same host, same box, same template directory. Four benign
// explanations were each eliminated by observation (16-06-PARITY.md §6.1). What
// remained was not a wrong number but an ABSENCE: "nuclei ran and exited 0" was
// compatible with nuclei having executed 49 templates or 13,000, and nothing in
// the workspace could tell those apart.
//
// The run's 49 distinct template IDs is a MATCH count, not an execution count —
// a template that runs and finds nothing emits nothing — so it cannot arbitrate.
// This record is the arbitration.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE PROXY DECLARATION — READ THIS BEFORE USING ANY NUMBER BELOW
// ─────────────────────────────────────────────────────────────────────────────
// RequestsSent is a PROXY for template execution, not a count of it. nuclei
// emits no per-template execution report; its only per-request evidence is the
// `-tlog` request trace, which for a 12-host run over ~13,000 templates runs to
// millions of lines. So per-template execution — "did keycloak-openid-config run
// against host 6?" — is NOT bounded by a production record and this record does
// not claim otherwise. What it bounds is the AGGREGATE: how many templates the
// filter set selected, how many the engine loaded, how many requests it planned,
// how many it actually sent, and which hosts it stopped scanning and why.
//
// That narrowing is declared in the record's own schema (ExecutionBasis) and
// asserted by a test, because an UNDECLARED proxy metric is exactly how "49
// distinct template IDs" became a coverage number in the first place. Repeating
// that error one level down, inside the fix for it, would be the worst outcome
// available here.
//
// Per-template answerability exists for FIXTURE runs, where the trace volume is
// bounded and the target is loopback: scripts/nuclei-coverage-probe.sh enables
// `-tlog` on its own invocations and answers the per-template question there.
// See 17-05-NUCLEI-COVERAGE.md.
//
// ─────────────────────────────────────────────────────────────────────────────
// UNKNOWN IS NOT ZERO
// ─────────────────────────────────────────────────────────────────────────────
// Every count nuclei reports is a *int and is nil — JSON `null` — when nuclei
// did not report it. A record that says 0 where it means "I could not tell"
// would reproduce this phase's entire defect class inside its own remedy, so the
// distinction is structural rather than conventional: there is no way to write a
// zero for a missing observation without deliberately dereferencing a nil.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHERE THE NUMBERS COME FROM (measured on this machine, nuclei v3.7.1)
// ─────────────────────────────────────────────────────────────────────────────
//   - `-stats -sj -si N` writes one JSON object per interval, and a final one at
//     scan end, to STDERR. It carries templates / hosts / requests / total /
//     matched / errors / percent / duration / rps / startedAt, all as STRINGS.
//     It is fully compatible with `-silent` and never touches stdout.
//   - `-silent` SUPPRESSES the `[INF] Skipped <host> from target list as found
//     unresponsive permanently: ...` notices. This is the per-host error budget
//     (`-mhe`, default 30) firing, and with `-silent` present the run has no
//     record of it at all — verified by an A/B on an identical fixture. That is
//     why the production vector no longer passes `-silent`: dropping it changes
//     NOTHING on stdout (findings still arrive as JSONL on stdout and in the
//     `-o` staging file) and adds nuclei's own account to stderr.
//   - `-tl` is a LISTING mode, not a scan: it prints one absolute template path
//     per line to stdout under the current filters. Cost on this machine against
//     ~/nuclei-templates with the production severity filter: 182 s cold (first
//     signature-verification walk), 1-2 s warm, 13,143 templates selected.
package web

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// nucleiCoverageSchema versions the record. A consumer that does not recognise
// the value must refuse to interpret the fields rather than guess.
const nucleiCoverageSchema = "nuclei-coverage/v1"

// nucleiCoverageFile is the workspace-relative path every record is appended to.
const nucleiCoverageFile = "logs/nuclei-coverage.jsonl"

// nucleiExecutionBasis is the proxy declaration carried IN the record, in the
// record's own words, so no reader of a bare JSONL line can mistake the proxy
// for the thing. NucleiCoverage.Validate rejects a record without it.
const nucleiExecutionBasis = "requests_sent is a PROXY for template execution, not a count of it: " +
	"it bounds coverage at the AGGREGATE level only. Per-template execution " +
	"(\"did template X run against host Y?\") is NOT bounded by a production record — " +
	"nuclei emits no per-template execution report and its only per-request evidence " +
	"(-tlog) is prohibitive at production volume. Fixture runs are the exception; see " +
	"scripts/nuclei-coverage-probe.sh."

// NucleiHostDrop is one host the engine stopped scanning early, with nuclei's
// own stated cause.
type NucleiHostDrop struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// NucleiCoverage is one nuclei group's account of what it covered.
//
// Every *int field is nil ("null") when nuclei did not report the number. nil
// means UNKNOWN and never zero — see the file header.
type NucleiCoverage struct {
	Schema string `json:"schema"`
	// ExecutionBasis names what this record's execution claim rests on. It is
	// asserted non-empty by Validate; a declaration nothing enforces is a comment.
	ExecutionBasis string `json:"execution_basis"`

	Tool       string `json:"tool"`
	Group      string `json:"group"`
	RecordedAt string `json:"recorded_at"`

	// FilterSelected is how many templates `-tl` reported under this group's
	// filter set. nil when the listing was not run or could not be parsed.
	FilterSelected *int `json:"filter_selected"`
	// TemplatesLoaded is how many templates the ENGINE reported loading for the
	// scan (`templates` in the -sj stats object).
	TemplatesLoaded *int `json:"templates_loaded"`

	// HostsSubmitted is how many hosts v2 wrote into the -l input file. This one
	// is always known: v2 counted them itself.
	HostsSubmitted int `json:"hosts_submitted"`
	// HostsSeenByEngine is nuclei's own host count from the stats object.
	HostsSeenByEngine *int `json:"hosts_seen_by_engine"`

	// RequestsPlanned is `total` from the stats object — the request budget the
	// loaded template set implies. RequestsSent is `requests`.
	RequestsPlanned *int `json:"requests_planned"`
	RequestsSent    *int `json:"requests_sent"`
	RequestErrors   *int `json:"request_errors"`

	// HostsDropped counts the per-host-error-budget skips nuclei announced.
	// nil when the argv suppressed the notices (`-silent`), which is precisely
	// the state the 2026-08-24 run was in.
	HostsDropped       *int             `json:"hosts_dropped"`
	HostsDroppedDetail []NucleiHostDrop `json:"hosts_dropped_detail"`

	// Matched is nuclei's own match count; FindingsParsed is how many records v2
	// actually decoded from the staging file. A gap between them is a parser bug.
	Matched        *int `json:"matched"`
	FindingsParsed *int `json:"findings_parsed"`

	// TerminatedEarly marks a group whose stream ended badly. Its findings are
	// discarded by the F6 rule, but the coverage record is written anyway:
	// coverage evidence about a failed run is worth more than evidence about a
	// clean one.
	TerminatedEarly  bool   `json:"terminated_early"`
	TerminationError string `json:"termination_error,omitempty"`

	// Argv is the exact vector this group dispatched. The whole question is
	// which flags shaped the coverage, so the flags are in the record.
	Argv []string `json:"argv"`
}

// newNucleiCoverage starts a record for a group. Every count begins UNKNOWN,
// with ONE argv-derived exception.
//
// HostsDropped is the exception, and the reason is the whole plan. nuclei
// announces a per-host-error-budget skip and says nothing at all when it skips
// nothing — so an absent notice is ambiguous between "no host was dropped" and
// "I would not have been told". The argv resolves that ambiguity and nothing
// else can: `-silent` suppresses the notices, so under `-silent` the count is
// genuinely UNKNOWN, and without it a run that saw no notice has OBSERVED zero
// drops. The 2026-08-24 parity run was in the first state and its record read
// like the second, which is exactly the confusion this constructor refuses to
// reproduce.
func newNucleiCoverage(group string, hostsSubmitted int, argv []string) *NucleiCoverage {
	c := &NucleiCoverage{
		Schema:             nucleiCoverageSchema,
		ExecutionBasis:     nucleiExecutionBasis,
		Tool:               "nuclei",
		Group:              group,
		RecordedAt:         time.Now().UTC().Format(time.RFC3339),
		HostsSubmitted:     hostsSubmitted,
		HostsDroppedDetail: []NucleiHostDrop{},
		Argv:               append([]string(nil), argv...),
	}
	if nucleiDropNoticesObservable(argv) {
		zero := 0
		c.HostsDropped = &zero
	}
	return c
}

// nucleiDropNoticesObservable reports whether this argv lets nuclei's per-host
// skip notices reach the stream at all.
func nucleiDropNoticesObservable(argv []string) bool {
	for _, a := range argv {
		if a == "-silent" || a == "--silent" {
			return false
		}
	}
	return true
}

// nucleiStatsLine is the `-stats -sj` object. nuclei emits every value as a
// STRING, including the numbers — decoding these as int silently fails the whole
// line, which is the httpxRaw.Port shape that emptied the web layer for two
// months. They are strings here and converted explicitly.
type nucleiStatsLine struct {
	Duration  string `json:"duration"`
	Errors    string `json:"errors"`
	Hosts     string `json:"hosts"`
	Matched   string `json:"matched"`
	Percent   string `json:"percent"`
	Requests  string `json:"requests"`
	RPS       string `json:"rps"`
	StartedAt string `json:"startedAt"`
	Templates string `json:"templates"`
	Total     string `json:"total"`
}

// atoiPtr converts a nuclei stats string to *int. A value that is empty or does
// not parse yields nil — UNKNOWN — rather than zero.
func atoiPtr(s string) *int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &n
}

// nucleiSkipPrefix is the marker nuclei prints when the per-host error budget
// (-mhe) removes a host mid-scan. Matched on the substring rather than the
// whole line because the line carries an ANSI-coloured `[INF]` prefix when
// stderr is a terminal.
const nucleiSkipMarker = "from target list as found unresponsive"

// observeLine feeds one raw stream line into the record.
//
// isErr selects nuclei's stderr, which is where BOTH accounting channels live:
// the -sj stats objects and the -mhe skip notices. stdout carries findings JSONL
// and is deliberately ignored here — the findings path reads the -o staging file.
//
// Later stats objects supersede earlier ones: nuclei emits one per interval and
// a final one at scan end, and the last is the complete account.
func (c *NucleiCoverage) observeLine(line []byte, isErr bool) {
	if c == nil || !isErr {
		return
	}
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return
	}

	if trimmed[0] == '{' {
		var st nucleiStatsLine
		if err := json.Unmarshal(trimmed, &st); err == nil && st.Templates != "" {
			c.TemplatesLoaded = atoiPtr(st.Templates)
			c.HostsSeenByEngine = atoiPtr(st.Hosts)
			c.RequestsSent = atoiPtr(st.Requests)
			c.RequestsPlanned = atoiPtr(st.Total)
			c.RequestErrors = atoiPtr(st.Errors)
			c.Matched = atoiPtr(st.Matched)
		}
		return
	}

	if strings.Contains(string(trimmed), nucleiSkipMarker) {
		host, reason := parseNucleiSkipNotice(string(trimmed))
		c.HostsDroppedDetail = append(c.HostsDroppedDetail, NucleiHostDrop{Host: host, Reason: reason})
		n := len(c.HostsDroppedDetail)
		c.HostsDropped = &n
	}
}

// parseNucleiSkipNotice pulls the host and the stated cause out of a line shaped
//
//	[INF] Skipped 127.0.0.1:18799 from target list as found unresponsive permanently: cause="port closed or filtered" ...
//
// Returns the raw line as the reason when the shape does not match, because a
// reason we could not parse is still evidence and dropping it would be the
// silent-degradation failure this file exists to prevent.
func parseNucleiSkipNotice(line string) (host, reason string) {
	reason = line
	if i := strings.Index(line, ": "); i >= 0 {
		if r := strings.TrimSpace(line[i+2:]); r != "" {
			reason = r
		}
	}
	const skipped = "Skipped "
	i := strings.Index(line, skipped)
	if i < 0 {
		return "", reason
	}
	rest := line[i+len(skipped):]
	j := strings.Index(rest, " from target list")
	if j < 0 {
		return "", reason
	}
	return strings.TrimSpace(rest[:j]), reason
}

// parseNucleiTemplateList counts the template paths in `-tl` stdout.
//
// `-tl` prefixes the list with a blank line and a "Listing available vN
// nuclei templates for <dir>" header, so the count is of lines that actually
// look like a template file. Returns nil — UNKNOWN — when the output contains no
// template path at all, rather than 0: "the listing did not run" and "the filter
// selected nothing" are different facts with different remedies.
func parseNucleiTemplateList(stdout []byte) *int {
	n := 0
	for _, raw := range strings.Split(string(stdout), "\n") {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		if strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".json") {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return &n
}

// markTerminated records that this group's stream ended badly. The record is
// still written; only the findings are discarded.
func (c *NucleiCoverage) markTerminated(err error) {
	if c == nil || err == nil {
		return
	}
	c.TerminatedEarly = true
	c.TerminationError = err.Error()
}

// setFindingsParsed records how many findings v2 decoded from the staging file.
func (c *NucleiCoverage) setFindingsParsed(n int) {
	if c == nil {
		return
	}
	c.FindingsParsed = &n
}

// errNucleiCoverageNoBasis is returned by Validate for a record whose proxy
// declaration was dropped.
type nucleiCoverageError string

func (e nucleiCoverageError) Error() string { return string(e) }

const errNucleiCoverageNoBasis = nucleiCoverageError(
	"nuclei coverage record has an empty execution_basis: the record would state a " +
		"coverage number without declaring that requests_sent is a proxy for execution, " +
		"which is the exact error (an undeclared proxy read as a count) that this record exists to prevent")

// Validate rejects a record that would mislead a reader.
func (c *NucleiCoverage) Validate() error {
	if c == nil || strings.TrimSpace(c.ExecutionBasis) == "" {
		return errNucleiCoverageNoBasis
	}
	return nil
}

// writeNucleiCoverage appends the record to <workDir>/logs/nuclei-coverage.jsonl.
//
// Append, not replace: a run has one record per nuclei GROUP (normal + waf) and
// both belong in the file. The file is 0o600 for the same reason logs/tools.jsonl
// is — it names hosts that were scanned.
func writeNucleiCoverage(workDir string, c *NucleiCoverage) error {
	if err := c.Validate(); err != nil {
		return err
	}
	path := filepath.Join(workDir, filepath.FromSlash(nucleiCoverageFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}
