// redaction_sink_test.go — the sink-level guard for the terminal path.
//
// The end-to-end proof lives in cmd/reconftw/redaction_e2e_test.go, where the
// real binary runs a real stub tool and the real wiring is exercised. This file
// guards the seam itself, at the level where a regression is cheapest to see:
// that taskDone applies the redactor, that it applies it to the REASON and not
// merely somewhere, that a nil redactor is still the pre-plan behaviour, and
// that redaction does not degrade into blanking the line.
//
// It is an INTERNAL test (package ui) because forceTTY is unexported and the
// TTY branch is a separate formatting path with its own Fprintf — a guard that
// covered only the plain-text branch would go green while the branch an operator
// actually sees leaked.

package ui

import (
	"bytes"
	"strings"
	"testing"
)

// stubRedactor replaces every occurrence of secret with "***" and counts calls,
// so a test can distinguish "the redactor was consulted and found nothing" from
// "the redactor was never consulted at all".
type stubRedactor struct {
	secret string
	calls  int
}

func (s *stubRedactor) Redact(in string) string {
	s.calls++
	if s.secret == "" {
		return in
	}
	return strings.ReplaceAll(in, s.secret, "***")
}

const sinkSecret = "Sh0dAnK3y7Qx2Wv9Zb4Nm6Tj"

// leakyReason is the exact shape task.ToolDegraded produces once
// errors.ToolError.Error() appends the tool's stderr tail (plan 16-01).
const leakyReason = "dnstake: tool dnstake (exit 1): exit status 1: " + sinkSecret

func TestStageProgressRedactsReasonOnPlainTextSink(t *testing.T) {
	var buf bytes.Buffer
	p := NewStageProgress(&buf, true, VerbosityNormal) // noColor → plain-text branch
	r := &stubRedactor{secret: sinkSecret}
	p.SetRedactor(r)

	p.StageStart("subdomains", 1)
	p.TaskDoneReason("subdomains.takeover.dnstake", BadgeSKIP, 0, leakyReason)

	got := buf.String()
	if r.calls == 0 {
		t.Fatal("the redactor was never consulted — the seam is not wired into taskDone")
	}
	if strings.Contains(got, sinkSecret) {
		t.Errorf("secret rendered verbatim on the plain-text sink:\n%s", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("no redaction placeholder in the rendered line:\n%s", got)
	}
}

func TestStageProgressRedactsReasonOnTTYSink(t *testing.T) {
	var buf bytes.Buffer
	p := NewStageProgress(&buf, false, VerbosityNormal)
	p.forceTTY = true // the ANSI branch is a separate Fprintf and needs its own proof
	r := &stubRedactor{secret: sinkSecret}
	p.SetRedactor(r)

	p.StageStart("subdomains", 1)
	p.TaskDoneReason("subdomains.takeover.dnstake", BadgeSKIP, 0, leakyReason)

	got := buf.String()
	if strings.Contains(got, sinkSecret) {
		t.Errorf("secret rendered verbatim on the ANSI/TTY sink:\n%q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("no redaction placeholder on the ANSI/TTY sink:\n%q", got)
	}
}

// TestStageProgressRedactedLineStaysInformative is threat T-17-01-05. Over-
// redaction that swallows the whole line would trade an information-disclosure
// defect for a repudiation one: the operator would see a SKIP with no cause,
// which is the silent-success state the Reason field was added to end.
func TestStageProgressRedactedLineStaysInformative(t *testing.T) {
	var buf bytes.Buffer
	p := NewStageProgress(&buf, true, VerbosityNormal)
	p.SetRedactor(&stubRedactor{secret: sinkSecret})

	p.StageStart("subdomains", 1)
	p.TaskDoneReason("subdomains.takeover.dnstake", BadgeSKIP, 0, leakyReason)

	got := strings.TrimSpace(buf.String())
	line := lastLine(got)
	for _, want := range []string{"SKIP", "subdomains.takeover", "dnstake", "exit 1"} {
		if !strings.Contains(line, want) {
			t.Errorf("redaction removed %q from the task line — the operator can no "+
				"longer tell what degraded or why.\nline: %q", want, line)
		}
	}
}

// TestStageProgressNilRedactorIsUnchangedBehaviour pins the degradation
// contract: the zero value must render exactly what it rendered before this
// plan, or the five construction sites would each have needed an edit and any
// one that was missed would silently start dropping output.
func TestStageProgressNilRedactorIsUnchangedBehaviour(t *testing.T) {
	render := func(set bool) string {
		var buf bytes.Buffer
		p := NewStageProgress(&buf, true, VerbosityNormal)
		if set {
			p.SetRedactor(nil)
		}
		p.StageStart("subdomains", 1)
		p.TaskDoneReason("subdomains.takeover.dnstake", BadgeSKIP, 0, leakyReason)
		return buf.String()
	}
	never, explicitNil := render(false), render(true)
	if never != explicitNil {
		t.Errorf("SetRedactor(nil) differs from never calling it:\n%q\n%q", never, explicitNil)
	}
	if !strings.Contains(never, sinkSecret) {
		t.Errorf("a nil redactor must not alter the rendered reason; got:\n%q", never)
	}
}

// TestStageProgressRedactorAppliesToReasonNotTaskName guards against a "fix"
// that redacts the whole formatted line. The task name is developer-controlled
// and must never be mangled; only the untrusted reason is scrubbed.
func TestStageProgressRedactorAppliesToReasonNotTaskName(t *testing.T) {
	var buf bytes.Buffer
	p := NewStageProgress(&buf, true, VerbosityNormal)
	// A redactor that would eat the task name too, if it were ever handed one.
	p.SetRedactor(&stubRedactor{secret: "subdomains"})

	p.StageStart("subdomains", 1)
	p.TaskDoneReason("subdomains.takeover.dnstake", BadgeSKIP, 0, "dnstake: tool failed")

	line := lastLine(strings.TrimSpace(buf.String()))
	if !strings.Contains(line, "subdomains.takeover") {
		t.Errorf("the task name was passed through the redactor; it must not be.\nline: %q", line)
	}
}

// TestStageProgressTaskDoneCarriesNoReason pins the TaskDone/TaskDoneReason
// split the corrected package header now asserts.
func TestStageProgressTaskDoneCarriesNoReason(t *testing.T) {
	var buf bytes.Buffer
	p := NewStageProgress(&buf, true, VerbosityNormal)
	r := &stubRedactor{secret: sinkSecret}
	p.SetRedactor(r)

	p.StageStart("subdomains", 1)
	p.TaskDone("subdomains.takeover.dnstake", BadgeSKIP, 0)

	if r.calls != 0 {
		t.Errorf("TaskDone consulted the redactor %d times; it passes an empty "+
			"reason and must short-circuit", r.calls)
	}
}

func lastLine(s string) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return parts[len(parts)-1]
}
