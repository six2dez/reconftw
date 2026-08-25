// result_reason_test.go — the Result constructors and the rule they encode.
//
// THE RULE: a non-Done status without a Reason is a bug. "[SKIP] web.nuclei 0s"
// answers nothing; "templates path not configured" answers it.

package task_test

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"
)

func TestProducedIsDoneWithNoReason(t *testing.T) {
	r := task.Produced("hosts_found", 3, "artefacts/hosts.jsonl")
	if r.Status != task.StatusDone {
		t.Errorf("Status = %q, want done", r.Status)
	}
	if r.Reason != "" {
		t.Errorf("Reason = %q, want empty — a Done status needs no explanation", r.Reason)
	}
	if r.Stats["hosts_found"] != 3 {
		t.Errorf("Stats[hosts_found] = %d, want 3", r.Stats["hosts_found"])
	}
	if len(r.Outputs) != 1 {
		t.Errorf("Outputs = %v, want the single path", r.Outputs)
	}
}

func TestNothingProducedIsSkippedWithReason(t *testing.T) {
	r := task.NothingProduced("probed 30 host(s), no live host survived")
	if r.Status != task.StatusSkipped {
		t.Errorf("Status = %q, want skipped", r.Status)
	}
	if r.Reason == "" {
		t.Fatal("NothingProduced returned an empty Reason — the whole point is the answer")
	}
}

// TestToolDegradedIsDistinguishableFromNothingProduced is the assertion that
// keeps the two facts apart. "The tool broke" and "the tool worked and found
// nothing" shared a message for months, and takeover detection produced zero the
// whole time without anyone noticing.
func TestToolDegradedIsDistinguishableFromNothingProduced(t *testing.T) {
	degraded := task.ToolDegraded("dnstake", stderrors.New("flag provided but not defined: -f"))
	nothing := task.NothingProduced("scanned 12 host(s), none vulnerable")

	if degraded.Status != task.StatusSkipped || nothing.Status != task.StatusSkipped {
		t.Fatal("both are skips — the STATUS is not what distinguishes them")
	}
	if degraded.Reason == nothing.Reason {
		t.Fatal("a failed tool and a clean result produce the same Reason")
	}
	if !strings.Contains(degraded.Reason, "dnstake") {
		t.Errorf("ToolDegraded Reason %q does not name the tool", degraded.Reason)
	}
	if !strings.Contains(degraded.Reason, "flag provided but not defined") {
		t.Errorf("ToolDegraded Reason %q dropped the tool's own account of the failure", degraded.Reason)
	}
}

// TestToolDegradedTolaratesNilCause: the helper must not panic on a nil error.
func TestToolDegradedToleratesNilCause(t *testing.T) {
	r := task.ToolDegraded("subzy", nil)
	if r.Status != task.StatusSkipped || r.Reason == "" {
		t.Errorf("ToolDegraded(nil cause) = %+v, want a skip with a reason", r)
	}
}
