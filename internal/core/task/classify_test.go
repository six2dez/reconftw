package task_test

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/task"
)

func TestClassifyToolErr(t *testing.T) {
	absent := &coreerrors.ToolError{Tool: "dalfox", ExitCode: -1, Inner: stderrors.New("tool not registered"), NeverStarted: true}
	exit2 := &coreerrors.ToolError{Tool: "dalfox", ExitCode: 2, Inner: stderrors.New("exit status 2"), Stderr: "unexpected argument"}
	timeout := &coreerrors.ToolTimeout{Tool: "fray", Timeout: 300 * time.Second}

	cases := []struct {
		name       string
		err        error
		wantStatus task.Status
		wantReason string // exact when non-empty
		wantSubstr string // substring when non-empty
	}{
		{"nil is done", nil, task.StatusDone, "", ""},
		{"never started is absent", absent, task.StatusSkipped, task.ReasonToolAbsent, ""},
		{"wrapped never started is absent", fmt.Errorf("vulns.xss: %w", absent), task.StatusSkipped, task.ReasonToolAbsent, ""},
		{"exit non-zero is degraded, names the tool", exit2, task.StatusSkipped, "", "dalfox: "},
		{"exit non-zero keeps stderr", exit2, task.StatusSkipped, "", "unexpected argument"},
		{"timeout is degraded, names the tool", timeout, task.StatusSkipped, "", "fray: "},
		{"cancelled is cancelled", fmt.Errorf("run: %w", context.Canceled), task.StatusCancelled, "", "canceled"},
		{"opaque error is degraded", stderrors.New("boom"), task.StatusSkipped, "tool: boom", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, reason := task.ClassifyToolErr(tc.err)
			if st != tc.wantStatus {
				t.Fatalf("status = %q, want %q (reason %q)", st, tc.wantStatus, reason)
			}
			if tc.wantReason != "" && reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
			if tc.wantSubstr != "" && !contains(reason, tc.wantSubstr) {
				t.Errorf("reason = %q, want it to contain %q", reason, tc.wantSubstr)
			}
			if st != task.StatusDone && reason == "" {
				t.Errorf("non-Done status %q with an empty Reason — the whole point of the policy", st)
			}
		})
	}
}

// TestClassifyToolErrAbsentAndFailedNeverShareAReason is the property the
// policy exists for: "the tool broke" and "the tool is not installed" must never
// produce the same text.
func TestClassifyToolErrAbsentAndFailedNeverShareAReason(t *testing.T) {
	_, absent := task.ClassifyToolErr(&coreerrors.ToolError{Tool: "x", ExitCode: -1, NeverStarted: true})
	_, failed := task.ClassifyToolErr(&coreerrors.ToolError{Tool: "x", ExitCode: 1, Inner: stderrors.New("exit status 1")})
	if absent == failed {
		t.Fatalf("absent and failed share the reason %q", absent)
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
