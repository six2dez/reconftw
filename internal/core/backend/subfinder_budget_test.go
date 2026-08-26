// subfinder_budget_test.go — CR-07, the half that lives below the module layer.
//
// Two facts have to hold together for subfinder's budget to mean anything, and
// they are owned by different files:
//
//	(a) internal/modules/subdomains passes -max-time in MINUTES
//	    (TestSubfinderMaxTimeIsInMinutesAtBothCallSites)
//	(b) the process deadline in tools.lock is not SHORTER than the budget (a)
//	    asks for — otherwise the manifest silently wins and (a) is decoration
//
// This file owns (b), and pins the consequence of losing it: a tool killed by
// its deadline loses every byte it had already written.

package backend_test

import (
	"context"
	stderrors "errors"
	"os"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// TestSubfinderProcessDeadlineCoversItsOwnBudget asserts the RELATIONSHIP
// between the two numbers rather than either literal, so a later change to
// config default or manifest cannot reintroduce the inversion while both values
// still look individually reasonable.
func TestSubfinderProcessDeadlineCoversItsOwnBudget(t *testing.T) {
	tool, ok := backend.Default.Lookup("subfinder")
	if !ok {
		t.Fatal("subfinder is not in the seeded registry — the manifest entry did not load")
	}

	budget := time.Duration(config.Defaults().Advanced.Tools.Subfinder.TimeoutMinutes) * time.Minute
	if budget <= 0 {
		t.Fatal("config default advanced.tools.subfinder.timeout_minutes is not positive; " +
			"subfinder would be dispatched with a meaningless -max-time")
	}

	if tool.Timeout > 0 && tool.Timeout < budget {
		t.Fatalf("subfinder's process deadline (%v, tools.lock timeout_seconds) is SHORTER than the "+
			"budget it is asked to honour (%v, advanced.tools.subfinder.timeout_minutes).\n"+
			"  The manifest then silently wins: subfinder is killed at %v regardless of -max-time,\n"+
			"  and LocalBackend discards the stdout it had already produced, so the primary passive\n"+
			"  source contributes ZERO rather than a partial set. v1 allows the full %v.\n"+
			"  Fix ONE of the two — raise timeout_seconds in tools.lock, or lower timeout_minutes.",
			tool.Timeout, budget, tool.Timeout, budget)
	}
}

// TestDeadlineDiscardsBufferedStdout pins a DECISION, not an accident.
//
// The buffered Exec path returns `nil, &ToolTimeout` when the deadline fires,
// throwing away everything the tool had already written to stdout. v1's
// equivalent (`subfinder … -o file`) keeps whatever reached the file.
//
// 17-07 chose NOT to change this, and the choice is pinned here so it stays a
// choice:
//
//   - Every caller today is `res, err := Run(...); if err != nil { … }`. Making
//     a timeout return a non-nil Result would only matter if a caller then
//     treated partial output as a complete result — and a passive source that
//     reports Done on a partial set is the outcome-mislabelling shape phase 16
//     spent a plan removing. The affected callers, all of which would have had
//     to make that judgement individually, are: runPassiveTask (subfinder, crt,
//     github-subdomains, gitlab-subdomains, urlfinder),
//     SubRecursivePassiveTask's per-target loop, and every other buffered
//     app.Tools.Run caller in internal/modules.
//   - The real remedy for subfinder was the deadline itself, reconciled above.
//     Measured 2026-08-26: subfinder emitted all 121 hosts for owasp.org inside
//     a single second at the END of a 31s run, so for this tool the discarded
//     buffer would usually have been empty anyway.
//
// THE COST, stated rather than hidden: a bounded tool's partial work is
// unrecoverable. If a future tool streams results steadily and is expected to be
// cut off, this decision has to be revisited — deliberately, with this test as
// the place the new answer is written down.
func TestDeadlineDiscardsBufferedStdout(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh is not present, so a real-process deadline cannot be demonstrated")
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "chattyslow", Path: "/bin/sh", Timeout: 400 * time.Millisecond})
	runner := backend.NewRunner(backend.NewLocalBackend(time.Second), reg, nil)

	res, err := runner.Run(context.Background(), "chattyslow",
		[]string{"-c", "echo partial.example.com; sleep 30"})

	if err == nil {
		t.Fatal("a tool that outlived its deadline returned no error")
	}
	var tt *coreerrors.ToolTimeout
	if !stderrors.As(err, &tt) {
		t.Fatalf("err = %v (%T), want *ToolTimeout", err, err)
	}
	if res != nil {
		t.Fatalf("Run returned a non-nil Result alongside a timeout (%d bytes of stdout).\n"+
			"  That is a DIFFERENT contract from the one documented on this test. If the change was\n"+
			"  deliberate, rewrite this test and the tools.lock comment to say what every caller now\n"+
			"  sees — do not leave the two disagreeing.", len(res.Stdout))
	}
}
