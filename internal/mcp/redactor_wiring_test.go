// redactor_wiring_test.go — V-01: every run this transport starts must carry the
// server's redactor.
//
// The hole this pins was PRE-EXISTING and silent: newToolDeps built RunOptions
// with only ConfigPath/SecretsPath, so secretsOrNil/registrarOrNil both saw nil,
// backend.NewToolRecorder got a nil redactor ("degrades to NO redaction ... not a
// safe default"), and app.Secrets was nil. Every MCP-driven scan wrote
// logs/tools.jsonl unredacted. Nothing failed; nothing said so.
package mcp

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// stubSched supplies the one dependency runOptions() dereferences, so these tests
// exercise the wiring under test rather than dying on an unrelated nil.
func stubSched() *scheduler.Scheduler { return &scheduler.Scheduler{} }

// TestToolDepsCarriesTheServerRedactor asserts the redactor handed to newToolDeps
// reaches RunOptions.Secrets, and survives the per-call copy runOptions() makes.
//
// Asserting on the SNAPSHOT alone would not be enough: runOptions() is what every
// tool handler actually calls, and a field dropped there would leave this green
// while production stayed unredacted.
func TestToolDepsCarriesTheServerRedactor(t *testing.T) {
	rdct := &log.Redactor{}
	const canary = "SERVER-REDACTOR-CANARY-VALUE"
	rdct.Register(canary)

	d := newToolDeps(nil, stubSched, nil, rdct, nil, "", "", t.Context())

	if d.base.Secrets == nil {
		t.Fatal("RunOptions.Secrets is nil — the MCP transport starts every scan with NO " +
			"redaction: NewToolRecorder gets a nil redactor and app.Secrets is nil, so " +
			"credentials on argv reach logs/tools.jsonl in clear text (V-01)")
	}

	opts := d.runOptions("example.com", false, "")
	if opts.Secrets == nil {
		t.Fatal("runOptions() dropped Secrets — the snapshot carries it but the per-call " +
			"copy every handler uses does not, so production is still unredacted")
	}
	// It must be the SAME redactor, carrying what was registered at startup — not a
	// fresh empty one, which would satisfy a nil-check and redact nothing.
	if got := opts.Secrets.Redact(canary); got == canary {
		t.Errorf("the run's redactor does not know the server's registered secrets: "+
			"Redact(%q) returned it unchanged", canary)
	}
}

// TestToolDepsNilRedactorStaysNil guards the interface-wrapping trap secretsOrNil
// exists to prevent: assigning a nil *log.Redactor to the RunSecrets interface
// yields a NON-nil interface holding a nil pointer, which would defeat every
// downstream nil-check and hand the recorder a live-looking redactor.
func TestToolDepsNilRedactorStaysNil(t *testing.T) {
	d := newToolDeps(nil, stubSched, nil, nil, nil, "", "", t.Context())
	if d.base.Secrets != nil {
		t.Fatal("a nil *log.Redactor was wrapped into a non-nil RunSecrets interface — " +
			"secretsOrNil's narrowing is defeated and downstream nil-checks all lie")
	}
}
