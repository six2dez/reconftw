// These fixtures are INTENTIONALLY violating FOUND-10. Plan 18-03 consumes them
// as proof that the BYPASS-MANIFEST checks fire — not merely that they pass on a
// good input. A guard that has only ever been observed to pass is not a guard.
//
// Two shapes, deliberately different:
//
//	fixtureStdinShape — assigns cmd.Stdin, so the `stdin` reason IS corroborated.
//	fixtureBareShape  — assigns nothing, so NO vocabulary reason is corroborated.
//
// The pair is what lets the fixture test distinguish "the predicate found
// evidence" from "the predicate returns true for everything".
//
// Unlike testdata/violating.go these must TYPECHECK: the corroboration
// predicates resolve receiver types through go/types, so the fixture is loaded
// with NeedTypes|NeedTypesInfo.
//
// DO NOT FIX — their purpose is to be detected.
//go:build ignore_in_normal_build

package violating

import (
	"bytes"
	"context"
	"os/exec"
)

// fixtureStdinShape dispatches directly AND assigns standard input.
// Walker sites: 2 (exec.CommandContext + (*exec.Cmd).Run).
func fixtureStdinShape(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "fixture-stdin-tool")
	cmd.Stdin = bytes.NewReader([]byte("payload"))
	return cmd.Run()
}

// fixtureBareShape dispatches directly and assigns nothing at all — no stdin, no
// working directory, no process-group attribute, a bare tool name.
// Walker sites: 2 (exec.CommandContext + (*exec.Cmd).Run).
func fixtureBareShape(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "fixture-bare-tool")
	return cmd.Run()
}
