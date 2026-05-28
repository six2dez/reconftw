// This fixture is INTENTIONALLY violating FOUND-10. The lint test consumes it as
// proof that the AST walker fires correctly. It is under testdata/ so it is NOT
// built into the production binary (Go's `go build` excludes testdata/ from the
// regular dependency graph per its spec).
//
// DO NOT FIX — its purpose is to be detected by the scanner.
//go:build ignore_in_normal_build

package violating

import "os/exec"

func badCommand() {
	_ = exec.Command("foo")
}

func badCommandContext() {
	_, _ = exec.CommandContext(nil, "bar").Output() //nolint:all // fixture
}
