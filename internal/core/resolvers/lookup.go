package resolvers

import "os/exec"

// lookPath wraps exec.LookPath and is the single call site for PATH-based
// binary discovery in this package (mirrors the registry.go pattern).
func lookPath(name string) (string, error) {
	return exec.LookPath(name)
}
