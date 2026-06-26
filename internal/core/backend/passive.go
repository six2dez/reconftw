// passive.go — PassiveBackend wraps a Backend and hard-blocks active tools.
//
// D-09: When PassiveMode=true, any tool whose name is in the activeToolSet
// is rejected with ErrPassiveViolation before the inner backend is called.
// This is the defense-in-depth guard; the primary guard is composition-level
// (passive composite only schedules passive-prefixed tasks).
package backend

import (
	"context"
	"strings"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// activeToolSet is the hard-block list of tool names (exact or prefix-matched)
// that are forbidden when PassiveMode=true. Sourced from D-09 spec:
// puredns, massdns, dnsx (active brute), naabu, nmap, dalfox, sqlmap,
// commix, ffuf, nuclei, httpx (active scan), and gato.
var activeToolSet = map[string]bool{
	"puredns": true,
	"massdns": true,
	"naabu":   true,
	"nmap":    true,
	"dalfox":  true,
	"sqlmap":  true,
	"commix":  true,
	"ffuf":    true,
	"nuclei":  true,
	"httpx":   true,
	"gato":    true,
}

// isActiveTool returns true if the tool name is in the hard-block set.
// Matches exact names and also catches tool names with a "-" suffix
// (e.g. "dnsx-brute" when a wrapper renames it).
func isActiveTool(name string) bool {
	if activeToolSet[name] {
		return true
	}
	// Also block any tool whose base name (before the first "-") is in the set.
	if idx := strings.IndexByte(name, '-'); idx > 0 {
		if activeToolSet[name[:idx]] {
			return true
		}
	}
	return false
}

// PassiveBackend wraps a Backend and returns ErrPassiveViolation for any call
// to Exec/ExecEnv/Stream/StreamEnv whose tool is in the active-tool set (D-09).
// HealthCheck and Capacity are delegated unconditionally.
type PassiveBackend struct {
	Inner Backend
}

// NewPassiveBackend wraps inner with passive-mode hard-guard.
func NewPassiveBackend(inner Backend) *PassiveBackend {
	return &PassiveBackend{Inner: inner}
}

// passiveViolation returns the standardized ErrPassiveViolation error for a tool.
func passiveViolation(toolName string) error {
	return &coreerrors.PassiveViolation{Tool: toolName}
}

func (b *PassiveBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	if isActiveTool(t.Name) {
		return nil, passiveViolation(t.Name)
	}
	return b.Inner.Exec(ctx, t, args)
}

func (b *PassiveBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	if isActiveTool(t.Name) {
		return nil, passiveViolation(t.Name)
	}
	return b.Inner.ExecEnv(ctx, t, args, env)
}

func (b *PassiveBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	if isActiveTool(t.Name) {
		return nil, passiveViolation(t.Name)
	}
	return b.Inner.Stream(ctx, t, args)
}

func (b *PassiveBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	if isActiveTool(t.Name) {
		return nil, passiveViolation(t.Name)
	}
	return b.Inner.StreamEnv(ctx, t, args, env)
}

func (b *PassiveBackend) HealthCheck(ctx context.Context) error {
	return b.Inner.HealthCheck(ctx)
}

func (b *PassiveBackend) Capacity() int {
	return b.Inner.Capacity()
}
