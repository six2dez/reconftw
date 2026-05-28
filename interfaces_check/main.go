// SPDX-License-Identifier: MIT
// interfaces_check — compile-only build target for ADR 0002 pre-sign gate (D-14).
// Source: .planning/phases/02-architecture-v2-design/02-RESEARCH.md §Pre-Sign Verification Gate
// Reference: .planning/decisions/0002-architecture-v2.md §5 Interface Signatures
// DO NOT import into production code — this package exists only to verify that
// the Go interface snippets in 0002-architecture-v2.md are syntactically valid.
package main

import (
	"context"
	"time"
)

// --------------------------------------------------------------------------
// §5.1 — Task interface (ARCH-05)
// Mirrors internal/core/task/task.go; uses interface{} for cross-package types
// so this file compiles standalone without module dependencies.
// --------------------------------------------------------------------------

// Status enumerates the terminal states a task may reach.
type Status string

const (
	StatusDone      Status = "done"
	StatusErrored   Status = "errored"
	StatusCancelled Status = "cancelled"
	StatusSkipped   Status = "skipped"
)

// Result carries the outcome of a single task execution.
type Result struct {
	Status   Status
	Duration time.Duration
	Outputs  []string
	Stats    map[string]int
}

// AppContext is the dependency kernel (placeholder — real type is in internal/core/appctx).
// Fields use interface{} here so this file compiles without importing all dependencies.
type AppContext struct {
	Log        interface{} // *slog.Logger
	Cfg        interface{} // *config.Config
	Scheduler  interface{} // *scheduler.Scheduler
	Tools      interface{} // *backend.Runner
	Tree       interface{} // *output.OutputTree
	Checkpoint interface{} // *checkpoint.Store
	Notify     interface{} // notifier.Notifier
	Target     interface{} // *Target
	UI         interface{} // *ui.Printer
}

// Task is the smallest schedulable unit of recon work. Self-registers via init().
// BINDING: renaming a method, changing a method signature, or removing a method
// requires an ADR amendment (D-06). Adding new methods is non-breaking (D-07).
type Task interface {
	Name() string
	Module() string
	Description() string
	Enabled(cfg interface{}) bool
	DependsOn() []string
	Run(ctx context.Context, app *AppContext) (Result, error)
}

// LifecycleAware is an optional lifecycle extension Tasks may implement.
type LifecycleAware interface {
	OnStart(ctx context.Context, app *AppContext) error
	OnEnd(ctx context.Context, app *AppContext, r Result) error
}

// --------------------------------------------------------------------------
// §5.2 — Backend interface (ARCH-06)
// Mirrors internal/core/backend/backend.go.
// --------------------------------------------------------------------------

// Event is a single streaming output unit from a running tool.
type Event struct {
	Line   []byte
	Source string
	IsErr  bool
}

// ExecResult holds the complete output of a buffered Exec call.
type ExecResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// Tool describes a single external binary resolved at startup.
type Tool struct {
	Name        string
	Path        string
	Version     string
	DefaultArgs []string
	Timeout     time.Duration
}

// Backend abstracts local subprocess execution from distributed (Axiom) execution.
// BINDING: adding methods is non-breaking (D-07); renaming, removing, or changing
// method signatures requires an ADR amendment (D-06).
type Backend interface {
	Exec(ctx context.Context, t *Tool, args []string) (*ExecResult, error)
	Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error)
	HealthCheck(ctx context.Context) error
	Capacity() int
}

// --------------------------------------------------------------------------
// §6 — Error class hierarchy (ARCH-08)
// --------------------------------------------------------------------------

// FailurePolicy controls how a stage handles task errors.
type FailurePolicy string

const (
	PolicyBestEffort FailurePolicy = "best_effort"
	PolicyFailFast   FailurePolicy = "fail_fast"
)

// --------------------------------------------------------------------------
// main — required for `go build ./interfaces_check/...`
// --------------------------------------------------------------------------

func main() {
	// Compile-only gate. This binary is never executed in production.
	// Running it is a no-op; its value is that it compiles without errors.
	_ = StatusDone
	_ = PolicyBestEffort
}
