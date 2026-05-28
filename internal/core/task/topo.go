// Source: ADR 0002 §6 PITFALL NOTE lines 1766-1769 — circular DependsOn
// is a *errors.ConfigError, NOT a runtime error. The Scheduler must NEVER
// observe a cyclic task graph; Registry.Build calls Sort at startup and
// the program errors out before any Task.Run.
//
// Algorithm: 3-color DFS topological sort (Cormen et al., "Introduction
// to Algorithms"). Each node carries a colour:
//
//	white = 0  unvisited
//	gray  = 1  visiting (currently in DFS stack)
//	black = 2  done
//
// Visiting a gray node = cycle. The path captured during descent is
// stringified into the ConfigError message so operators can diagnose the
// cycle.
//
// Determinism: names sorted before DFS entry so the produced order is
// stable across multiple Sort invocations with the same input.

package task

import (
	"sort"
	"strings"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Sort topologically orders tasks by their DependsOn graph. Returns a
// slice where every task appears after all of its dependencies.
//
// Errors:
//
//   - circular DependsOn → *coreerrors.ConfigError with Key="task.depends_on"
//     and Message="circular DependsOn detected: A → B → A"
//   - missing dependency (A depends on B, but B not registered) →
//     *coreerrors.ConfigError with the missing task name
//
// The Scheduler calls Build() (which delegates to Sort) at startup; on
// error, the binary exits non-zero before any task runs (per ADR §6
// PITFALL NOTE).
func Sort(tasks map[string]Task) ([]Task, error) {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int, len(tasks))
	order := make([]Task, 0, len(tasks))

	var dfs func(name string, path []string) error
	dfs = func(name string, path []string) error {
		t, ok := tasks[name]
		if !ok {
			// path[len-1] depended on `name`; surface the chain for diagnostics.
			via := ""
			if len(path) > 0 {
				via = " (via " + path[len(path)-1] + ")"
			}
			return &coreerrors.ConfigError{
				Key:     "task.depends_on",
				Message: "task " + name + " not registered" + via,
			}
		}
		switch color[name] {
		case black:
			return nil
		case gray:
			cycle := append(append([]string{}, path...), name)
			return &coreerrors.ConfigError{
				Key:     "task.depends_on",
				Message: "circular DependsOn detected: " + strings.Join(cycle, " → "),
			}
		}
		color[name] = gray

		// Deduplicate dependencies before recursing — duplicate entries in
		// DependsOn() are harmless but waste a DFS call.
		deps := t.DependsOn()
		if len(deps) > 1 {
			seen := make(map[string]struct{}, len(deps))
			uniq := make([]string, 0, len(deps))
			for _, d := range deps {
				if _, ok := seen[d]; ok {
					continue
				}
				seen[d] = struct{}{}
				uniq = append(uniq, d)
			}
			deps = uniq
		}
		for _, dep := range deps {
			if err := dfs(dep, append(path, name)); err != nil {
				return err
			}
		}
		color[name] = black
		order = append(order, t)
		return nil
	}

	// Deterministic iteration order over the registry.
	names := make([]string, 0, len(tasks))
	for n := range tasks {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, n := range names {
		if err := dfs(n, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}
