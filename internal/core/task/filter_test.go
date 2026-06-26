// Tests for FilterByModuleAndEnabled and MatchesAnyPrefix.
//
// External test package per project convention (see internal/core/log/redactor_test.go).
package task_test

import (
	"context"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// filterFakeTask is a minimal Task implementation used specifically by filter tests.
// Named distinctly from fakeTask in task_test.go to avoid package-level collision.
type filterFakeTask struct {
	name    string
	module  string
	enabled bool
}

func (f *filterFakeTask) Name() string                                            { return f.name }
func (f *filterFakeTask) Module() string                                          { return f.module }
func (f *filterFakeTask) Description() string                                     { return "fake" }
func (f *filterFakeTask) Enabled(_ *config.Config) bool                           { return f.enabled }
func (f *filterFakeTask) DependsOn() []string                                     { return nil }
func (f *filterFakeTask) Run(_ context.Context, _ *appctx.AppContext) (task.Result, error) {
	return task.Result{Status: task.StatusDone, Duration: time.Second}, nil
}

// cfg is a zero-value config sufficient for fakeTask.Enabled (which ignores cfg).
var testCfg = &config.Config{}

func TestFilterByModuleAndEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		tasks    []task.Task
		module   string
		prefixes []string
		wantLen  int
		wantName []string // expected task names in result (order-independent)
	}{
		{
			name:     "nil input returns nil",
			tasks:    nil,
			module:   "subdomains",
			prefixes: []string{"sub."},
			wantLen:  0,
		},
		{
			name: "empty prefixes returns no tasks",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{},
			wantLen:  0,
		},
		{
			name: "module mismatch excludes task",
			tasks: []task.Task{
				&filterFakeTask{name: "web.probe", module: "web", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{"web."},
			wantLen:  0,
		},
		{
			name: "disabled task excluded even if module and prefix match",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: false},
			},
			module:   "subdomains",
			prefixes: []string{"sub."},
			wantLen:  0,
		},
		{
			name: "matching task returned",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{"sub."},
			wantLen:  1,
			wantName: []string{"sub.passive"},
		},
		{
			name: "prefix mismatch excludes task",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{"web."},
			wantLen:  0,
		},
		{
			name: "multiple tasks — only matching returned",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: true},
				&filterFakeTask{name: "sub.crt", module: "subdomains", enabled: true},
				&filterFakeTask{name: "sub.brute", module: "subdomains", enabled: false},
				&filterFakeTask{name: "web.probe", module: "web", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{"sub."},
			wantLen:  2,
			wantName: []string{"sub.passive", "sub.crt"},
		},
		{
			name: "multiple prefixes — task matching any prefix included",
			tasks: []task.Task{
				&filterFakeTask{name: "sub.passive", module: "subdomains", enabled: true},
				&filterFakeTask{name: "sub.active", module: "subdomains", enabled: true},
				&filterFakeTask{name: "sub.enrich", module: "subdomains", enabled: true},
			},
			module:   "subdomains",
			prefixes: []string{"sub.passive", "sub.active"},
			wantLen:  2,
			wantName: []string{"sub.passive", "sub.active"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := task.FilterByModuleAndEnabled(tc.tasks, tc.module, testCfg, tc.prefixes)
			if len(got) != tc.wantLen {
				t.Errorf("FilterByModuleAndEnabled() len = %d; want %d (tasks: %v)", len(got), tc.wantLen, got)
			}
			// Check wantName subset (order-independent).
			nameSet := make(map[string]bool, len(got))
			for _, t := range got {
				nameSet[t.Name()] = true
			}
			for _, name := range tc.wantName {
				if !nameSet[name] {
					t.Errorf("FilterByModuleAndEnabled() missing expected task %q in result", name)
				}
			}
		})
	}
}

func TestMatchesAnyPrefix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		taskName string
		prefixes []string
		want     bool
	}{
		{
			name:     "empty prefixes returns false",
			taskName: "sub.passive",
			prefixes: []string{},
			want:     false,
		},
		{
			name:     "nil prefixes returns false",
			taskName: "sub.passive",
			prefixes: nil,
			want:     false,
		},
		{
			name:     "exact match returns true",
			taskName: "sub.passive",
			prefixes: []string{"sub.passive"},
			want:     true,
		},
		{
			name:     "prefix of longer name returns true",
			taskName: "sub.passive.crtsh",
			prefixes: []string{"sub.passive"},
			want:     true,
		},
		{
			name:     "non-matching prefix returns false",
			taskName: "sub.passive",
			prefixes: []string{"web."},
			want:     false,
		},
		{
			name:     "second prefix matches",
			taskName: "sub.active",
			prefixes: []string{"sub.passive", "sub.active"},
			want:     true,
		},
		{
			name:     "empty task name does not match non-empty prefix",
			taskName: "",
			prefixes: []string{"sub."},
			want:     false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := task.MatchesAnyPrefix(tc.taskName, tc.prefixes)
			if got != tc.want {
				t.Errorf("MatchesAnyPrefix(%q, %v) = %v; want %v", tc.taskName, tc.prefixes, got, tc.want)
			}
		})
	}
}
