// token_redaction_test.go — the GitHub/GitLab token reaches the redactor BEFORE
// the tool is dispatched.
//
// Both tasks read a token FILE and put its CONTENT on argv (`-t <token>`). The
// comment at passive.go had promised since phase 4 that the token was "registered
// as a secret before any logging"; nothing registered it — the code logged the
// token's LENGTH and moved on. That was survivable while argv stayed in memory.
// It stopped being survivable when logs/tools.jsonl began writing argv to disk.

package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// recordingRegistrar captures what a task registers, and when relative to
// dispatch.
type recordingRegistrar struct {
	mu         sync.Mutex
	registered []string
	// dispatched is set by the capturing backend the moment the tool runs, so the
	// test can prove ORDER, not just occurrence.
	dispatched bool
	atDispatch []string
}

func (r *recordingRegistrar) Register(v string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.registered = append(r.registered, v)
}

func (r *recordingRegistrar) markDispatch() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dispatched = true
	r.atDispatch = append([]string(nil), r.registered...)
}

func (r *recordingRegistrar) snapshotAtDispatch() (bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dispatched, append([]string(nil), r.atDispatch...)
}

// dispatchNotifyingBackend is argCapturingBackend plus an ordering hook.
type dispatchNotifyingBackend struct {
	argCapturingBackend
	reg *recordingRegistrar
}

func (b *dispatchNotifyingBackend) Exec(ctx context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	b.reg.markDispatch()
	return b.argCapturingBackend.Exec(ctx, t, args)
}

func (b *dispatchNotifyingBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func TestGithubGitlabTokensAreRegisteredBeforeDispatch(t *testing.T) {
	cases := []struct {
		task  string
		tool  string
		token string
		field string // config field to point at the token file
	}{
		{"subdomains.passive.github", "github-subdomains", "ghp_FakeTokenForTestOnly1234567890", "github"},
		{"subdomains.passive.gitlab", "gitlab-subdomains", "glpat-FakeTokenForTestOnly0987654321", "gitlab"},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			workDir := t.TempDir()
			tokenFile := filepath.Join(workDir, "tokens.txt")
			if err := os.WriteFile(tokenFile, []byte(tc.token+"\n"), 0o600); err != nil {
				t.Fatalf("seed token file: %v", err)
			}

			reg := &recordingRegistrar{}
			be := &dispatchNotifyingBackend{reg: reg}
			r := backend.NewToolRegistry()
			r.Register(&backend.Tool{Name: tc.tool})

			app := newTestApp(workDir, backend.NewRunner(be, r, nil), &mockTree{})
			app.Secrets = reg
			if tc.field == "github" {
				app.Cfg.Paths.GitHubTokens = tokenFile
			} else {
				app.Cfg.Paths.GitLabTokens = tokenFile
			}

			tsk := lookupSubTask(t, tc.task)
			if _, err := tsk.Run(context.Background(), app); err != nil {
				t.Logf("task returned %v (tool is a stub; the registration is what matters)", err)
			}

			dispatched, atDispatch := reg.snapshotAtDispatch()
			if !dispatched {
				t.Skipf("%s was never dispatched in this configuration — nothing to order against", tc.tool)
			}
			found := false
			for _, v := range atDispatch {
				if v == tc.token {
					found = true
				}
			}
			if !found {
				t.Errorf("the token was NOT registered with the redactor by the time %s was "+
					"dispatched; registered-at-dispatch = %v.\nIts CONTENT is on argv, so an "+
					"unregistered token becomes plaintext in logs/tools.jsonl", tc.tool, atDispatch)
			}
			// The token must not be truncated or transformed on the way in.
			for _, v := range atDispatch {
				if strings.Contains(tc.token, v) && v != tc.token {
					t.Errorf("a PARTIAL token was registered (%q) — partial registration "+
						"redacts partially, which is a leak", v)
				}
			}
		})
	}
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (b *dispatchNotifyingBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *dispatchNotifyingBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
}
