// reverseip.go — hakip2host reverse-IP → host discovery for the resolve stage.
//
// PAR-01 (Phase 13-01): folds bash sub_dns's hakip2host reverse-IP step
// (modules/subdomains.sh:931-935) into SubDNSTask. hakip2host is a hakluke
// stdin-only tool — it reads newline-delimited IPs on stdin and emits
// "[TAG] <ip> <hostname>" lines.
//
// 18-01: THIS FILE NO LONGER BYPASSES THE SEAM. It used to reach for a direct
// exec.CommandContext with cmd.Stdin, because the name-keyed Backend/Runner had
// no way to inject standard input — the justification recorded on its FOUND-10
// allowlist entry. backend.Runner.RunOpts now carries stdin, so the reason is
// gone and the entry has been REMOVED from the allowlist. hakip2host was
// invisible to logs/tools.jsonl, to the arg-vector census and to the tools.lock
// timeout contract for its whole life; it is now recorded like any other tool.
//
// TIMEOUT: the local 120s context.WithTimeout is GONE, deliberately. hakip2host
// carries timeout_seconds = 120 in tools.lock, and applyToolContract now derives
// that bound inside the Runner — keeping the local one would mean two bounds for
// the same tool that drift apart the moment the manifest is edited.
//
// BEHAVIOUR CHANGE, STATED RATHER THAN HIDDEN: on a NON-ZERO EXIT the old code
// returned whatever partial stdout it had captured, and LocalBackend does not —
// it returns a *ToolError with no Result. Partial output from a failing
// hakip2host is therefore no longer parsed. This is the same buffered-path
// decision every other tool on the seam already lives with (see the CR-07 note
// at local.go's deadline arm); the alternative is keeping this tool outside
// every guard phases 16-17 built, which is what this phase exists to end.
//
// The dispatch stays behind the hakip2hostRunner package var so hermetic tests
// (reverseip_internal_test.go) can inject canned output without a real binary.
package subdomains

import (
	"context"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// hakip2hostRunner runs hakip2host with the given newline-delimited IP list on
// stdin and returns raw stdout. Overridable in tests. Returns ("", nil) when the
// binary is not on PATH (D-O2 graceful skip) so a missing optional tool never
// fails the resolve stage.
var hakip2hostRunner = func(ctx context.Context, app *appctx.AppContext, ips []string) (string, error) {
	if app == nil || app.Tools == nil {
		return "", nil
	}
	res, err := app.Tools.RunOpts(ctx, "hakip2host", nil, backend.ExecOptions{
		Stdin: []byte(strings.Join(ips, "\n") + "\n"),
	})
	if err != nil {
		// A tool that is not registered, or registered but absent from PATH
		// (Discover leaves Path empty, so cmd.Start fails and LocalBackend
		// reports NeverStarted), is a GRACEFUL SKIP per D-O2 — a missing
		// optional tool must never fail the resolve stage. Note the gain over
		// the old exec.LookPath skip: this path is now RECORDED as
		// dispatch_failed in logs/tools.jsonl instead of vanishing silently.
		if coreerrors.IsDispatchFailure(err) {
			return "", nil
		}
		return "", err
	}
	return string(res.Stdout), nil
}

// reverseIPHosts runs hakip2host over the given public IPs and returns the
// distinct, in-scope hostnames discovered (bash: hakip2host | awk '{print $3}' |
// unfurl -u domains | in-scope grep). A tool error degrades to whatever partial
// output was captured (CONTINUE_ON_TOOL_ERROR parity) — it never fails the task.
func reverseIPHosts(ctx context.Context, app *appctx.AppContext, ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	out, err := hakip2hostRunner(ctx, app, ips)
	if err != nil && app.Log != nil {
		app.Log.Warn("resolve: hakip2host reverse-IP failed (non-fatal)", "error", err.Error())
	}
	return parseHakip2hostHosts(out, app)
}

// parseHakip2hostHosts parses hakip2host stdout ("[TAG] <ip> <hostname>", third
// whitespace field is the hostname — bash awk '{print $3}') and returns
// distinct, in-scope, syntactically-valid hostnames. In-scope filtering
// (inScope → app.Tree.InScope) is the T-13-01-01 mitigation: reverse-IP output
// can include off-scope hosts, so it is anchored-filtered before staging.
func parseHakip2hostHosts(out string, app *appctx.AppContext) []string {
	if out == "" {
		return nil
	}
	set := newOrderedStringSet()
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		host := normalizeHost(fields[2])
		if hostnameRE.MatchString(host) && inScope(app, host) {
			set.add(host)
		}
	}
	return set.list()
}
