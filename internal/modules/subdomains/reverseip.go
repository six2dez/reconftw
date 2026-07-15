// reverseip.go — hakip2host reverse-IP → host discovery for the resolve stage.
//
// PAR-01 (Phase 13-01): folds bash sub_dns's hakip2host reverse-IP step
// (modules/subdomains.sh:931-935) into SubDNSTask. hakip2host is a hakluke
// stdin-only tool — it reads newline-delimited IPs on stdin and emits
// "[TAG] <ip> <hostname>" lines. The name-keyed Backend/Runner (app.Tools) does
// NOT support stdin injection, so — exactly like the sibling
// web/hakoriginfinder.go (another hakluke stdin tool) — this file uses a
// direct, timeout-bounded exec.CommandContext with cmd.Stdin. It is therefore
// added to the FOUND-10 allowlist (internal/core/backend/lint/
// no_raw_subprocess_test.go) alongside the other sanctioned stdin-tool wrappers.
//
// The exec call is behind the hakip2hostRunner package var so hermetic tests
// (reverseip_internal_test.go) can inject canned output without a real binary.
package subdomains

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

// hakip2hostTimeout bounds a single hakip2host invocation (mirrors the
// tools.lock hakip2host timeout_seconds=120).
const hakip2hostTimeout = 120 * time.Second

// hakip2hostRunner runs hakip2host with the given newline-delimited IP list on
// stdin and returns raw stdout. Overridable in tests. Returns ("", nil) when the
// binary is not on PATH (D-O2 graceful skip) so a missing optional tool never
// fails the resolve stage.
var hakip2hostRunner = func(ctx context.Context, ips []string) (string, error) {
	bin, err := exec.LookPath("hakip2host")
	if err != nil {
		return "", nil // not installed — graceful skip
	}
	cmdCtx, cancel := context.WithTimeout(ctx, hakip2hostTimeout)
	defer cancel()
	//nolint:gosec // bin resolved via LookPath; stdin carries caller-validated public IPs only
	cmd := exec.CommandContext(cmdCtx, bin)
	cmd.Stdin = strings.NewReader(strings.Join(ips, "\n") + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if runErr := cmd.Run(); runErr != nil {
		// Non-zero exit / no results is normal — return whatever was captured
		// so partial output is still parsed (best-effort discovery source).
		return out.String(), runErr
	}
	return out.String(), nil
}

// reverseIPHosts runs hakip2host over the given public IPs and returns the
// distinct, in-scope hostnames discovered (bash: hakip2host | awk '{print $3}' |
// unfurl -u domains | in-scope grep). A tool error degrades to whatever partial
// output was captured (CONTINUE_ON_TOOL_ERROR parity) — it never fails the task.
func reverseIPHosts(ctx context.Context, app *appctx.AppContext, ips []string) []string {
	if len(ips) == 0 {
		return nil
	}
	out, err := hakip2hostRunner(ctx, ips)
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
