// Source: ADR 0002 §5.3 lines 1736-1742 (Target shape) + lib/validation.sh
// regex `^[a-zA-Z0-9.-]+$` (proven security posture; v1 bash equivalent
// referenced by the Phase 3 CONTEXT and PATTERNS files).
//
// Target is the immutable scan target description. Constructed by Boot
// (boot.go) after CLI parsing and scope-file load; after construction the
// Target struct is read-only — Tasks SHOULD NOT mutate any field.

package appctx

import (
	"net"
	"regexp"
	"strings"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// domainRegex mirrors v1 lib/validation.sh validate_domain() — rejects
// shell metacharacters, semicolons, quotes, paths, anything that could
// inject into a downstream command line. We deliberately keep it strict;
// IPs are validated via net.ParseIP and CIDRs via net.ParseCIDR (which
// allow the digits + dots + slash this regex would reject).
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

// NewTarget validates domain/IP/CIDR and constructs a Target. Returns
// *errors.ScopeError if validation fails — distinct from OutputTree's
// write-time OutOfScope rejection (same ErrScope sentinel, different
// semantic).
//
// workDir is expected to be the absolute path to workspaces/<target-id>/;
// Boot computes this from cfg.Output / target-id. Tests may pass
// t.TempDir().
//
// scope is the list of wildcard patterns from the user-provided scope
// file (may be empty — Target.Scope can be nil, ScopeFilter then admits
// everything matching the Domain).
func NewTarget(domain string, scope []string, workDir string) (*Target, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, &coreerrors.ScopeError{
			Input:  domain,
			Reason: "empty target",
		}
	}

	// Try IP first.
	//
	// The default-scope rule below is the same one the hostname branch has
	// always had, and its absence here was silent and total: DefaultScopeFilter
	// rejects everything when Patterns is empty, so `--target 10.0.0.5` built an
	// empty scope and every artefact write was refused — an IP or CIDR scan
	// produced nothing at all. The hostname branch got the fix because it
	// returns last; these two return early and were missed.
	if ip := net.ParseIP(domain); ip != nil {
		if len(scope) == 0 {
			scope = []string{domain} // exactly this address, nothing else
		}
		return &Target{
			Domain:  domain,
			IsIP:    true,
			Scope:   scope,
			WorkDir: workDir,
		}, nil
	}

	// Try CIDR next.
	if _, _, err := net.ParseCIDR(domain); err == nil {
		if len(scope) == 0 {
			scope = []string{domain} // the prefix; DefaultScopeFilter does containment
		}
		return &Target{
			Domain:  domain,
			IsCIDR:  true,
			Scope:   scope,
			WorkDir: workDir,
		}, nil
	}

	// Otherwise validate as a hostname.
	if !domainRegex.MatchString(domain) {
		return nil, &coreerrors.ScopeError{
			Input:  domain,
			Reason: "domain contains shell metacharacters or invalid characters",
		}
	}
	// Default scope: when no scope file is provided (the common `--target X`
	// case), admit the apex AND all of its subdomains. The DefaultScopeFilter
	// rejects everything when Patterns is empty, so without this default a
	// plain `--target example.com` run would discard every discovered host
	// ("0 found"). `*.example.com` matches the apex (host == base) and any
	// subdomain (HasSuffix ".example.com") per matchScopePattern. An explicit
	// user-provided scope (non-empty) is always honored verbatim.
	if len(scope) == 0 {
		scope = []string{"*." + domain}
	}
	return &Target{
		Domain:  domain,
		Scope:   scope,
		WorkDir: workDir,
	}, nil
}
