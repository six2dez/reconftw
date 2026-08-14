// target_test.go — F20 bullet 2: hostname syntax validation at the boundary.
//
// The previous domainRegex (`^[a-zA-Z0-9.-]+$`) enforced the character set but
// nothing about label structure, so `a..b`, `-a.com` and `a-.com` all reached
// 70+ external tool command lines and were slugified into workspace directory
// names. These tables are the regression guard.
//
// The IP / CIDR branches and both default-scope rules were fixed by an earlier
// audit and are asserted here too so a future regex change cannot quietly
// re-route an address through the hostname path.
package appctx_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// TestNewTargetHostnameAcceptSet: syntactically valid names keep working.
func TestNewTargetHostnameAcceptSet(t *testing.T) {
	t.Parallel()

	accept := []string{
		"example.com",
		"a.example.com",
		"a",                              // single label (e.g. an internal short name)
		"xn--80ak6aa92e.com",             // punycode
		"example.com.",                   // absolute name — folded by CanonicalTargetID
		"a-b.example.com",                // interior hyphen
		"1example.com",                   // leading digit (RFC 1123)
		strings.Repeat("a", 63) + ".com", // 63-octet label is the cap, not over it
	}
	for _, in := range accept {
		tgt, err := appctx.NewTarget(in, nil, "")
		if err != nil {
			t.Errorf("NewTarget(%q) = error %v; want accepted", in, err)
			continue
		}
		if tgt == nil {
			t.Errorf("NewTarget(%q) returned a nil Target with a nil error", in)
		}
	}
}

// TestNewTargetHostnameRejectSet is the F20 bullet 2 core assertion.
func TestNewTargetHostnameRejectSet(t *testing.T) {
	t.Parallel()

	reject := []string{
		"a..b",                           // empty label
		"-a.com",                         // leading hyphen
		"a-.com",                         // trailing hyphen
		".",                              // root only
		"..",                             // two empty labels
		"example.com..",                  // doubled root label
		".example.com",                   // leading empty label
		"-",                              // hyphen only
		strings.Repeat("a", 64) + ".com", // 64-octet label
	}
	for _, in := range reject {
		tgt, err := appctx.NewTarget(in, nil, "")
		if err == nil {
			t.Errorf("NewTarget(%q) returned nil error; want a rejection", in)
			continue
		}
		if tgt != nil {
			t.Errorf("NewTarget(%q) returned a non-nil Target alongside an error", in)
		}
		var se *coreerrors.ScopeError
		if !errors.As(err, &se) {
			t.Errorf("NewTarget(%q) returned %T; want *ScopeError", in, err)
		}
	}
}

// TestNewTargetHostnameLengthCap: a 254-octet name is rejected and the operator
// is told the actual limit.
func TestNewTargetHostnameLengthCap(t *testing.T) {
	t.Parallel()

	// 5 × "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa." (50) = 250, + "abcd" = 254.
	long := strings.Repeat(strings.Repeat("a", 49)+".", 5) + "abcd"
	if len(long) != 254 {
		t.Fatalf("fixture is %d chars, want 254", len(long))
	}
	tgt, err := appctx.NewTarget(long, nil, "")
	if err == nil {
		t.Fatalf("254-character hostname accepted; want rejection")
	}
	if tgt != nil {
		t.Errorf("254-character hostname returned a non-nil Target")
	}
	if !strings.Contains(err.Error(), "253") {
		t.Errorf("error %q does not name the 253-character limit", err)
	}

	// One octet shorter is fine — the cap is off-by-one sensitive.
	short := long[:253]
	if _, err := appctx.NewTarget(short, nil, ""); err != nil {
		t.Errorf("253-character hostname rejected: %v", err)
	}
}

// TestNewTargetHostnameScopeUnchanged: the default-scope rule for hostnames is
// untouched by the tightened regex.
func TestNewTargetHostnameScopeUnchanged(t *testing.T) {
	t.Parallel()

	tgt, err := appctx.NewTarget("example.com", nil, "")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if want := []string{"*.example.com"}; !reflect.DeepEqual(tgt.Scope, want) {
		t.Errorf("Scope = %#v, want %#v", tgt.Scope, want)
	}
	if tgt.IsIP || tgt.IsCIDR {
		t.Errorf("hostname classified as address: IsIP=%v IsCIDR=%v", tgt.IsIP, tgt.IsCIDR)
	}
}

// TestNewTargetAddressBranchesUnchanged: IP and CIDR still bypass the hostname
// regex entirely and keep their own default scopes.
func TestNewTargetAddressBranchesUnchanged(t *testing.T) {
	t.Parallel()

	cidr, err := appctx.NewTarget("10.0.0.0/24", nil, "")
	if err != nil {
		t.Fatalf("NewTarget(CIDR): %v", err)
	}
	if !cidr.IsCIDR {
		t.Errorf("10.0.0.0/24 IsCIDR = false")
	}
	if want := []string{"10.0.0.0/24"}; !reflect.DeepEqual(cidr.Scope, want) {
		t.Errorf("CIDR Scope = %#v, want %#v", cidr.Scope, want)
	}

	ip, err := appctx.NewTarget("10.0.0.5", nil, "")
	if err != nil {
		t.Fatalf("NewTarget(IP): %v", err)
	}
	if !ip.IsIP {
		t.Errorf("10.0.0.5 IsIP = false")
	}
	if want := []string{"10.0.0.5"}; !reflect.DeepEqual(ip.Scope, want) {
		t.Errorf("IP Scope = %#v, want %#v", ip.Scope, want)
	}

	v6, err := appctx.NewTarget("2001:db8::1", nil, "")
	if err != nil {
		t.Fatalf("NewTarget(IPv6): %v", err)
	}
	if !v6.IsIP {
		t.Errorf("2001:db8::1 IsIP = false")
	}
}
