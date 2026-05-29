// target_scope_default_test.go — regression test for the live-run fix: a
// hostname target created with no scope file must default to "*.<domain>" so
// the DefaultScopeFilter admits the apex + all subdomains. Without this, an
// ad-hoc `--target example.com` run rejected every discovered host ("0 found").
package appctx_test

import (
	"reflect"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

func TestNewTargetDefaultsScopeToWildcard(t *testing.T) {
	tgt, err := appctx.NewTarget("example.com", nil, "")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	want := []string{"*.example.com"}
	if !reflect.DeepEqual(tgt.Scope, want) {
		t.Errorf("default Scope = %#v; want %#v", tgt.Scope, want)
	}
}

func TestNewTargetHonorsExplicitScope(t *testing.T) {
	explicit := []string{"*.acme.com", "acme.io"}
	tgt, err := appctx.NewTarget("acme.com", explicit, "")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if !reflect.DeepEqual(tgt.Scope, explicit) {
		t.Errorf("explicit Scope overridden: got %#v; want %#v", tgt.Scope, explicit)
	}
}
