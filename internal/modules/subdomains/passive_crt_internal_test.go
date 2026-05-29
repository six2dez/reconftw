// passive_crt_internal_test.go — unit test for parseCrtJSON (unexported, so
// this lives in package subdomains, not subdomains_test).
//
// crt's `-s -json` output is a JSON array of {"subdomain": <value>}; values
// can include certificate-CN noise with spaces and "*." wildcard labels.
// parseCrtJSON must keep only hostname-shaped values and strip wildcards.
package subdomains

import (
	"reflect"
	"testing"
)

func TestParseCrtJSON(t *testing.T) {
	in := []byte(`[
		{"subdomain":"dev.example.com"},
		{"subdomain":"AS207960 Test Intermediate - example.com"},
		{"subdomain":"*.api.example.com"},
		{"subdomain":"DEV.example.com"},
		{"subdomain":""},
		{"subdomain":"nodot"}
	]`)
	got := parseCrtJSON(in)
	want := []string{"dev.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCrtJSON = %#v; want %#v", got, want)
	}

	// Malformed JSON (e.g. crt's default ANSI table) → nil, never an error.
	if r := parseCrtJSON([]byte("+----+\n| subdomains |\n+----+")); r != nil {
		t.Errorf("parseCrtJSON(table) = %#v; want nil", r)
	}
	if r := parseCrtJSON(nil); r != nil {
		t.Errorf("parseCrtJSON(nil) = %#v; want nil", r)
	}
}
