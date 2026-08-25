// SPDX-License-Identifier: MIT
//
// Fixtures for the output-contract detector (internal/modules/output_contract_test.go).
//
// These live under testdata/ so the go tool never builds, vets or lints them —
// they exist only to be parsed by go/parser, and are deliberately not compilable
// in isolation. The detector is a syntactic analysis and must be proven against
// syntax.
//
// WITHOUT THESE, reducing discoverJSONDecoders to `return nil` would leave every
// assertion in output_contract_test.go vacuously true and the whole suite green:
// no decoders found means nothing unclassified, nothing uncovered, nothing
// stale. That is the same "a filter that matches nothing passes" shape this
// phase exists to eliminate, and it would live inside the detector built to
// eliminate it.
package outputcontract

import "encoding/json"

// unmarshalDecoder MUST be discovered — json.Unmarshal.
func unmarshalDecoder(b []byte) error {
	var v struct {
		Port string `json:"port"`
	}
	return json.Unmarshal(b, &v)
}

// streamDecoder MUST be discovered — json.NewDecoder.
func streamDecoder(r reader) error {
	var v map[string]string
	return json.NewDecoder(r).Decode(&v)
}

// methodDecoder MUST be discovered, named by its receiver type.
func (t *fixtureTask) methodDecoder(b []byte) error {
	var v []string
	return json.Unmarshal(b, &v)
}

// nestedDecoder MUST be discovered: the call is inside a closure, and a walker
// that only inspects top-level statements would miss it.
func nestedDecoder(b []byte) error {
	var err error
	func() {
		var v map[string]any
		err = json.Unmarshal(b, &v)
	}()
	return err
}

// notADecoder MUST NOT be discovered — it mentions json but decodes nothing.
func notADecoder(v any) ([]byte, error) {
	return json.Marshal(v)
}

// alsoNotADecoder MUST NOT be discovered — no json package call at all.
func alsoNotADecoder(s string) string { return s }
