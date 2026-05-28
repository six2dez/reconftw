// koanf provider that consumes a Defaults() *Config and exposes its
// koanf-tagged fields as a nested map[string]any.
//
// Goal: layer 1 (Defaults) is loaded into koanf as a fully-populated tree so
// that subsequent layers (TOML files, env, CLI) overwrite at the per-key level.
//
// We use a hand-rolled reflect walk rather than pulling in koanf's structs
// provider (which depends on mapstructure semantics we don't need here).

package config

import (
	"reflect"
)

// structsProvider returns a koanf.Provider that exposes cfg's koanf-tagged
// fields as a nested map. The implementation uses reflect to walk the struct
// tree and emit primitives at the leaves.
func structsProvider(cfg *Config) *structsProv {
	return &structsProv{root: cfg}
}

type structsProv struct {
	root *Config
}

func (p *structsProv) ReadBytes() ([]byte, error) { return nil, nil }

func (p *structsProv) Read() (map[string]any, error) {
	return walkStruct(reflect.ValueOf(p.root).Elem()), nil
}

// walkStruct emits a nested map[string]any for every koanf-tagged field of v.
// Non-struct leaves are emitted as the field's Interface(). Slice/map leaves
// are emitted as-is.
func walkStruct(v reflect.Value) map[string]any {
	out := make(map[string]any)
	if v.Kind() != reflect.Struct {
		return out
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		ft := t.Field(i)
		tag := ft.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		fv := v.Field(i)
		if fv.Kind() == reflect.Struct {
			out[tag] = walkStruct(fv)
		} else {
			out[tag] = fv.Interface()
		}
	}
	return out
}
