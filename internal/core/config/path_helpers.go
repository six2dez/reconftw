// Tiny reflect-driven get/set on koanf-tagged structs for the [legacy] alias
// mechanism. Keeping this small + focused — only handles dotted paths through
// public struct fields tagged koanf:"..." (the entire Config tree).
//
// Phase 11 migrator may extend this with type-coercion smarts; for Plan 02
// the corpus is small enough that a simple reflect-walk suffices.

package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// readByPath returns the value at dotted koanf-path p in cfg, or nil if not
// found. Only scalar (string/int/int64/bool/log.Secret) leaves are returned;
// struct nodes are not.
func readByPath(cfg *Config, p string) any {
	v := reflect.ValueOf(cfg).Elem()
	for _, part := range strings.Split(p, ".") {
		fv := findFieldByKoanfTag(v, part)
		if !fv.IsValid() {
			return nil
		}
		v = fv
	}
	if !v.IsValid() {
		return nil
	}
	return v.Interface()
}

// writeByPath sets the value at dotted koanf-path p in cfg to value. Coerces
// the value to the destination field's type (int, int64, string, bool,
// log.Secret). Returns an error if the path doesn't exist or coercion fails.
func writeByPath(cfg *Config, p string, value any) error {
	v := reflect.ValueOf(cfg).Elem()
	parts := strings.Split(p, ".")
	for i, part := range parts {
		fv := findFieldByKoanfTag(v, part)
		if !fv.IsValid() {
			return fmt.Errorf("no field for path %q at segment %q", p, part)
		}
		if i == len(parts)-1 {
			return coerceAndSet(fv, value)
		}
		v = fv
	}
	return fmt.Errorf("empty path")
}

// findFieldByKoanfTag locates the field of v whose koanf tag matches name.
// v must be a struct; otherwise returns reflect.Value{}.
func findFieldByKoanfTag(v reflect.Value, name string) reflect.Value {
	if v.Kind() != reflect.Struct {
		return reflect.Value{}
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("koanf")
		if tag == name {
			return v.Field(i)
		}
	}
	return reflect.Value{}
}

// coerceAndSet writes value into dst with appropriate type coercion.
// Handles the scalar types used by Config: int, int64, string, bool, float64,
// log.Secret. Anything else is set via reflect.ValueOf().Convert if assignable;
// returns an error otherwise.
func coerceAndSet(dst reflect.Value, value any) error {
	if !dst.CanSet() {
		return fmt.Errorf("destination not settable")
	}
	rv := reflect.ValueOf(value)

	switch dst.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		switch v := value.(type) {
		case int:
			dst.SetInt(int64(v))
		case int64:
			dst.SetInt(v)
		case float64:
			dst.SetInt(int64(v))
		case string:
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return fmt.Errorf("cannot coerce %q to int: %w", v, err)
			}
			dst.SetInt(n)
		default:
			if rv.IsValid() && rv.Type().ConvertibleTo(dst.Type()) {
				dst.Set(rv.Convert(dst.Type()))
				return nil
			}
			return fmt.Errorf("cannot coerce %T to %s", value, dst.Type())
		}

	case reflect.Bool:
		switch v := value.(type) {
		case bool:
			dst.SetBool(v)
		case string:
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("cannot coerce %q to bool: %w", v, err)
			}
			dst.SetBool(b)
		default:
			return fmt.Errorf("cannot coerce %T to bool", value)
		}

	case reflect.String:
		switch v := value.(type) {
		case string:
			dst.SetString(v)
		default:
			dst.SetString(fmt.Sprintf("%v", value))
		}

	case reflect.Float32, reflect.Float64:
		switch v := value.(type) {
		case float64:
			dst.SetFloat(v)
		case float32:
			dst.SetFloat(float64(v))
		case int:
			dst.SetFloat(float64(v))
		case string:
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return fmt.Errorf("cannot coerce %q to float: %w", v, err)
			}
			dst.SetFloat(f)
		default:
			return fmt.Errorf("cannot coerce %T to float", value)
		}

	default:
		// Last-resort assignment for log.Secret (named-string) etc.
		if rv.IsValid() && rv.Type().ConvertibleTo(dst.Type()) {
			dst.Set(rv.Convert(dst.Type()))
			return nil
		}
		return fmt.Errorf("unsupported destination kind %s", dst.Kind())
	}
	return nil
}
