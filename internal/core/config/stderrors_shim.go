// Tiny shim around stderrors.As to keep validate.go's import section narrow.
// (The validate.go file mentions errorsAs by name; this file provides it.)

package config

import (
	stderrors "errors"
	"reflect"
)

// stdAs is errors.As. Kept here so validate.go's import block stays focused.
func stdAs(err error, target any) bool { return stderrors.As(err, target) }

// reflectTypeOf is reflect.TypeOf. Same rationale.
func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }

// reflectPtr is reflect.Ptr (alias kept inline so validate.go avoids the
// reflect import).
const reflectPtr = reflect.Ptr
