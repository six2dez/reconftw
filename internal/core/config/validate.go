// Validate(cfg) runs go-playground/validator/v10 against the Config struct.
// Custom validators registered:
//   - nopath_traversal — rejects ".." path components (T-02-02-01)
//   - nuclei_severity — CSV of {info,low,medium,high,critical}
//   - oneof_scheme — URL scheme allowlist (T-02-02-02)
//
// SECURITY: error messages NEVER include the raw field value. See
// extractRuleViolation below. Violating this rule causes secret leak via
// error logging — the redactor's two-layer defense cannot scrub a value that
// the config loader hasn't registered yet. The rule is enforced by
// TestSecretRedactionInError + the CI sentinel gate (XCUT-07 family).

package config

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// validate is the package-level validator instance with all custom rules
// registered. Initialised once at init() time — tests reset it via the
// public Validate entry point only.
var validate *validator.Validate

func init() {
	validate = validator.New(validator.WithRequiredStructEnabled())
	mustRegister("nopath_traversal", validateNoPathTraversal)
	mustRegister("nuclei_severity", validateNucleiSeverity)
	mustRegister("oneof_scheme", validateOneofScheme)
}

func mustRegister(tag string, fn validator.Func) {
	if err := validate.RegisterValidation(tag, fn); err != nil {
		panic(fmt.Sprintf("config: register validator %s: %v", tag, err))
	}
}

// Validate walks cfg and returns nil on success or a *errors.ConfigError on
// the first violation (we surface the first error to keep the SECURITY rule
// auditable — multiple errors would each need redaction-scrubbing).
//
// The validate tag names referenced in config.go MUST exist either in the
// stdlib validator tagset or in the custom-registered set above. Unknown tags
// cause init() to panic — desirable: schema typos crash at boot, not at scan
// time.
func Validate(cfg *Config) error {
	if cfg == nil {
		return &coreerrors.ConfigError{
			File: "(nil)", Line: 0, Key: "(root)", Message: "config is nil",
		}
	}
	if err := validate.Struct(cfg); err != nil {
		// validator.ValidationErrors is a slice of validator.FieldError
		var vErrs validator.ValidationErrors
		if ok := errorsAs(err, &vErrs); !ok {
			// InvalidValidationError — schema bug, return as-is
			return &coreerrors.ConfigError{
				File: "(validator)", Line: 0, Key: "(unknown)",
				Message: "internal validator error: " + err.Error(),
			}
		}
		// Translate the first FieldError to a *ConfigError without leaking
		// raw values.
		fe := vErrs[0]
		return &coreerrors.ConfigError{
			File:    "(merged)",
			Line:    0,
			Key:     koanfPathFor(fe),
			Message: fmt.Sprintf("validation failed: rule %q (param=%q)", fe.Tag(), fe.Param()),
		}
	}
	return nil
}

// errorsAs is a tiny stderrors.As wrapper kept inline to avoid importing
// stderrors here (keeps the import section tight).
func errorsAs(err error, target any) bool {
	// inline import of stderrors via a function literal would obscure intent;
	// since errorsAs is called once, use the explicit import alias.
	return stdAs(err, target)
}

// koanfPathFor derives a dotted koanf path from a validator.FieldError. The
// validator's Namespace() is "Config.Concurrency.MaxJobs" — we translate
// that PascalCase chain back to koanf snake_case via a lookup against the
// Config struct's koanf tags.
//
// Slow path: we accept O(N) struct walks here because this only runs on a
// validation failure (rare).
func koanfPathFor(fe validator.FieldError) string {
	// fe.Namespace() returns "Config.Concurrency.MaxJobs"; drop the leading
	// "Config." segment.
	ns := fe.Namespace()
	parts := strings.Split(ns, ".")
	if len(parts) > 1 && parts[0] == "Config" {
		parts = parts[1:]
	}
	// Walk the Config struct using each PascalCase part to find the koanf tag.
	resolved := make([]string, 0, len(parts))
	c := Defaults()
	t := reflectTypeOf(c).Elem()
	for _, part := range parts {
		field, ok := t.FieldByName(part)
		if !ok {
			resolved = append(resolved, toSnake(part))
			continue
		}
		tag := field.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			tag = toSnake(part)
		}
		resolved = append(resolved, tag)
		// Descend into the nested struct type for the next part.
		t = field.Type
		if t.Kind() == reflectPtr {
			t = t.Elem()
		}
	}
	return strings.Join(resolved, ".")
}

// toSnake converts PascalCase to snake_case as a fallback when the struct
// walk fails to find a koanf tag.
func toSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ---------------- Custom Validators ----------------

// validateNoPathTraversal rejects any string containing ".." as a path
// component. Empty strings pass (paired with omitempty). Matches:
//   - ../etc/passwd     (rejected)
//   - /etc/../etc/passwd (rejected)
//   - /etc/passwd       (passes)
//   - .hidden           (passes — "." alone is not traversal)
func validateNoPathTraversal(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return true
	}
	// Split on / and check each segment for "..".
	for _, segment := range strings.Split(s, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

// validateNucleiSeverity accepts a CSV of {info,low,medium,high,critical}.
// Empty input is rejected (omitempty pairs in the validate tag handle the
// optional case).
func validateNucleiSeverity(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return false
	}
	valid := map[string]bool{
		"info": true, "low": true, "medium": true, "high": true, "critical": true,
	}
	for _, part := range strings.Split(s, ",") {
		if !valid[strings.TrimSpace(part)] {
			return false
		}
	}
	return true
}

// validateOneofScheme accepts URLs whose scheme is in the space-separated
// allowlist `param`. Empty input passes (paired with omitempty).
//
// Example tag: `validate:"omitempty,url,oneof_scheme=http https"`
func validateOneofScheme(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return true
	}
	allowed := strings.Fields(fl.Param())
	for _, scheme := range allowed {
		if strings.HasPrefix(s, scheme+"://") {
			return true
		}
	}
	return false
}
