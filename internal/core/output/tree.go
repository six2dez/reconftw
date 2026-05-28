// Source:
//   - ADR §3.1 lines 1188-1222 (workspaces/<target-id>/ directory shape).
//   - ADR §3.2 lines 1233-1252 (Artefact JSONL schemas + OutOfScope guard
//     enforced at OutputTree.Append boundary, NOT inside Task code).
//   - internal/core/errors/errors.go (Plan 01 — OutOfScope typed error).
//
// OutputTree owns the AtomicWriter. Tasks call `Tree.Append(artefact, lines)`;
// every line is validated against the configured ScopeFilter BEFORE the
// AtomicWriter is invoked. The Append boundary is the ONLY place in the
// kernel where scope is enforced — Task code cannot bypass.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// OutputTree is the canonical write-path object for an active workspace.
// It is constructed by AppContext.Boot (Plan 05) with the workspace root
// path and the resolved scope filter.
type OutputTree struct {
	// Root is the absolute path to workspaces/<target-id>/.
	Root string
	// Scope is the configured scope filter. May be nil for tests that wish
	// to disable scope enforcement (Append degrades to "no scope check").
	Scope ScopeFilter
}

// NewTree creates the workspace directory tree under root and returns
// an *OutputTree ready for Append calls. Subdirectories created:
// inputs/, artefacts/, raw/, reports/, logs/ per ADR §3.1.
func NewTree(root string, scope ScopeFilter) (*OutputTree, error) {
	if root == "" {
		return nil, fmt.Errorf("output: NewTree: empty root")
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0o755); err != nil {
			return nil, fmt.Errorf("output: NewTree mkdir %s: %w", sub, err)
		}
	}
	return &OutputTree{Root: root, Scope: scope}, nil
}

// Append writes lines to artefacts/<artefact>.jsonl via AtomicWriter.
// Every line is parsed as JSON; the scope-relevant field is extracted per
// the dispatch table in artefactScopeField. If ANY line is out of scope,
// the whole batch is rejected with *errors.OutOfScope and the existing
// file is NOT modified (no partial write). Empty batches are a no-op.
//
// Write semantics: REPLACE. Tasks should dedup + merge before calling
// Append; the OutputTree boundary writes the full batch contents to the
// artefact file, replacing any prior contents. Per ADR §3.2 "merged set
// written at end of Task."
func (t *OutputTree) Append(artefact string, lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	scopeField := artefactScopeField(artefact)
	for _, line := range lines {
		if scopeField == "" {
			// Artefact has no scope dispatch entry — but the line must still
			// be syntactically valid JSON (otherwise we'd write garbage).
			if !json.Valid(line) {
				return fmt.Errorf("output: Append %s: invalid JSON line: %s", artefact, truncForErr(line))
			}
			continue
		}
		val, isURL, err := extractScopeValue(line, scopeField)
		if err != nil {
			return fmt.Errorf("output: Append %s: %w", artefact, err)
		}
		if val == "" {
			// Field is absent: rejection is safer than silent acceptance —
			// the schema-on-write contract requires the scope-checkable
			// field to exist on the line.
			return fmt.Errorf("output: Append %s: missing %q field on line", artefact, scopeField)
		}
		if t.Scope != nil {
			var inScope bool
			if isURL {
				inScope = t.Scope.IsInScopeURL(val)
			} else {
				inScope = t.Scope.IsInScope(val)
			}
			if !inScope {
				return &coreerrors.OutOfScope{
					Value:  val,
					Reason: fmt.Sprintf("not in workspace scope (%s)", artefact),
				}
			}
		}
	}
	target := filepath.Join(t.Root, "artefacts", artefact+".jsonl")
	return WriteJSONL(target, lines)
}

// artefactScopeField returns the JSON field used for the scope check on
// a given artefact. Empty string means "no scope check (pass-through)" —
// applied to notes.jsonl and any future schemaless artefact.
//
// Per ADR §3.2 dispatch table:
//   - subdomains.jsonl → "subdomain"
//   - hosts.jsonl      → "host"
//   - urls.jsonl       → "url" (URL form)
//   - findings.jsonl   → "host" (primary) → falls back to "url"
//     handled by extractScopeValue
//   - others           → ""  (pass-through)
func artefactScopeField(artefact string) string {
	switch artefact {
	case "subdomains":
		return "subdomain"
	case "hosts":
		return "host"
	case "urls":
		return "url"
	case "findings":
		// Special-cased in extractScopeValue (host or url fallback).
		return "findings:host|url"
	default:
		return ""
	}
}

// extractScopeValue parses line as JSON and extracts the scope-relevant
// value per the field token. Returns (value, isURL, err).
//
// For findings, prefer host; fall back to url. If url is the chosen field
// (urls.jsonl), isURL=true so callers route through IsInScopeURL.
func extractScopeValue(line []byte, field string) (val string, isURL bool, err error) {
	var obj map[string]any
	if err := json.Unmarshal(line, &obj); err != nil {
		return "", false, fmt.Errorf("invalid JSON line: %s", truncForErr(line))
	}
	switch field {
	case "subdomain":
		s, _ := obj["subdomain"].(string)
		return s, false, nil
	case "host":
		s, _ := obj["host"].(string)
		return s, false, nil
	case "url":
		s, _ := obj["url"].(string)
		return s, true, nil
	case "findings:host|url":
		if s, ok := obj["host"].(string); ok && s != "" {
			return s, false, nil
		}
		if s, ok := obj["url"].(string); ok && s != "" {
			return s, true, nil
		}
		return "", false, nil
	default:
		return "", false, nil
	}
}

// truncForErr returns at most 64 bytes of line for error messages, never
// leaking secrets or large payloads. Defensive for log redaction.
func truncForErr(line []byte) string {
	const cap = 64
	if len(line) <= cap {
		return string(line)
	}
	return string(line[:cap]) + "..."
}
