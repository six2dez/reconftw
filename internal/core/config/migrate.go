// Config migrator engine (Phase 14 — CUT-01/02/05/06, D-01/D-02/D-03).
//
// Migrate translates a v1 bash `reconftw.cfg` into a v2-native TOML config the
// v2 loader round-trips with ZERO unknown-key warnings. It implements:
//
//   - Line-by-line parse (SPEC-mandated): `KEY=VALUE`, skipping blank / comment
//     / `export ` / bash control-flow lines.
//   - Value evaluation (D-01): the `$(nproc …)` idiom → runtime.NumCPU(),
//     `$(( expr ))` arithmetic → Go stdlib `go/parser`+`go/constant` (int-only,
//     NEVER a shell), `${VAR:-default}` → its literal default, quoted scalars
//     unquoted, durations/CSV kept as strings. NO value is EVER passed to a
//     shell (CLAUDE.md ARCH-02; threat T-14-01).
//   - Three-way disposition (D-02): Case A mapped → live v2-native key with an
//     inline `# was KEY` note; Case B superseded → `# SUPERSEDED …` comment;
//     Case C unknown → `# UNKNOWN …` comment + loud `⚠ unknown key …` stderr.
//     The output is NEVER a live [legacy] block (RESEARCH ★Q1).
//
// The engine is pure (no cobra, no file writes in Migrate) so it is unit-testable;
// MigrateFile is the thin file-I/O wrapper used by the CLI adapter.

package config

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/token"
	"io"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/output"
)

// DispositionCase is the D-02 three-way classification of a single v1 key.
type DispositionCase int

const (
	CaseMapped     DispositionCase = iota // A: live v2-native key
	CaseSuperseded                        // B: `# SUPERSEDED …` comment
	CaseUnknown                           // C: `# UNKNOWN …` comment + loud stderr
)

func (c DispositionCase) String() string {
	switch c {
	case CaseMapped:
		return "mapped"
	case CaseSuperseded:
		return "superseded"
	case CaseUnknown:
		return "unknown"
	default:
		return "?"
	}
}

// MigrateOptions controls migrate-time behavior. WarnSink defaults to os.Stderr
// (mirroring loader.go's WarnSink idiom); tests inject a buffer.
type MigrateOptions struct {
	WarnSink io.Writer
	DryRun   bool
}

// DispositionEntry records how one v1 key was handled. TableNote and the
// rendered value fields are always secret-safe (redacted); the live TOML value
// (with the real secret) lives only in MigrateResult.TOML.
type DispositionEntry struct {
	Key       string
	Case      DispositionCase
	V2Path    string // Case A: the v2-native path
	Comment   string // Case B/C: the TOML comment line (secret-redacted)
	TableNote string // secret-safe one-liner for the --dry-run table
	Secret    bool
}

// MigrateResult carries the ordered disposition and the assembled TOML so the
// CLI can honor --dry-run (print the table, write nothing) without re-parsing.
type MigrateResult struct {
	Entries         []DispositionEntry
	TOML            []byte
	MappedCount     int
	SupersededCount int
	UnknownCount    int
}

// mergedEntry is one v2-native key being emitted; collisions (many v1 → one v2)
// merge here per the collision policy (OR-combine for bools, last-wins else).
type mergedEntry struct {
	kind       reflect.Kind
	literal    string // real TOML literal (secret written verbatim to file)
	sourceKeys []string
	secret     bool
	boolVal    bool // tracked for OR-combine on bool collisions
}

var (
	assignRe     = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$`)
	nprocIdiomRe = regexp.MustCompile(`\$\(\s*nproc\b`)
	arithRe      = regexp.MustCompile(`^\$\(\((.*)\)\)$`)
	varDefaultRe = regexp.MustCompile(`^\$\{[A-Za-z_][A-Za-z0-9_]*:-(.*)\}$`)
	shellRe      = regexp.MustCompile(`\$\(|\$\{|\$[A-Za-z_]`)
)

// Migrate parses v1 cfg from in and returns the disposition + assembled v2 TOML.
// It writes no files (the CLI/MigrateFile own I/O). Loud unknown-key warnings go
// to opts.WarnSink at migrate-time (CUT-06), never on subsequent config loads.
func Migrate(in io.Reader, opts MigrateOptions) (MigrateResult, error) {
	if opts.WarnSink == nil {
		opts.WarnSink = os.Stderr
	}
	order, values, err := parseCfg(in)
	if err != nil {
		return MigrateResult{}, err
	}

	emit := map[string]*mergedEntry{}
	var res MigrateResult

	for _, key := range order {
		raw := values[key]
		ev := evaluateValue(raw)
		secret := legacyAliasSecretKeys[key]

		// Case B — explicit superseded set (checked FIRST; takes precedence over
		// any legacyAliasMap entry so drop-list keys never emit a live value).
		if info, ok := supersededKeys[key]; ok {
			res.Entries = append(res.Entries, supersededEntry(key, ev.value, info, secret))
			res.SupersededCount++
			continue
		}

		// Case A — mapped to a v2-native path.
		if path, ok := legacyAliasMap[key]; ok {
			if ev.shell {
				// Value carries unresolved shell expansion (${VAR}, $(cat …)): we
				// cannot emit a concrete value, so preserve it as a Case-B comment
				// rather than silently drop it (D-02 keep-all).
				info := supersededInfo{reason: "value uses runtime shell expansion; set " + path + " explicitly", pin: path}
				res.Entries = append(res.Entries, supersededEntry(key, ev.value, info, secret))
				res.SupersededCount++
				continue
			}
			kind, literal, cerr := coerceForPath(path, ev.value)
			if cerr != nil {
				// Type mismatch (e.g. a v1 duration into a v2 int field): keep as a
				// Case-B comment instead of dropping or emitting an invalid value.
				info := supersededInfo{reason: "value does not fit the v2 field type; set it manually", pin: path}
				res.Entries = append(res.Entries, supersededEntry(key, ev.value, info, secret))
				res.SupersededCount++
				continue
			}
			addToEmit(emit, path, kind, literal, key, secret, ev.value)
			res.Entries = append(res.Entries, DispositionEntry{
				Key:       key,
				Case:      CaseMapped,
				V2Path:    path,
				TableNote: path + " = " + redact(literal, secret),
				Secret:    secret,
			})
			res.MappedCount++
			continue
		}

		// Case C — unknown: loud stderr NOW (CUT-06) + a preserved comment.
		fmt.Fprintf(opts.WarnSink, "⚠ unknown key %s — needs human review\n", key)
		res.Entries = append(res.Entries, DispositionEntry{
			Key:       key,
			Case:      CaseUnknown,
			Comment:   fmt.Sprintf("# UNKNOWN (needs human review): %s = %s", key, redact(ev.value, secret)),
			TableNote: "needs human review",
			Secret:    secret,
		})
		res.UnknownCount++
	}

	res.TOML = emitTOML(emit, res.Entries)
	return res, nil
}

// MigrateFile opens fromPath, migrates it, and (unless DryRun or a stdout target)
// atomically writes the v2 TOML to toPath via output.WriteFile. A toPath of ""
// or "-" means "stream from the caller" — MigrateFile writes nothing and the CLI
// prints res.TOML.
func MigrateFile(fromPath, toPath string, opts MigrateOptions) (MigrateResult, error) {
	f, err := os.Open(fromPath)
	if err != nil {
		return MigrateResult{}, fmt.Errorf("migrate: open %s: %w", fromPath, err)
	}
	defer f.Close() //nolint:errcheck

	res, err := Migrate(f, opts)
	if err != nil {
		return res, err
	}
	if opts.DryRun || toPath == "" || toPath == "-" {
		return res, nil
	}
	if err := output.WriteFile(toPath, res.TOML, 0o644); err != nil {
		return res, fmt.Errorf("migrate: write %s: %w", toPath, err)
	}
	return res, nil
}

// DispositionTable renders a secret-safe, human-readable disposition table for
// the --dry-run preview. It NEVER contains a raw secret value.
func (r MigrateResult) DispositionTable() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-40s %-11s %s\n", "V1 KEY", "CASE", "V2 PATH / NOTE")
	b.WriteString(strings.Repeat("-", 90) + "\n")
	for _, e := range r.Entries {
		fmt.Fprintf(&b, "%-40s %-11s %s\n", e.Key, e.Case.String(), e.TableNote)
	}
	fmt.Fprintf(&b, "\nSummary: %d mapped, %d superseded, %d unknown\n",
		r.MappedCount, r.SupersededCount, r.UnknownCount)
	return b.String()
}

// ---------- parse ----------

// parseCfg reads v1 cfg lines and returns the first-seen key order plus a
// key→raw-value map (last assignment wins, mirroring bash sourcing). Blank,
// comment, `export `, and control-flow lines are skipped.
func parseCfg(in io.Reader) ([]string, map[string]string, error) {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var order []string
	values := map[string]string{}
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "export ") {
			continue
		}
		m := assignRe.FindStringSubmatch(line)
		if m == nil {
			continue // not a KEY= assignment (control-flow, case arm, etc.)
		}
		key, raw := m[1], m[2]
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = raw
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("migrate: read cfg: %w", err)
	}
	return order, values, nil
}

// ---------- evaluate ----------

type evalResult struct {
	value string // cleaned, concrete value (unquoted, comment-stripped)
	shell bool   // true if the value still carries unresolved shell expansion
}

// evaluateValue resolves a raw v1 value to a concrete Go string WITHOUT any
// shell-out (D-01/CUT-02): the $(nproc …) idiom → runtime.NumCPU(), $(( … ))
// arithmetic → go/constant, ${VAR:-default} → default. Anything still carrying
// shell expansion returns shell=true so the caller routes it to Case B.
func evaluateValue(raw string) evalResult {
	v := strings.TrimSpace(stripInlineComment(raw))
	if v == "" {
		return evalResult{"", false}
	}
	// $(nproc 2>/dev/null || sysctl … || echo N) idiom → the host CPU count.
	if nprocIdiomRe.MatchString(v) {
		return evalResult{strconv.Itoa(runtime.NumCPU()), false}
	}
	// $(( expr )) — substitute the one known var ref, then stdlib int-eval.
	if m := arithRe.FindStringSubmatch(v); m != nil {
		expr := strings.ReplaceAll(m[1], "AVAILABLE_CORES", strconv.Itoa(runtime.NumCPU()))
		if n, err := evalIntExpr(expr); err == nil {
			return evalResult{strconv.Itoa(n), false}
		}
		return evalResult{v, true}
	}
	inner, wasDouble := unquote(v)
	// ${VAR:-default} → its literal default (never an env lookup — deterministic).
	if m := varDefaultRe.FindStringSubmatch(inner); m != nil {
		return evalResult{m[1], false}
	}
	// Any remaining shell expansion ($(cat …), ${VAR}, $VAR) is not expanded.
	if shellRe.MatchString(inner) {
		return evalResult{inner, true}
	}
	if wasDouble {
		inner = unescapeDoubleQuoted(inner)
	}
	return evalResult{inner, false}
}

// stripInlineComment truncates a value at an unquoted ` #`/`\t#` comment start.
func stripInlineComment(s string) string {
	inS, inD := false, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return s[:i]
			}
		}
	}
	return s
}

// unquote strips one layer of matching surrounding quotes. The second return is
// true only for double-quotes (which permit backslash escapes).
func unquote(v string) (string, bool) {
	if len(v) >= 2 {
		if v[0] == '"' && v[len(v)-1] == '"' {
			return v[1 : len(v)-1], true
		}
		if v[0] == '\'' && v[len(v)-1] == '\'' {
			return v[1 : len(v)-1], false
		}
	}
	return v, false
}

// unescapeDoubleQuoted applies the bash double-quote escape subset (\\, \", \`,
// \$) so a cfg value like "169\\.254" resolves to the concrete regex 169\.254.
func unescapeDoubleQuoted(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '"', '`', '$':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// evalIntExpr evaluates a pure-integer arithmetic expression with the Go stdlib
// (go/parser + go/constant), restricted to + - * / ( ) and int literals. It is
// the SAFE, injection-free replacement for a bash `$(( … ))` eval (threat T-14-01).
func evalIntExpr(expr string) (int, error) {
	node, err := parser.ParseExpr(expr)
	if err != nil {
		return 0, err
	}
	v, err := evalConst(node)
	if err != nil {
		return 0, err
	}
	n, ok := constant.Int64Val(v)
	if !ok {
		return 0, fmt.Errorf("non-integer arithmetic result")
	}
	return int(n), nil
}

func evalConst(n ast.Expr) (constant.Value, error) {
	switch e := n.(type) {
	case *ast.BasicLit:
		if e.Kind != token.INT {
			return nil, fmt.Errorf("only integer literals allowed")
		}
		return constant.MakeFromLiteral(e.Value, token.INT, 0), nil
	case *ast.ParenExpr:
		return evalConst(e.X)
	case *ast.UnaryExpr:
		x, err := evalConst(e.X)
		if err != nil {
			return nil, err
		}
		if e.Op == token.ADD || e.Op == token.SUB {
			return constant.UnaryOp(e.Op, x, 0), nil
		}
		return nil, fmt.Errorf("unsupported unary operator %s", e.Op)
	case *ast.BinaryExpr:
		x, err := evalConst(e.X)
		if err != nil {
			return nil, err
		}
		y, err := evalConst(e.Y)
		if err != nil {
			return nil, err
		}
		switch e.Op {
		case token.ADD, token.SUB, token.MUL:
			return constant.BinaryOp(x, e.Op, y), nil
		case token.QUO:
			xi, xok := constant.Int64Val(x)
			yi, yok := constant.Int64Val(y)
			if !xok || !yok {
				return nil, fmt.Errorf("non-integer division operand")
			}
			if yi == 0 {
				return nil, fmt.Errorf("division by zero")
			}
			return constant.MakeInt64(xi / yi), nil
		}
		return nil, fmt.Errorf("unsupported binary operator %s", e.Op)
	default:
		return nil, fmt.Errorf("unsupported expression %T", n)
	}
}

// ---------- disposition helpers ----------

// coerceForPath resolves the v2 field kind at path (via readByPath on Defaults)
// and renders a TOML literal of the correct type. Returns an error when the
// value cannot be coerced to the field's type (routed to Case B by the caller).
func coerceForPath(path, val string) (reflect.Kind, string, error) {
	def := readByPath(Defaults(), path)
	if def == nil {
		return 0, "", fmt.Errorf("no field for path %q", path)
	}
	kind := reflect.ValueOf(def).Kind()
	switch kind {
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.ToLower(strings.TrimSpace(val)))
		if err != nil {
			return 0, "", fmt.Errorf("not a bool: %q", val)
		}
		return kind, boolLit(b), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
		if err != nil {
			return 0, "", fmt.Errorf("not an int: %q", val)
		}
		return kind, strconv.FormatInt(n, 10), nil
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
		if err != nil {
			return 0, "", fmt.Errorf("not a float: %q", val)
		}
		return kind, strconv.FormatFloat(f, 'g', -1, 64), nil
	case reflect.String:
		return kind, tomlBasicString(val), nil
	default:
		return 0, "", fmt.Errorf("unsupported field kind %s at %q", kind, path)
	}
}

// addToEmit merges a Case-A value into the emit map, applying the collision
// policy for many-v1→one-v2 keys: OR-combine for booleans, last-wins otherwise,
// recording every source key for the `# was KEY1 / KEY2` provenance comment.
func addToEmit(m map[string]*mergedEntry, path string, kind reflect.Kind, literal, key string, secret bool, val string) {
	if ex, ok := m[path]; ok {
		if kind == reflect.Bool {
			b, _ := strconv.ParseBool(strings.ToLower(strings.TrimSpace(val)))
			ex.boolVal = ex.boolVal || b
			ex.literal = boolLit(ex.boolVal)
		} else {
			ex.literal = literal // last-wins
		}
		ex.sourceKeys = append(ex.sourceKeys, key)
		if secret {
			ex.secret = true
		}
		return
	}
	me := &mergedEntry{kind: kind, literal: literal, sourceKeys: []string{key}, secret: secret}
	if kind == reflect.Bool {
		me.boolVal, _ = strconv.ParseBool(strings.ToLower(strings.TrimSpace(val)))
	}
	m[path] = me
}

// supersededEntry builds a Case-B disposition with a `# SUPERSEDED …` comment.
func supersededEntry(key, val string, info supersededInfo, secret bool) DispositionEntry {
	shown := redact(val, secret)
	comment := fmt.Sprintf("# SUPERSEDED: %s = %s  — %s", key, shown, info.reason)
	note := info.reason
	if info.pin != "" {
		comment += fmt.Sprintf("; to pin manually set %s = %s", info.pin, shown)
		note += " (pin " + info.pin + ")"
	}
	return DispositionEntry{
		Key:       key,
		Case:      CaseSuperseded,
		Comment:   comment,
		TableNote: note,
		Secret:    secret,
	}
}

// ---------- emit ----------

// schemaLeaf is one migratable scalar leaf of the v2 Config schema, in struct
// (== ADR §2.2) order, with its containing section and Go kind.
type schemaLeaf struct {
	section string
	leaf    string
	full    string
}

// schemaLeafOrder walks the Config struct reflectively to produce every scalar
// leaf's dotted path in canonical struct order. This drives deterministic,
// struct-ordered TOML emission (non-scalar leaves — Legacy map, Events slice,
// LogOutput writer — are skipped: no v1 key maps to them).
func schemaLeafOrder() []schemaLeaf {
	var out []schemaLeaf
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("koanf")
			if tag == "" || tag == "-" {
				continue
			}
			full := tag
			if prefix != "" {
				full = prefix + "." + tag
			}
			switch f.Type.Kind() {
			case reflect.Struct:
				walk(f.Type, full)
			case reflect.Map, reflect.Slice, reflect.Interface:
				continue
			default:
				out = append(out, schemaLeaf{section: prefix, leaf: tag, full: full})
			}
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	return out
}

// emitTOML renders the migrated config: live v2-native keys grouped in struct
// (ADR §2.2) section order with inline `# was KEY` provenance, followed by a
// trailing comment block of the Case-B/C keys. It NEVER emits a live [legacy]
// table (D-02) — superseded/unknown keys are comments the loader never parses.
func emitTOML(emit map[string]*mergedEntry, entries []DispositionEntry) []byte {
	var b strings.Builder
	b.WriteString("# reconftw v2 configuration — migrated from reconftw.cfg by `reconftw migrate`.\n")
	b.WriteString("# Mapped v1 keys are live v2-native keys (inline `# was KEY`). Superseded/unknown\n")
	b.WriteString("# v1 keys are preserved as comments so this file loads with zero warnings.\n\n")

	leaves := schemaLeafOrder()
	for i := 0; i < len(leaves); {
		sec := leaves[i].section
		var lines []string
		for i < len(leaves) && leaves[i].section == sec {
			if me, ok := emit[leaves[i].full]; ok {
				lines = append(lines, formatLeafLine(leaves[i].leaf, me))
			}
			i++
		}
		if len(lines) > 0 {
			b.WriteString("[" + sec + "]\n")
			for _, l := range lines {
				b.WriteString(l)
				b.WriteByte('\n')
			}
			b.WriteByte('\n')
		}
	}

	var comments []string
	for _, e := range entries {
		if e.Case == CaseSuperseded || e.Case == CaseUnknown {
			comments = append(comments, e.Comment)
		}
	}
	if len(comments) > 0 {
		b.WriteString("# ---------------------------------------------\n")
		b.WriteString("# Superseded / unknown v1 keys (preserved for reference — NOT active v2 config)\n")
		b.WriteString("# ---------------------------------------------\n")
		for _, c := range comments {
			b.WriteString(c)
			b.WriteByte('\n')
		}
	}
	return []byte(b.String())
}

// formatLeafLine renders one live v2-native key with sorted `# was KEY` provenance.
func formatLeafLine(leaf string, me *mergedEntry) string {
	keys := append([]string(nil), me.sourceKeys...)
	sort.Strings(keys)
	return fmt.Sprintf("%s = %s  # was %s", leaf, me.literal, strings.Join(keys, " / "))
}

// ---------- small utilities ----------

func boolLit(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// redact returns "***" for secret values, the value otherwise (used for all
// stderr / --dry-run / comment rendering; the live TOML key keeps the real value).
func redact(v string, secret bool) string {
	if secret {
		return "***"
	}
	return v
}

// tomlBasicString encodes s as a TOML basic (double-quoted) string with the
// standard escapes, so go-toml/v2 parses it back to the exact Go value.
func tomlBasicString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
