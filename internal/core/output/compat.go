// Source:
//   - ADR §4.1 lines 1376-1411 (AtomicSymlink — BINDING, lifted verbatim).
//   - ADR §4.3 lines 1443-1467 (representative V1→V2 mapping table).
//   - ADR §4.4 lines 1469-1489 (compat writer lifecycle at end-of-scan finalization, error isolation).
//   - .planning/phases/14-cutover-and-migration §D-04 (subset, content-transformed).
//
// The compat layer bridges the v2 JSONL output tree back to the v1 bash-shape
// Recon/<domain>/ contract for the 6-month compat window (ADR §4.5). It is the
// ONE sanctioned place where bash filenames + line-format reappear from v2 JSONL.
//
// WriteCompat TRANSFORMS the high-value v2 artefacts (artefacts/*.jsonl) into
// real bash line-format .txt files (subdomain / host / URL / IP lists — the
// files people actually script against), and reuses AtomicSymlink for the
// same-format directory pass-throughs (raw/nuclei, raw/screenshots). It never
// symlinks a .txt to a .jsonl (bash consumers parse .txt content). Niche v1
// files are intentionally skipped (D-04: incomplete tree by design).
package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// AtomicSymlink creates link → target atomically. Lifted from ADR §4.1
// lines 1392-1404 verbatim, hardened with error wrapping.
//
// The temp-path-in-same-dir pattern ensures os.Rename is atomic (same
// filesystem). os.Symlink is POSIX-atomic; os.Rename over the temp slot
// then atomically swaps the symlink. A reader that opens `link` at any
// point either sees the previous symlink (if any) or the new one;
// neither a stale nor missing intermediate state is observable.
//
// Idempotent: calling twice with the same arguments leaves the symlink
// pointing at target.
func AtomicSymlink(target, link string) error {
	dir := filepath.Dir(link)
	tmp, err := os.CreateTemp(dir, ".symlink-tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanedUp := false
	defer func() {
		if !cleanedUp {
			_ = os.Remove(tmpName)
		}
	}()

	// Close + Remove the placeholder file — we need only the unique name
	// slot for os.Symlink to write into.
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Remove(tmpName); err != nil {
		return err
	}

	if err := os.Symlink(target, tmpName); err != nil {
		return err
	}
	// Atomic swap. After Rename, tmpName no longer exists — flag so the
	// defer skips the (failing) os.Remove.
	if err := os.Rename(tmpName, link); err != nil {
		return err
	}
	cleanedUp = true
	return nil
}

// CompatWriter produces the v1 bash-shape _compat/ tree from a completed v2
// workspace. It is invoked at end-of-scan finalization (the handlers' finalization
// hook point, ADR §4.4) once artefacts/ holds the final merged records.
//
// Contract:
//   - WriteCompat reads workspaces/<target-id>/artefacts/*.jsonl and writes the
//     high-value v1 .txt files under workspaces/<target-id>/_compat/ (see
//     V1ToV2Mapping) plus same-format directory symlinks (nuclei_output,
//     screenshots).
//   - The top-level Recon/<domain> → workspaces/<target-id>/_compat/ symlink
//     (ADR §4.2) is created idempotently when ReconDir is set. Callers that
//     create it at workspace init may leave ReconDir empty.
//   - Error isolation (ADR §4.4): a missing/empty/oversized artefact NEVER
//     crashes the writer. Problems are logged at WARN and the scan continues;
//     WriteCompat returns nil so compat writing can never fail the scan.
type CompatWriter struct {
	// WorkspaceRoot is the absolute path to workspaces/<target-id>/. Used as
	// the fallback root when WriteCompat is called without an OutputTree.
	WorkspaceRoot string
	// ReconDir is the path of the top-level v1 contract symlink Recon/<domain>
	// (see ReconLinkPath). When non-empty, WriteCompat idempotently (re)points
	// it at the _compat/ tree as a RELATIVE symlink, replacing a stale symlink
	// atomically and never clobbering a real directory or file. Empty = the
	// symlink is disabled (output.compat.recon_symlink = false) or created
	// elsewhere.
	ReconDir string
}

// maxCompatLineBytes bounds a single JSONL line the scanner will read, so a
// pathologically long line cannot exhaust memory (threat T-14-02-02). Artefact
// records are single JSON objects — well under this cap in normal operation.
const maxCompatLineBytes = 10 * 1024 * 1024 // 10 MiB

// WriteCompat transforms the workspace's v2 JSONL artefacts into the v1
// bash-shape _compat/ tree. It reads each source artefact itself (OutputTree is
// write-only), extracts the mapped field(s), dedup+sorts, and writes atomic
// .txt files via WriteFile. Same-format directories are symlinked via
// AtomicSymlink. Missing/empty artefacts are skipped with a WARN — WriteCompat
// always returns nil (error isolation, ADR §4.4): compat writing must never
// fail the scan.
func (c *CompatWriter) WriteCompat(tree *OutputTree) error {
	root := ""
	if tree != nil {
		root = tree.Root
	}
	if root == "" {
		root = c.WorkspaceRoot
	}
	if root == "" {
		slog.Warn("compat_writer_no_root",
			"note", "no OutputTree.Root and no WorkspaceRoot — nothing to write")
		return nil
	}

	compatRoot := filepath.Join(root, "_compat")
	// Pre-create the stable bash-shape subtree so the tree exists even when a
	// given artefact is absent, and so AtomicSymlink has a parent dir to write
	// its temp slot into.
	for _, sub := range []string{"subdomains", "webs", "hosts", "vulns", "osint"} {
		if err := os.MkdirAll(filepath.Join(compatRoot, sub), 0o755); err != nil {
			slog.Warn("compat_mkdir_failed", "subdir", sub, "err", err)
		}
	}

	// 1. Content transforms: JSONL artefact → bash line-format .txt.
	for _, rule := range compatRules {
		srcPath, err := securePath(root, rule.artefact)
		if err != nil {
			slog.Warn("compat_source_path_rejected", "artefact", rule.artefact, "err", err)
			continue
		}
		dstPath, err := securePath(root, rule.compatPath)
		if err != nil {
			slog.Warn("compat_dest_path_rejected", "compat", rule.compatPath, "err", err)
			continue
		}

		lines, err := extractLines(srcPath, rule)
		if err != nil {
			if os.IsNotExist(err) {
				// Missing artefact: skip this entry, do not write a stub file.
				slog.Warn("compat_artefact_missing", "artefact", rule.artefact, "compat", rule.compatPath)
				continue
			}
			// Oversized line / read error: extractLines still returned the
			// partial set — write what we have, but record the problem.
			slog.Warn("compat_extract_partial", "artefact", rule.artefact, "err", err)
		}

		var content []byte
		if len(lines) > 0 {
			content = []byte(strings.Join(lines, "\n") + "\n")
		}
		if err := WriteFile(dstPath, content, 0o644); err != nil {
			slog.Warn("compat_write_failed", "compat", rule.compatPath, "err", err)
		}
	}

	// 2. Same-format directory pass-throughs: symlink only (no transform, no
	//    .txt→.jsonl symlink). Reuses the production AtomicSymlink.
	for link, target := range compatDirSymlinks {
		linkPath, err := securePath(root, link)
		if err != nil {
			slog.Warn("compat_symlink_path_rejected", "link", link, "err", err)
			continue
		}
		targetPath, err := securePath(root, target)
		if err != nil {
			slog.Warn("compat_symlink_path_rejected", "target", target, "err", err)
			continue
		}
		if _, err := os.Stat(targetPath); err != nil {
			// Source dir absent: skip rather than create a dangling link.
			slog.Warn("compat_symlink_source_missing", "target", target)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
			slog.Warn("compat_symlink_mkdir_failed", "link", link, "err", err)
			continue
		}
		if err := AtomicSymlink(targetPath, linkPath); err != nil {
			slog.Warn("compat_symlink_failed", "link", link, "target", target, "err", err)
		}
	}

	// 3. Top-level Recon/<domain> → _compat/ contract symlink (ADR §4.2),
	//    created idempotently at the OnEnd hook when ReconDir is wired.
	if c.ReconDir != "" {
		c.linkReconDir(compatRoot)
	}

	return nil
}

// linkReconDir (re)points c.ReconDir at compatRoot (CUT-08, MIGRATION §2.2):
//
//	Recon/example.com → ../workspaces/<target-id>/_compat
//
// The symlink target is RELATIVE to the link's parent so the tree stays valid
// when the engagement directory is moved or mounted elsewhere. A stale symlink
// (previous slug, previous layout) is swapped atomically via AtomicSymlink. A
// pre-existing REAL directory or file at the link path — typically a genuine v1
// Recon/<domain>/ tree the operator still has — is never overwritten: it is
// logged at WARN and the symlink is skipped. Best-effort like the rest of the
// writer: every failure is a WARN, never an error.
func (c *CompatWriter) linkReconDir(compatRoot string) {
	link := c.ReconDir
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		slog.Warn("compat_recon_dir_exists_not_symlink",
			"recon_dir", link,
			"note", "a real directory/file is already there; leaving it untouched and skipping the Recon/<domain> symlink")
		return
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		slog.Warn("compat_recon_parent_mkdir_failed", "recon_dir", link, "err", err)
		return
	}
	if err := AtomicSymlink(relativeSymlinkTarget(link, compatRoot), link); err != nil {
		slog.Warn("compat_recon_symlink_failed", "recon_dir", link, "target", compatRoot, "err", err)
	}
}

// relativeSymlinkTarget returns target expressed relative to link's parent
// directory (what os.Symlink resolves a relative target against). Falls back to
// the absolute target when either path cannot be made absolute or no relative
// form exists (different volumes), so the link is still correct, just absolute.
func relativeSymlinkTarget(link, target string) string {
	absLink, err := filepath.Abs(link)
	if err != nil {
		return target
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return target
	}
	rel, err := filepath.Rel(filepath.Dir(absLink), absTarget)
	if err != nil {
		return absTarget
	}
	return rel
}

// ReconLinkPath computes where the top-level v1 contract symlink for the
// workspace at workdir lives: <parent of the workspaces root>/Recon/<name>,
// i.e. a sibling of workspaces/ (MIGRATION §2.2: Recon/example.com →
// workspaces/<target-id>/_compat/). The name is derived from the workspace's
// own identity marker (.target-identity.json) so it can never disagree with
// the directory the scan actually wrote to:
//
//   - domain targets use the canonical hostname (Recon/example.com — the v1
//     contract every `Recon/$domain/...` script relies on);
//   - IP and CIDR targets use the workspace slug, the same target-id the
//     workspace directory is named with (a CIDR's '/' can never be a path
//     component, and v1 had no stable name for these anyway).
//
// workdir may be relative (it is resolved against the cwd); the result is
// absolute. A workspace without a readable identity marker is an error — the
// caller skips the symlink rather than guessing a name.
func ReconLinkPath(workdir string) (string, error) {
	absWorkdir, err := filepath.Abs(workdir)
	if err != nil {
		return "", fmt.Errorf("output: ReconLinkPath: abs %q: %w", workdir, err)
	}
	marker, err := readIdentityMarker(absWorkdir)
	if err != nil {
		return "", fmt.Errorf("output: ReconLinkPath: identity marker: %w", err)
	}
	name := marker.Slug
	if marker.Kind == KindDomain && marker.Canonical != "" {
		name = marker.Canonical
	}
	// Defense-in-depth: a name must be exactly one path component. Canonical
	// hostnames and slugs are, but a hand-edited marker must not escape Recon/.
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("output: ReconLinkPath: unusable target name %q in %s", name, IdentityMarkerName)
	}
	// absWorkdir = <workspaces root>/<slug>; Recon/ is a sibling of the root.
	return filepath.Join(filepath.Dir(filepath.Dir(absWorkdir)), "Recon", name), nil
}

// ruleKind selects how a JSONL record is rendered into a bash .txt line.
type ruleKind int

const (
	// kindField extracts one string field verbatim (e.g. .subdomain, .ip).
	kindField ruleKind = iota
	// kindWebURL prefers .url; falls back to reconstructing scheme://host.
	kindWebURL
	// kindFinding renders "<severity> <host|url> <rule_id>".
	kindFinding
)

// compatRule maps one v1 bash-shape .txt file to its v2 source artefact and the
// field/transform that produces its lines. This is the single source of truth
// for the content-transform half of the compat writer; V1ToV2Mapping is derived
// from it so the public table can never drift from the extraction logic.
type compatRule struct {
	compatPath string   // .txt path relative to workspace root (under _compat/)
	artefact   string   // source JSONL path relative to workspace root
	field      string   // primary JSON field (kindField)
	kind       ruleKind // how to render each line
}

// compatRules is the D-04 high-value subset (14-RESEARCH Deliverable 3). Order
// is deterministic for readable logs; per-file writes are independent.
var compatRules = []compatRule{
	// subdomains.txt is the 116-ref v1 name; all.txt is the ADR §4.3 seed name.
	{compatPath: "_compat/subdomains/subdomains.txt", artefact: "artefacts/subdomains.jsonl", field: "subdomain", kind: kindField},
	{compatPath: "_compat/subdomains/all.txt", artefact: "artefacts/subdomains.jsonl", field: "subdomain", kind: kindField},
	{compatPath: "_compat/subdomains/subdomains_alive.txt", artefact: "artefacts/hosts.jsonl", field: "host", kind: kindField},
	{compatPath: "_compat/webs/webs.txt", artefact: "artefacts/hosts.jsonl", field: "url", kind: kindWebURL},
	// webs_all.txt is the 99-ref v1 name (all probed URLs).
	{compatPath: "_compat/webs/webs_all.txt", artefact: "artefacts/hosts.jsonl", field: "url", kind: kindField},
	{compatPath: "_compat/hosts/ips.txt", artefact: "artefacts/hosts.jsonl", field: "ip", kind: kindField},
	{compatPath: "_compat/webs/url_extract.txt", artefact: "artefacts/urls.jsonl", field: "url", kind: kindField},
	{compatPath: "_compat/vulns/findings.txt", artefact: "artefacts/findings.jsonl", field: "", kind: kindFinding},
}

// compatDirSymlinks are same-format directory pass-throughs: _compat/<link> is a
// symlink to <target> (raw tool output). Never a .txt→.jsonl symlink.
var compatDirSymlinks = map[string]string{
	"_compat/nuclei_output": "raw/nuclei",
	"_compat/screenshots":   "raw/screenshots",
}

// V1ToV2Mapping is the canonical compat-path → artefact-path table, derived from
// compatRules so it can never drift from the extraction logic. Key = compat
// .txt path relative to the workspace; value = source artefact path.
var V1ToV2Mapping = buildV1ToV2Mapping()

func buildV1ToV2Mapping() map[string]string {
	m := make(map[string]string, len(compatRules))
	for _, r := range compatRules {
		m[r.compatPath] = r.artefact
	}
	return m
}

// securePath joins rel under root and rejects any result that escapes root
// (defense-in-depth vs path traversal, threat T-14-02-01). All compat/artefact
// rel paths are in-tree constants today; this guards future edits + a
// maliciously-shaped root/target-id.
func securePath(root, rel string) (string, error) {
	p := filepath.Join(root, rel)
	cleanRoot := filepath.Clean(root)
	if p != cleanRoot && !strings.HasPrefix(p, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("compat: path %q escapes workspace root %q", rel, root)
	}
	return p, nil
}

// extractLines streams srcPath (a JSONL artefact), renders each record per rule,
// and returns the sorted-unique set of non-empty lines. A missing file returns
// os.ErrNotExist (caller skips). Malformed JSON lines are skipped, not fatal
// (threat T-14-02-02); an oversized line ends the scan early but the partial
// set is still returned alongside the scanner error.
func extractLines(srcPath string, rule compatRule) ([]string, error) {
	f, err := os.Open(srcPath) //nolint:gosec // path is securePath-validated under the workspace root
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only handle

	set := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxCompatLineBytes)
	for sc.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			// Blank or malformed line — skip, never panic.
			continue
		}
		if v := renderLine(obj, rule); v != "" {
			set[v] = struct{}{}
		}
	}
	sorted := setToSorted(set)
	if err := sc.Err(); err != nil {
		return sorted, err
	}
	return sorted, nil
}

// renderLine renders a single decoded JSONL record into its bash .txt line, or
// "" to omit it.
func renderLine(obj map[string]any, rule compatRule) string {
	switch rule.kind {
	case kindWebURL:
		if u, _ := obj["url"].(string); strings.TrimSpace(u) != "" {
			return strings.TrimSpace(u)
		}
		scheme, _ := obj["scheme"].(string)
		host, _ := obj["host"].(string)
		host = strings.TrimSpace(host)
		scheme = strings.TrimSpace(scheme)
		if host == "" || scheme == "" {
			return ""
		}
		return scheme + "://" + host
	case kindFinding:
		sev, _ := obj["severity"].(string)
		host, _ := obj["host"].(string)
		if strings.TrimSpace(host) == "" {
			host, _ = obj["url"].(string)
		}
		rid, _ := obj["rule_id"].(string)
		sev, host, rid = strings.TrimSpace(sev), strings.TrimSpace(host), strings.TrimSpace(rid)
		if sev == "" && host == "" && rid == "" {
			return ""
		}
		return fmt.Sprintf("%s %s %s", sev, host, rid)
	default: // kindField
		s, _ := obj[rule.field].(string)
		return strings.TrimSpace(s)
	}
}

// setToSorted returns the set's keys in sorted order (stable, deduped output).
func setToSorted(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
