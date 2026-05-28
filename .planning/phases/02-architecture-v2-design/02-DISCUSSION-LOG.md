# Phase 2: Architecture v2 Design - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-28
**Phase:** 02-architecture-v2-design
**Areas discussed:** Doc shape & length, Contracts locking tier, TOML schema scope, Sign-off ceremony

---

## Doc shape & length

### Q1: How should the Phase 2 architecture doc be packaged?

| Option | Description | Selected |
|--------|-------------|----------|
| Single mega-ADR | Everything in `.planning/decisions/0002-architecture-v2.md`: TOML schema, all interface signatures, error catalog, CLI surface, test ring policy, logging policy, output tree layout. One file = one source of truth. ~80-150 pages. | ✓ |
| Thin ADR + linked detail docs | `0002-architecture-v2.md` is short (~10-20 pages) with decisions + rationale only; full specs live in linked files: `TOML-SCHEMA.md`, `INTERFACES.md`, `ERRORS.md`, `CLI.md`. | |
| ADR + tabular appendices | Hybrid: ADR has full decision narratives but appendices for schema/interfaces/errors are dense tables. Mid-length (~40-60 pages). | |
| You decide | Defer to Claude. | |

### Q2: How code-heavy should the mega-ADR be?

| Option | Description | Selected |
|--------|-------------|----------|
| Full Go snippets + TOML samples | Every interface section has a working Go code block; every TOML section has a sample with comments; error catalog has minimal Go example of each error. | ✓ |
| Signatures + prose only | Interface SIGNATURES (just `Run(ctx, app) Result` shape, no method bodies); TOML keys + types in a table; error catalog as a table. | |
| Mixed | Full Go for Task/Backend/AppContext + error class hierarchy. Prose for TOML schema, CLI surface, test policy. | |
| You decide | Claude's discretion. | |

### Q3: Should the mega-ADR include architecture diagrams?

| Option | Description | Selected |
|--------|-------------|----------|
| Mermaid + ASCII | Mermaid for top-level diagrams (System Overview, AppContext composition, request flow). ASCII for inline detail (output tree, TOML precedence). | ✓ |
| ASCII only | Old-school ASCII art everywhere. Renders identically in any viewer. | |
| No diagrams | Prose + code only. Future maintainers reconstruct architecture from interfaces + AppContext. | |
| You decide | Claude's discretion. | |

### Q4: How should new readers orient when first reading the ADR?

| Option | Description | Selected |
|--------|-------------|----------|
| TL;DR + glossary + reading order | Top of doc has: TL;DR of every locked decision, glossary of new terms with one-line definitions, suggested reading order. | ✓ |
| Section index only (linear doc) | Table of contents at top; reader goes top-to-bottom. No TL;DR, no glossary. | |
| Frontmatter status + linear | Just YAML frontmatter (Status, Date, Signed By, Supersedes) + linear sections. Match Phase 1's ADR 0001 shape. | |
| You decide | Claude's discretion. | |

**Notes:** Doc-shape decisions favor maximum self-containment and onboarding-readiness. The mega-ADR with full code + TOML + diagrams + TL;DR/glossary is heavier to write but far more useful for the 12-18-month milestone where future-self (or new contributors) will reference the ADR repeatedly.

---

## Contracts locking tier

### Q1: How binding are the interface signatures Phase 2 locks for downstream phases?

| Option | Description | Selected |
|--------|-------------|----------|
| Binding | Once signed, Task/Backend/AppContext signatures + error class shapes are FIXED. Any Phase 3+ deviation requires a formal ADR amendment. | ✓ |
| Draft | Phase 2 ships best-guess signatures; Phase 3's Foundation work treats them as starting points. Final signatures are whatever Phase 3 ships. | |
| Tiered | Core contracts (Task, Backend, AppContext shape) BINDING; secondary (Result fields, error metadata, Tool struct internals) DRAFT. | |
| You decide | Claude's discretion. | |

### Q2: What's the amendment mechanism for the binding ADR?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline amendment block | Phase 3+ proposes change → amendment block appended to `0002-architecture-v2.md` with `Amended: 2026-XX-XX | Section: §N | Reason: …`. Same file, same ADR number. Git history is the audit trail. | ✓ |
| New ADR per amendment | Each amendment is its own ADR file (`0003-...`, `0004-...`) that explicitly `Supersedes: 0002 §N`. Heavier process. | |
| Mid-phase RFC | Phase 3+ writes a one-page RFC in `.planning/rfc/` first; if maintainer approves, the RFC text is merged into the ADR. | |
| You decide | Claude's discretion. | |

### Q3: What counts as a "deviation" triggering the amendment process?

| Option | Description | Selected |
|--------|-------------|----------|
| Breaking changes only | Amendment required when: renaming a method, changing a method signature, removing a field, changing a field's type, redefining error semantics. NOT required for: adding fields, adding new methods, adding new error types. | ✓ |
| Any signature change | Amendment for: ANY field add/rename/remove, ANY method add/remove, ANY type change. | |
| Semantic changes only | Amendment ONLY when the BEHAVIOR contract changes. Field additions and method additions don't need it. | |
| You decide | Claude's discretion. | |

### Q4: Who approves an amendment to the ADR?

| Option | Description | Selected |
|--------|-------------|----------|
| Same as sign-off ceremony | Whatever governance gate is used for the original ADR sign-off applies to amendments. Consistent rule. | ✓ |
| Self-approve for non-breaking, gated for breaking | Phase 3+ executor commits the amendment block inline IF non-breaking. Breaking-change amendments require a separate maintainer sign-off step. | |
| All amendments require explicit maintainer turn | Even non-breaking amendments require explicit /gsd-execute-phase checkpoint. | |
| You decide | Claude's discretion. | |

**Notes:** Locking-tier decisions favor stability + lightweight friction. Binding signatures with inline amendments + breaking-change-only triggers + same-gate governance = Phase 3 can grow the contracts freely on non-breaking changes while the audit trail captures every breaking change in one searchable file.

---

## TOML schema scope

### Q1: How much of the v1 reconftw.cfg surface should the v2 TOML schema cover?

| Option | Description | Selected |
|--------|-------------|----------|
| All ~323 v1 flags 1:1 | Every v1 flag in reconftw.cfg has a documented TOML equivalent. Migrator does strict 1:1 mapping. Zero migration surprises. | ✓ |
| Core flags + extension namespace | TOML schema covers ~80-100 'core' flags. v1's obscure flags go in a generic `[advanced.<tool>]` table. | |
| v2 native only | TOML schema describes ONLY the v2-natural shape (~50-60 keys). Migrator translates v1 → v2 heuristically; some obscure v1 flags get dropped silently. | |
| You decide | Claude's discretion. | |

### Q2: Given 1:1 v1 coverage, how should the TOML namespace be organized?

| Option | Description | Selected |
|--------|-------------|----------|
| v2-native hierarchy + v1-name aliases | Schema groups keys by v2 domain (`[subdomains.passive]`, `[web.fuzz]`, etc.). Each v1 flag is reachable EITHER under its v2-natural location OR via a `[legacy]` section using the original UPPER_CASE name. | ✓ |
| Flat namespace | TOML keys mirror v1 names directly: `SUBPASSIVE = true`, `HTTPX_RATELIMIT = 150`. | |
| Strict v2-native + MIGRATION.md lookup | TOML schema is fully v2-shaped (no UPPER_CASE anywhere); MIGRATION.md is the lookup table for old→new names. | |
| You decide | Claude's discretion. | |

### Q3: How should the schema treat v1 flags that have no v2 analog?

| Option | Description | Selected |
|--------|-------------|----------|
| Drop with migrator warning | Schema doesn't include them. Migrator detects them in user's v1 cfg, emits a MIGRATION-WARNINGS.md line per dropped flag. | ✓ |
| Keep as deprecated entries | Schema includes them in `[legacy.deprecated]` namespace marked `deprecated = true`; v2 reads them but ignores them with a runtime warning. | |
| Defer to Phase 11 | Phase 2 ADR doesn't decide — just declares Phase 11 produces the canonical drop list during installer/migrator design. | |
| You decide | Claude's discretion. | |

### Q4: Should the TOML schema lock per-key validation rules in Phase 2, or defer to Phase 3?

| Option | Description | Selected |
|--------|-------------|----------|
| Lock validation in Phase 2 | Every key in the schema has its validation rules documented: type, range, regex pattern, required/optional, default, mutually-exclusive groups. Phase 3 IMPLEMENTS the rules. | ✓ |
| Types only | Schema declares each key's type (`string`, `int`, `bool`, `[]string`) and a brief one-liner. Phase 3 picks validation depth. | |
| Hybrid | Validation locked for security-critical keys (paths, URLs, API keys, rate limits); everything else types-only. | |
| You decide | Claude's discretion. | |

**Notes:** TOML scope decisions favor migration parity over schema minimalism. 1:1 v1 flag coverage means existing v1 users have zero migration surprises; v2-native hierarchy + legacy aliases gives both clean schema and soft landing; validation rules locked alongside the schema make security and behavioral guarantees explicit (not Phase 3 inventions).

---

## Sign-off ceremony

### Q1: Same sign-off ceremony as Phase 1 (solo same-day), or community pre-review for Phase 2?

| Option | Description | Selected |
|--------|-------------|----------|
| Solo same-day (same as Phase 1 D-02) | Maintainer writes the ADR, signs same day, commits to `rewrite/v2`. No community gate. Amendments are still allowed. | ✓ |
| GitHub Discussion + 1-week comment window | Draft ADR posted as GitHub Discussion thread; 1-week open comment period; maintainer reviews comments, may amend, then signs. | |
| Cross-AI review (use /gsd:review) | Draft ADR → `/gsd:review` to get peer review from external AI CLIs; incorporate findings; sign. | |
| Both: cross-AI THEN solo sign-off | Maintainer drafts → `/gsd:review` external AI peers → maintainer revises → signs same-day. Belt-and-suspenders. | |

### Q2: Should signing require a pre-commit checklist (verify-before-signing gate)?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — explicit pre-sign verification | Before flipping Status to Accepted, executor runs programmatic checks: ARCH-NN coverage, TOML parse, Go snippet compile, glossary completeness. | ✓ |
| No — same flow as Phase 1 (read + sign) | Maintainer reads through; if it looks done, signs. Consistent with Phase 1's lightweight ceremony. | |
| Hybrid — spot-check, not exhaustive | Maintainer manually spot-checks 3-5 sections + grep validation that ARCH-01..ARCH-12 are all mentioned by REQ-ID. | |
| You decide | Claude's discretion. | |

### Q3: Where does the signed ADR live after Phase 2?

| Option | Description | Selected |
|--------|-------------|----------|
| Same place as ADR 0001 — `.planning/decisions/0002-architecture-v2.md` | Consistent with Phase 1. Committed to `rewrite/v2`. Future ADRs follow the same pattern. | ✓ |
| Docs site / website | ADR also published to a docs site for SEO + searchability + cross-linking. | |
| Both — source in .planning/, mirror to docs at release | Source lives in `.planning/decisions/`. At each v2.x release, the docs site is regenerated. | |
| You decide | Claude's discretion. | |

### Q4: Should signing the ADR trigger any downstream artifact updates?

| Option | Description | Selected |
|--------|-------------|----------|
| Update STATE.md + PROJECT.md only | Phase 2's sign-off task updates STATE.md (Phase 2 complete) and PROJECT.md (Key Decisions row). No collapse of research files. | ✓ |
| Update STATE.md/PROJECT.md AND collapse research/ARCHITECTURE.md | ARCHITECTURE.md is rewritten to reference the signed ADR as the source of truth. Analogous to D-03 from Phase 1. | |
| Update STATE.md/PROJECT.md, regenerate REQUIREMENTS.md traceability | Sign-off updates STATE/PROJECT AND re-runs requirements traceability scan. | |
| You decide | Claude's discretion. | |

**Notes:** Sign-off decisions favor speed + safety. Solo same-day matches Phase 1; the pre-sign verification gate (programmatic ARCH-NN coverage + TOML parse + Go compile + glossary) catches docs-completeness bugs cheaply WITHOUT requiring a calendar-time community review. No research-file collapse because architecture research is broader than the ADR — the ADR cites the research but doesn't supersede it (different shape from D-03 in Phase 1 where the loser language genuinely needed to be expunged).

---

## Claude's Discretion

These areas were not exhaustively discussed; researcher and planner resolve with sensible defaults:

- **Compat-symlink fidelity** — Whether the ADR specifies file-by-file mapping for every `Recon/<domain>/X.txt` → `workspaces/<id>/Y.jsonl`, or specifies the principle + 3-5 examples.
- **MCP contract pre-locking** — Whether Phase 2 ADR locks `Backend.Stream()` for Phase 8 MCP server now, or defers entirely.
- **AppContext composition style** — Single big struct vs smaller composable contexts (`RunCtx`, `ToolCtx`, `SchedCtx`).
- **CLI deprecation timeline measurement unit** — "2 minor versions" is locked; calendar time vs release count is planner's call.
- **Test ring depth per ring** — ARCH-11 names the rings; the ADR's prescription level per ring is planner's call.
- **Logging redaction pattern specifics** — Go `Secret` + `LogValuer` + slog handler chain shape is researcher/planner territory.

## Deferred Ideas

- Docs-site mirror of `.planning/decisions/` (Phase 11 packaging follow-up)
- GitHub Discussion / Twitter announcement of ADR 0002 sign-off (Phase 12 post-cutover marketing)
- Compat-symlink deletion timeline (locked at "6 months post-cutover" by milestone init; Phase 12 finalizes the exact date)
