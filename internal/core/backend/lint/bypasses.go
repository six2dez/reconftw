// SPDX-License-Identifier: MIT
//
// bypasses.go — the typed FOUND-10 bypass manifest (plan 18-03, RS-C).
//
// WHY THIS FILE EXISTS. Until 18-03 the FOUND-10 gate was a []string of
// repo-relative paths carrying free-text comments. An experiment run at the top
// of 18-03 established the mechanism by observation rather than by reading the
// rule (all four steps and their output are in 18-03-SUMMARY.md):
//
//	step 2 — a new file under internal/modules/ with one direct dispatch and no
//	         allowlist entry FAILED the gate. The rule fires.
//	step 3 — appending that file's path with a comment claiming a reason that was
//	         KNOWN FALSE for it turned the gate GREEN. Nothing corroborates a
//	         justification.
//
// So the guard's failure mode was never "it does not fire". It is that the
// remedy it invites — one line of path plus one paragraph of prose — IS the
// bypass, and the prose is unfalsifiable. Six undocumented bypasses entered the
// tree through that door.
//
// WHAT REPLACED IT. Every entry below declares a CLOSED-VOCABULARY reason set,
// and each reason carries a corroboration predicate evaluated against THAT
// FILE'S OWN SYNTAX TREE (bypasses_test.go). A claim that the file reads standard
// input must be evidenced by an assignment to the Stdin field of a value whose
// type resolves to *os/exec.Cmd. `Why` is prose FOR A HUMAN and the guard trusts
// none of it.
//
// The manifest is also a WORK LIST. `HomeBy` names the plan that routes the file
// back onto backend.Runner; a `pending_removal` entry with an empty `HomeBy`
// fails the gate, because a temporary exemption with no expiry is a permanent one.
package lint

// Reason is a member of the CLOSED vocabulary of bypass justifications.
//
// Closed means: a reason string with no corroboration predicate defined in
// bypasses_test.go FAILS the gate rather than defaulting to permitted. A
// vocabulary member that corroborates nothing is a hole with a name.
type Reason string

// The vocabulary. Each member's corroboration predicate lives in
// bypasses_test.go (reasonPredicates); adding a member here without adding a
// predicate there is caught by TestUnknownReasonFails.
const (
	// ReasonStdin — the file assigns the Stdin field of an *os/exec.Cmd.
	ReasonStdin Reason = "stdin"

	// ReasonWorkDir — the file assigns the Dir field of an *os/exec.Cmd.
	ReasonWorkDir Reason = "work_dir"

	// ReasonClonePath — the dispatched executable, or its leading script
	// argument, is a path constructed with filepath.Join rather than a bare
	// tool name resolved on PATH.
	ReasonClonePath Reason = "clone_path"

	// ReasonProcessLifecycle — the file manages the child process's lifetime
	// itself: a SysProcAttr assignment, or a signal delivered to a negative pid
	// (a process group).
	ReasonProcessLifecycle Reason = "process_lifecycle"

	// ReasonNonReconBinary — the dispatched program name is not an entry in
	// internal/core/backend/tools.lock. The registry runs the recon inventory;
	// it is not a general-purpose process launcher.
	ReasonNonReconBinary Reason = "non_recon_binary"

	// ReasonInstallerToolchain — the file is under internal/installer/, which
	// runs package managers and the toolchain bootstrap, not recon tools.
	ReasonInstallerToolchain Reason = "installer_toolchain"

	// ReasonPendingRemoval — this bypass has no surviving technical reason and
	// is scheduled to be routed back onto backend.Runner. REQUIRES a non-empty
	// HomeBy naming the owning plan (TestNoPendingRemovalOutlivesItsPlan).
	ReasonPendingRemoval Reason = "pending_removal"
)

// Bypass is one declared file that dispatches a subprocess outside
// backend.Runner.
type Bypass struct {
	// File is the repo-relative path, forward slashes.
	File string

	// Reasons is every reason that applies. ALL of them must be corroborated
	// against the file's syntax tree, and together they must explain EVERY
	// dispatch site in the file — a two-shape file cannot hide its second shape
	// behind its first shape's reason.
	Reasons []Reason

	// Sites is the EXACT number of direct dispatch sites the AST walker finds in
	// this file. Not a floor: an exact match, checked in both directions, so a
	// second dispatch added to an already-forgiven file is a failing diff.
	Sites int

	// Tool is the program this file dispatches, for the census.
	Tool string

	// Why is prose for a human: what capability the seam lacked AT THE TIME.
	// The guard trusts NOTHING in this field.
	Why string

	// HomeBy is "" or the plan id that routes this file back onto
	// backend.Runner. Required when Reasons contains ReasonPendingRemoval.
	HomeBy string
}

// Bypasses is the manifest. One entry per file that dispatches outside
// backend.Runner. Infrastructure files (the seam itself and its tests) are NOT
// here — see infrastructureAllowlist in bypasses_test.go.
var Bypasses = []Bypass{
	// ---- vulns ----------------------------------------------------------------
	// internal/modules/vulns/ssrf.go went home in 18-05 Task 3 (2 sites), and it
	// is the entry whose reason this phase inherited as NOT obsolete. 18-03
	// recorded process_lifecycle as the one reason 18-01 had not served, because
	// ExecOptions has no caller-managed background-process mode. 18-05 tested that
	// rather than inheriting it: "no background-process MODE" is not "cannot serve
	// this lifecycle". Runner.StreamOpts returns a channel outliving the call, and
	// LocalBackend.StreamOpts already sets Setpgid, group-SIGTERMs on cancel and
	// escalates to a group SIGKILL for grandchildren.
	// TestInteractshLifecycleThroughStreamOpts proves all three legs against a
	// real process with a SIGTERM-IMMUNE grandchild; MUTATION 5 proved the
	// kill-tree assertion is real (it PASSED on the first fixture, which is why
	// the fixture now traps TERM). The interactsh-client row was set to
	// timeout_seconds = 0 in the same change — see its derivation in tools.lock.
	// internal/modules/vulns/bypass4xx.go went home in 18-05 Task 2 (2 sites),
	// alongside web/nomore403.go and by the same path. Its former reasons (stdin,
	// work_dir) were both served: ExecOptions.Stdin from 18-01, Tool.WorkDir from
	// 18-02's clone_workdir. The two modules now resolve the SAME Tool.Path for
	// nomore403, asserted by TestBypass4xxAndNomore403ResolveTheSameBinary — which
	// is the defect the pair of entries really recorded.

	// ---- web --------------------------------------------------------------------
	// internal/modules/web/nomore403.go went home in 18-05 Task 1 (2 sites). It
	// needed all three of 18-01/18-02's capabilities at once — an executable
	// resolved from a clone, that clone as cwd, and stdin — which is why it was the
	// tracer. Tool.WorkDir (clone_workdir = true, the only row that declares it)
	// replaced the hand-rolled cmd.Dir, and the module's join into the tools root
	// is gone with it.
	{
		File:    "internal/modules/web/wordlistgen.go",
		Reasons: []Reason{ReasonClonePath},
		Sites:   2,
		Tool:    "getjswords.py",
		Why: "HALF OF THIS FILE WENT HOME IN 18-05 AND HALF DID NOT, so both the " +
			"reason set and the site count shrank rather than the entry being " +
			"deleted. The stdin shape (wordlistgenRoboxtractorRunner) now dispatches " +
			"roboxtractor through backend.Runner; its two sites are gone and with " +
			"them the `stdin` reason. What remains is wordlistgenGetJSWordsRunner, " +
			"which dispatches an interpreter plus a filepath.Join-built script path " +
			"(filepath.Join(app.Cfg.ToolsRoot(), \"getjswords.py\")). " +
			"WHY IT STAYS, ADJUDICATED IN 18-05 RATHER THAN GRANDFATHERED: the " +
			"script sits directly in the tools root with no clone directory and no " +
			"venv, and the interpreter is cfg.Web.JS.GetJSWordsPython, which an " +
			"operator sets at runtime — legacy_aliases.go:490 pins v1's " +
			"GETJSWORDS_VENV to that key, so the migrator actively directs operators " +
			"to it. Discover can only take an interpreter from the MANIFEST, so " +
			"declaring clone coordinates would silently ignore the operator's value: " +
			"a NEW silent divergence, created by the phase that exists to end them. " +
			"FLIP CONDITION: when Discover can resolve an interpreter from the " +
			"loaded config (a clone_interpreter_config_key naming " +
			"web.js.getjswords_python), this row gets clone_dir = \".\" plus " +
			"clone_entry = \"getjswords.py\" and the leg comes home. Note the file " +
			"no longer joins the tools root ITSELF: web.resolveToolsDir is deleted " +
			"and this is Config.ToolsRoot() over paths.tools_dir.",
		HomeBy: "",
	},
	// internal/modules/web/jsa.go went home in 18-05 Task 2 (2 sites). Its
	// clone_path reason was the interpreter-plus-script shape exactly, and
	// 18-02's clone_interpreter + clone_entry supply both: Tool.Path is the venv
	// python3 and Tool.ArgvPrefix is [jsa.py]. Its tools.lock deadline was
	// reconciled in the same change (300 -> 30 — the file enforced 30 per URL and
	// the row would otherwise have raised every per-URL bound tenfold).

	// ---- osint ------------------------------------------------------------------
	// internal/modules/osint/github_repos.go went home in 18-05 Task 3 (2 sites).
	// Its non_recon_binary reason rested on a TRUE premise (git was not a
	// tools.lock entry) and a rationale that did not survive checking: "the
	// registry runs the recon inventory, not the version-control system" is not a
	// boundary this codebase draws — tools.lock already carries seven kind="system"
	// rows (whois, nmap, exiftool, sqlmap, massdns, testssl.sh, axiom-scan), every
	// one a base system dependency. And this git is not infrastructure: it fetches
	// UNTRUSTED third-party repositories at enumerepo-derived URLs, mitigated only
	// by `-c protocol.ext.allow=never` and GIT_TERMINAL_PROMPT=0 — which no
	// artefact of a run could show had been applied. git is now a registered
	// kind="system" row (critical=false, timeout_seconds=300) and the argv is in
	// logs/tools.jsonl. The INSTALLER's own git dispatch stays a declared
	// installer_toolchain bypass; the two are different trust boundaries.

	// ---- installer --------------------------------------------------------------
	// Declared PER FILE, not as the old "internal/installer/" directory prefix: a
	// prefix entry cannot carry an exact site count, and an exact count is what
	// makes a newly-added dispatch a failing diff.
	{
		File:    "internal/installer/installer.go",
		Reasons: []Reason{ReasonInstallerToolchain},
		Sites:   2,
		Tool:    "go/uv/apt-get/brew/pacman/cargo/tar (runCmd, runCmdDir)",
		Why: "The installer runs package managers and the SHA-256-verified toolchain " +
			"bootstrap. None of these are registered recon tools — the registry exists " +
			"to run tools.lock, not to install it. This reason does not expire.",
		HomeBy: "",
	},
	{
		File:    "internal/installer/probe.go",
		Reasons: []Reason{ReasonInstallerToolchain},
		Sites:   1,
		Tool:    "version probes (go version -m, uv tool list)",
		Why: "Version probes for the install inventory, same boundary as " +
			"installer.go. Does not expire.",
		HomeBy: "",
	},
}
