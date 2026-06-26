// alias.go — pre-cobra v1 alias translation (D-08).
//
// translateV1Args rewrites deprecated v1 flag forms into v2 subcommand
// invocations before cobra parses os.Args. Called from run() between
// parseEarlyFlags and rootCmd.ExecuteContext.
//
// Design constraints (from ADR 0002 §8.3 + 09-CONTEXT.md D-08):
//   - Leaves the original mode flag in the rewritten slice so cobra's
//     MarkDeprecated still emits its one-time stderr warning (MODE-09).
//   - If args[0] is already a known v2 subcommand, skip mode-flag injection
//     but still translate -d / -l / -v (Pitfall 4 double-insertion guard).
//   - Global flag rewrites: -d X → --target X, -l X → --list X, -v → --axiom.
//   - On multiple mode flags (e.g. --recon --all), first-wins.

package main

// v1SubcommandFlags maps v1 mode-flag strings (long or short) → v2 subcommand name.
// Used by translateV1Args for the first-pass subcommand injection.
var v1SubcommandFlags = map[string]string{
	"--recon": "recon", "-r": "recon",
	"--all": "all", "-a": "all",
	"--passive": "passive", "-p": "passive",
	"--subdomains": "subs", "-s": "subs",
	"--web": "web", "-w": "web",
	"--vulns": "vulns",
	"--osint": "osint", "-n": "osint",
	"--zen": "zen", "-z": "zen",
	"--deep": "deep", "-y": "deep",
}

// knownSubcmds is the set of all v2 subcommand names. When args[0] already
// matches one of these, translateV1Args skips mode-flag injection (Pitfall 4).
var knownSubcmds = map[string]bool{
	"recon": true, "all": true, "passive": true, "subs": true, "web": true,
	"vulns": true, "osint": true, "zen": true, "deep": true,
	"monitor": true, "report": true, "mcp": true, "migrate": true,
	"install": true, "health-check": true, "version": true,
	"quick-rescan": true, "refresh-cache": true, "gen-resolvers": true,
	// Built-in cobra commands that should never be treated as mode injections.
	"completion": true, "help": true,
}

// translateV1Args rewrites deprecated v1 flag forms into v2 subcommand
// invocations before cobra parses os.Args. Returns a new slice; the input
// slice is not modified.
//
// Translation rules (applied in order):
//  1. If len(args) == 0, return args unchanged.
//  2. Scan for the first non-flag token. If it is already a known subcommand,
//     skip mode-flag injection but still apply global alias rewrites (step 4).
//  3. Scan the full args for the first matching key in v1SubcommandFlags. If
//     found, prepend the v2 subcommand name before all original args. The
//     original flag is left in place so MarkDeprecated fires (MODE-09).
//  4. Global alias rewrites over the result slice:
//     -d X → --target X, -l X → --list X, -v (boolean) → --axiom.
//  5. When multiple mode flags are present, first-wins.
func translateV1Args(args []string) []string {
	if len(args) == 0 {
		return args
	}

	// Step 2: find first non-flag token to detect subcommand-first invocations.
	alreadyHasSubcmd := false
	for _, a := range args {
		if len(a) == 0 || a[0] != '-' {
			if knownSubcmds[a] {
				alreadyHasSubcmd = true
			}
			break
		}
	}

	// Step 3: scan for first v1 mode flag (first-wins on multiple mode flags).
	injectedSubcmd := ""
	if !alreadyHasSubcmd {
		for _, a := range args {
			if sub, ok := v1SubcommandFlags[a]; ok {
				injectedSubcmd = sub
				break
			}
		}
	}

	// Build the working slice. If we found a subcommand to inject, prepend it.
	var out []string
	if injectedSubcmd != "" {
		// Prepend subcommand; original args follow unchanged so MarkDeprecated fires.
		out = make([]string, 0, len(args)+1)
		out = append(out, injectedSubcmd)
		out = append(out, args...)
	} else {
		out = make([]string, len(args))
		copy(out, args)
	}

	// Step 4: global alias rewrites over the working slice.
	// -d X → --target X, -l X → --list X, -v → --axiom
	result := make([]string, 0, len(out))
	for i := 0; i < len(out); i++ {
		a := out[i]
		switch {
		case a == "-d" && i+1 < len(out):
			result = append(result, "--target", out[i+1])
			i++
		case a == "-l" && i+1 < len(out):
			result = append(result, "--list", out[i+1])
			i++
		case a == "-v":
			result = append(result, "--axiom")
		default:
			result = append(result, a)
		}
	}

	return result
}
