// ensure.go — boot-time resolver acquisition (v1 parity).
//
// v1 acquires its resolver lists at SCAN TIME: modules/axiom.sh:resolvers_update
// downloads (or dnsvalidator-generates) into ${tools}/resolvers*.txt whenever the
// files are absent or older than a day, and reconftw.cfg:408-409 guarantee the
// paths are never empty. v2 shipped the download code (RunGenResolvers) but wired
// it only to the explicit `reconftw gen-resolvers` subcommand, so a default run
// with no reconftw.toml reached puredns with `-r "" -rt ""` and died in the only
// fail-fast stage group. EnsureResolvers closes that gap.
//
// Freshness, not unconditional download: a run only fetches when a file is
// missing, empty, or older than cache.max_age_days_resolvers (or when
// cache.refresh forces it). The steady state is two os.Stat calls.

package resolvers

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/six2dez/reconftw/internal/core/config"
)

// defaultResolverMaxAgeDays mirrors v1's `find -mtime +1` staleness window when
// cache.max_age_days_resolvers is left at 0 (meaning "unset", not "always stale").
const defaultResolverMaxAgeDays = 7

// ResolverStatus reports what EnsureResolvers found or did, for logging and for
// the caller's decision to abort.
type ResolverStatus struct {
	// Path / TrustedPath are the files that were checked.
	Path        string
	TrustedPath string
	// Usable is true when Path exists with at least one non-empty line. It is the
	// only field a caller needs to decide whether a DNS-resolving run can proceed.
	Usable bool
	// TrustedUsable is the same check for the trusted list.
	TrustedUsable bool
	// Refreshed is true when this call actually fetched something.
	Refreshed bool
}

// EnsureResolvers makes cfg.Paths.Resolvers / cfg.Paths.ResolversTrusted usable,
// downloading them when they are absent or stale.
//
// It is BEST-EFFORT by contract: a network failure returns an error alongside a
// ResolverStatus describing what is on disk, and the caller decides whether that
// is fatal. Runs that do not resolve DNS (osint, web, vulns) must not be blocked
// by an unreachable resolver mirror; runs that do resolve DNS must not proceed
// silently without one. Both policies are expressible from the returned status.
//
// The returned error is never nil-but-unusable and never non-nil-but-usable:
// err == nil implies status.Usable.
func EnsureResolvers(ctx context.Context, cfg *config.Config, log *slog.Logger) (ResolverStatus, error) {
	st := ResolverStatus{}
	if cfg == nil {
		return st, fmt.Errorf("resolvers: nil config")
	}
	st.Path = cfg.Paths.Resolvers
	st.TrustedPath = cfg.Paths.ResolversTrusted

	if st.Path == "" {
		// config.Load fills this from the XDG state dir; empty here means neither
		// XDG_CONFIG_HOME nor a home directory was resolvable.
		return st, fmt.Errorf("resolvers: no resolver file path — set paths.resolvers in reconftw.toml, " +
			"or export XDG_CONFIG_HOME/HOME so the default ~/.config/reconftw/resolvers.txt can be used")
	}

	maxAge := cfg.Cache.MaxAgeDaysResolvers
	if maxAge <= 0 {
		maxAge = defaultResolverMaxAgeDays
	}

	needMain := !fileFresh(st.Path, maxAge) || cfg.Cache.Refresh
	needTrusted := st.TrustedPath != "" && (!fileFresh(st.TrustedPath, maxAge) || cfg.Cache.Refresh)

	if !needMain && !needTrusted {
		st.Usable = fileUsable(st.Path)
		st.TrustedUsable = fileUsable(st.TrustedPath)
		return st, usabilityError(st)
	}

	// update_resolvers=false is an explicit operator opt-out of the refresh, exactly
	// as in v1 — but it is an opt-out of REFRESHING a list, not a licence to run with
	// no list at all. When nothing is on disk we still fetch, because the alternative
	// is the silent `-r ""` failure this whole file exists to prevent.
	dnsResolve := cfg.Subdomains.DNSResolve
	haveSomething := fileUsable(st.Path)
	if !dnsResolve.UpdateResolvers && !dnsResolve.GenerateResolvers && haveSomething {
		st.Usable = true
		st.TrustedUsable = fileUsable(st.TrustedPath)
		if log != nil {
			log.Debug("resolvers: stale but update_resolvers=false — keeping existing list", "path", st.Path)
		}
		return st, nil
	}

	if log != nil {
		log.Info("resolvers: acquiring DNS resolver list",
			"path", st.Path,
			"reason", acquireReason(haveSomething, cfg.Cache.Refresh),
			"generate", dnsResolve.GenerateResolvers,
		)
	}

	// v1 parity: dnsvalidator is used ONLY when generate_resolvers=true
	// (reconftw.cfg:24). RunGenResolvers prefers dnsvalidator whenever it is on
	// PATH, which is right for the explicit `gen-resolvers` subcommand but would
	// turn every default scan boot into a ~10-minute validation sweep. So the
	// non-generate path downloads directly.
	var acqErr error
	if dnsResolve.GenerateResolvers {
		acqErr = RunGenResolvers(ctx, cfg)
	} else {
		acqErr = downloadResolverLists(ctx, cfg, needMain, needTrusted, log)
	}

	st.Usable = fileUsable(st.Path)
	st.TrustedUsable = fileUsable(st.TrustedPath)
	st.Refreshed = acqErr == nil

	if acqErr != nil {
		if st.Usable {
			// A stale-but-present list beats aborting the scan.
			if log != nil {
				log.Warn("resolvers: refresh failed — continuing with the existing list",
					"path", st.Path, "err", acqErr.Error())
			}
			return st, nil
		}
		return st, fmt.Errorf("resolvers: could not obtain a DNS resolver list at %s: %w "+
			"(fix: run `reconftw gen-resolvers`, or set paths.resolvers in reconftw.toml to an existing list)",
			st.Path, acqErr)
	}

	return st, usabilityError(st)
}

// downloadResolverLists fetches the public and trusted lists over HTTPS, writing
// each only when that list actually needs it.
func downloadResolverLists(ctx context.Context, cfg *config.Config, needMain, needTrusted bool, log *slog.Logger) error {
	if needMain {
		url := cfg.Paths.ResolversDownload.URL
		if url == "" {
			url = fallbackResolversURL
		}
		if err := os.MkdirAll(filepath.Dir(cfg.Paths.Resolvers), 0o755); err != nil {
			return fmt.Errorf("create resolver dir: %w", err)
		}
		if err := httpDownload(ctx, url, cfg.Paths.Resolvers); err != nil {
			return err
		}
	}

	if needTrusted {
		url := cfg.Paths.ResolversDownload.TrustedURL
		if url == "" {
			url = fallbackTrustedResolversURL
		}
		if err := os.MkdirAll(filepath.Dir(cfg.Paths.ResolversTrusted), 0o755); err != nil {
			// Non-fatal: puredns runs without -rt, dnsx falls back to system resolvers.
			if log != nil {
				log.Warn("resolvers: create trusted resolver dir failed (non-fatal)", "err", err.Error())
			}
			return nil
		}
		if err := httpDownload(ctx, url, cfg.Paths.ResolversTrusted); err != nil {
			if log != nil {
				log.Warn("resolvers: trusted list download failed (non-fatal)", "err", err.Error())
			}
		}
	}
	return nil
}

// usabilityError converts a status into the error contract documented on
// EnsureResolvers: err == nil implies st.Usable.
func usabilityError(st ResolverStatus) error {
	if st.Usable {
		return nil
	}
	return fmt.Errorf("resolvers: %s is missing or empty "+
		"(fix: run `reconftw gen-resolvers`, or set paths.resolvers in reconftw.toml to an existing list)", st.Path)
}

func acquireReason(haveSomething, forced bool) string {
	switch {
	case !haveSomething:
		return "absent"
	case forced:
		return "cache.refresh"
	default:
		return "stale"
	}
}

// fileUsable reports whether path names an existing regular file with content.
// Size, not line count: the per-line count is the resolvers.health gate's job.
func fileUsable(path string) bool {
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Size() > 0
}

// fileFresh reports whether path is usable AND younger than maxAgeDays.
func fileFresh(path string, maxAgeDays int) bool {
	if !fileUsable(path) {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < time.Duration(maxAgeDays)*24*time.Hour
}
