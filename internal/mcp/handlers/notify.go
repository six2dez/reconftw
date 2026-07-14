// Package handlers — in-scan notification seam (INTEG-02).
//
// These helpers emit notifier events from the shared scan finalization path so
// Slack/Telegram/Discord fire during ordinary recon/all/web/vulns/osint runs —
// not only under the monitor loop. They reuse INTEG-01's persistScanToStore
// finalization point and the ingest.Result it produces:
//
//   - notifyScanStart    — on-scan-start (soft) at the top of each RunXAsync
//   - notifyScanComplete — on-scan-complete (soft, with ingest counts) plus one
//     on-critical-finding per severity>=high finding read
//     from <workDir>/artefacts/findings.jsonl
//   - notifyScanFailure  — on-failure when a pipeline returns a non-nil error
//
// Every helper is BEST-EFFORT (T-12-04-02): a webhook/notifier error is logged
// at warn and swallowed — a notification failure must NEVER abort a scan, exactly
// like persistScanToStore. Dispatch is routed through notifier.EventFilter using
// cfg.Notifications.Events (the same construction the monitor loop uses), so event
// routing + notifications.enabled + soft_enabled are all honored. The monitor loop
// sets RunOptions.SuppressScanNotify so per-cycle composite runs stay silent on
// this seam (INTEG-04 owns monitor notifications; prevents double-alerting every
// critical each cycle).
//
// Message hygiene (T-12-04-01): messages carry only mode/target/counts and a
// finding's title+severity — never raw finding evidence — and pass through the
// same redacted notifier chain (LogSink/DigestCoalescer wrap the redactor) the
// monitor uses.
package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/notifier"
)

// inScanEventFilter returns a routed EventFilter for the current scan, or
// ok=false when in-scan notifications must stay silent. Silent when the app or
// its notifier is unwired, notifications are disabled, or the monitor loop set
// SuppressScanNotify. The EventFilter is built exactly as the monitor's is
// (NewEventFilter(app.Notify, cfg.Notifications.Events)) so routing is identical.
func inScanEventFilter(boot AppBoot, opts RunOptions) (*notifier.EventFilter, bool) {
	if boot.App == nil || boot.App.Notify == nil || boot.App.Cfg == nil {
		return nil, false
	}
	if opts.SuppressScanNotify || !boot.App.Cfg.Notifications.Enabled {
		return nil, false
	}
	return notifier.NewEventFilter(boot.App.Notify, boot.App.Cfg.Notifications.Events), true
}

// softEnabled reports whether soft (informational) events — scan-start and
// scan-complete — are enabled. Criticals and failures ignore this knob.
func softEnabled(boot AppBoot) bool {
	return boot.App != nil && boot.App.Cfg != nil && boot.App.Cfg.Notifications.SoftEnabled
}

// notifyScanStart fires an on-scan-start soft event at the beginning of a scan.
// scan-start is a soft event: it fires only when SoftEnabled (in addition to the
// shared enabled/routed/suppress gating). Best-effort.
func notifyScanStart(ctx context.Context, boot AppBoot, opts RunOptions, mode string) {
	ef, ok := inScanEventFilter(boot, opts)
	if !ok || !softEnabled(boot) {
		return
	}
	msg := fmt.Sprintf("[%s] scan started — target %s", mode, opts.Target)
	if err := ef.NotifyEvent(ctx, notifier.EventScanStart, notifier.LevelInfo, msg); err != nil {
		logNotifyErr(ctx, boot, "on-scan-start", err)
	}
}

// notifyScanComplete fires the end-of-scan notifications from the shared
// persistScanToStore seam:
//
//	(a) a soft on-scan-complete event carrying the ingest.Result counts
//	    (gated by SoftEnabled), and
//	(b) one on-critical-finding event per severity>=high finding read from
//	    <workDir>/artefacts/findings.jsonl — NOT gated by SoftEnabled (a critical
//	    is not a soft event), de-duped by a title+severity content hash within
//	    this call.
//
// Reading the artefact (not the store) avoids the INTEG-01 List*Cursor
// NULL-sentinel gotcha and needs no DB open. Best-effort throughout — a nil
// EventFilter (disabled/suppressed) short-circuits before any I/O.
func notifyScanComplete(ctx context.Context, boot AppBoot, opts RunOptions, mode string, res ingest.Result) {
	ef, ok := inScanEventFilter(boot, opts)
	if !ok {
		return
	}
	if softEnabled(boot) {
		msg := fmt.Sprintf("[%s] scan complete — findings=%d hosts=%d urls=%d",
			mode, res.Findings, res.Hosts, res.URLs)
		if err := ef.NotifyEvent(ctx, notifier.EventScanComplete, notifier.LevelInfo, msg); err != nil {
			logNotifyErr(ctx, boot, "on-scan-complete", err)
		}
	}
	notifyCriticalFindings(ctx, boot, ef, mode)
}

// notifyScanFailure fires an on-failure event when a scan pipeline returns a
// non-nil error. NOT gated by SoftEnabled — only by the shared enabled/routed/
// suppress gating. Best-effort.
func notifyScanFailure(ctx context.Context, boot AppBoot, opts RunOptions, mode string, cause error) {
	if cause == nil {
		return
	}
	ef, ok := inScanEventFilter(boot, opts)
	if !ok {
		return
	}
	msg := fmt.Sprintf("[%s] scan failed: %v", mode, cause)
	if err := ef.NotifyEvent(ctx, notifier.EventFailure, notifier.LevelError, msg); err != nil {
		logNotifyErr(ctx, boot, "on-failure", err)
	}
}

// notifyFindingRecord mirrors the subset of ingest.findingRecord (the union of
// the web/vulns/osint finding shapes) needed to classify severity and build a
// human title. ingest's type is unexported, so this local mirror keeps severity
// parsing identical (same json tags) without importing across the seam.
type notifyFindingRecord struct {
	Severity    string `json:"severity"`
	Type        string `json:"type"`
	TemplateID  string `json:"template_id"`
	MatcherName string `json:"matcher_name"`
	VulnClass   string `json:"vuln_class"`
	Class       string `json:"class"`
	Category    string `json:"category"`
	Source      string `json:"source"`
}

// notifyCriticalFindings reads <workDir>/artefacts/findings.jsonl and fires one
// on-critical-finding event per finding with severity in {high, critical}, de-
// duped by a title+severity content hash within the call. A missing/unreadable
// artefact is silently skipped (best-effort — an absent file just means no
// findings to alert on).
func notifyCriticalFindings(ctx context.Context, boot AppBoot, ef *notifier.EventFilter, mode string) {
	lines, err := readJSONLLines(filepath.Join(boot.WorkDir, "artefacts", "findings.jsonl"))
	if err != nil {
		return
	}
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		var rec notifyFindingRecord
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		sev := normalizeNotifySeverity(rec.Severity)
		if sev != "high" && sev != "critical" {
			continue
		}
		title := firstNonBlank(rec.MatcherName, rec.VulnClass, rec.Category, rec.TemplateID, rec.Type, rec.Class, rec.Source)
		if title == "" {
			title = sev + " finding"
		}
		sum := sha256.Sum256([]byte(title + "|" + sev))
		key := hex.EncodeToString(sum[:16])
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		msg := fmt.Sprintf("%s critical: %s (%s)", mode, title, sev)
		if nerr := ef.NotifyEvent(ctx, notifier.EventCriticalFinding, notifier.LevelWarn, msg); nerr != nil {
			logNotifyErr(ctx, boot, "on-critical-finding", nerr)
		}
	}
}

// normalizeNotifySeverity mirrors ingest.normalizeSeverity so the severity gate
// matches what the store records — unknown/empty coerces to "info".
func normalizeNotifySeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// firstNonBlank returns the first argument that is non-empty after trimming.
func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// logNotifyErr logs a swallowed notifier error at warn. A notifier failure must
// never propagate to the scan (best-effort — mirrors persistScanToStore).
func logNotifyErr(ctx context.Context, boot AppBoot, event string, err error) {
	if boot.App != nil && boot.App.Log != nil {
		boot.App.Log.WarnContext(ctx, "in-scan notification failed (non-fatal)", "event", event, "err", err)
	}
}
