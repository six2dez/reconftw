// Phase 10: EventFilter — event-kind gated notification middleware (NOTIF-04).
//
// EventFilter wraps an inner Notifier and gates dispatch by the configured
// set of event kinds (from cfg.Notifications.Events). Callers use
// NotifyEvent (not Notify) for typed event dispatch — EventFilter does NOT
// implement the Notifier interface; it exposes a separate NotifyEvent method
// so that the type system enforces explicit event tagging at call sites.
//
// EventKind constants mirror the validate:"oneof=..." constraint on
// NotificationsConfig.Events in config.go.
//
// Source: 10-02-PLAN.md Task 1 + 10-PATTERNS.md § EventFilter.

package notifier

import "context"

// EventKind identifies the type of event triggering a notification.
// Values mirror NotificationsConfig.Events validation oneof constraint.
type EventKind string

const (
	// EventCriticalFinding fires when a critical-severity finding is discovered.
	EventCriticalFinding EventKind = "on-critical-finding"
	// EventScanComplete fires when a scan cycle completes successfully.
	EventScanComplete EventKind = "on-scan-complete"
	// EventFailure fires when a scan cycle fails or a critical tool errors out.
	EventFailure EventKind = "on-failure"
)

// EventFilter gates notification dispatch by event kind. It does NOT
// implement Notifier — callers use NotifyEvent for typed dispatch.
//
// Wiring: the monitor loop's post-cycle diff step wraps app.Notify with
// this filter to honour the configured event set.
type EventFilter struct {
	inner   Notifier
	allowed map[EventKind]bool
}

// NewEventFilter constructs an EventFilter. events is the slice from
// cfg.Notifications.Events (e.g. ["on-critical-finding", "on-scan-complete"]).
// Unknown event strings are silently ignored (the validate tag on the config
// field rejects them at load time).
func NewEventFilter(inner Notifier, events []string) *EventFilter {
	m := make(map[EventKind]bool, len(events))
	for _, e := range events {
		m[EventKind(e)] = true
	}
	return &EventFilter{inner: inner, allowed: m}
}

// NotifyEvent checks whether kind is in the allowed set before forwarding
// to the inner Notifier. Returns nil immediately if the kind is not allowed.
//
// This is the only dispatch method — EventFilter does not implement Notifier
// (intentional; see package-level comment).
func (f *EventFilter) NotifyEvent(ctx context.Context, kind EventKind, lvl Level, msg string) error {
	if !f.allowed[kind] {
		return nil
	}
	return f.inner.Notify(ctx, lvl, msg)
}
