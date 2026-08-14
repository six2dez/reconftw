// SPDX-License-Identifier: MIT
//
// Stream consumption helpers — the terminal-error contract.
//
// Backend.Stream's contract has two independent failure channels and they mean
// very different things. Confusing them is the single most consequential mistake
// a consumer can make, so it is spelled out once here and referenced from both
// helpers:
//
//	ch, err := app.Tools.Stream(ctx, "arjun", args)
//	if err != nil {
//	    // (1) DISPATCH failure: the tool is not registered, is not on PATH, or
//	    //     the process could not be started. The stream NEVER RAN.
//	    //     Best-effort modules return task.StatusSkipped here — see
//	    //     internal/modules/web/arjun.go and internal/core/scheduler/policy.go.
//	    //     Do NOT escalate this to StatusErrored: `subdomains` and `scheduler`
//	    //     are PolicyFailFast, so turning a missing optional tool into an error
//	    //     fails the whole run on any host that did not install it.
//	}
//	if err := backend.Drain(ch); err != nil {
//	    // (2) TERMINAL failure: the tool RAN and ended badly — it exited non-zero
//	    //     or its output was truncated by a scanner overflow. Whatever it wrote
//	    //     to its staging file is partial, and anything already on disk from a
//	    //     previous run is stale. Return task.StatusErrored.
//	}
//
// Before these helpers existed, all 23 stream-consumption loops in
// internal/modules dropped Event.Err on the floor (audit finding F6): a tool
// could emit half its findings, exit 7, and the task was still reported
// successful while the parser read a truncated — or entirely stale — file.
package backend

// Drain reads ch until it is closed, discarding every Line, and returns the
// FIRST non-nil Event.Err it observed (nil when the stream ended cleanly).
//
// Draining to completion is mandatory even after an error is captured: the
// Backend contract (see Backend.Stream) requires the consumer to read until
// close, and abandoning the channel early strands the producer goroutine and the
// context bounding the child process. Drain therefore keeps reading after it has
// latched the first error, and only the first is reported — a stream produces at
// most one terminal event, so a second would indicate a producer bug rather than
// extra information worth surfacing.
//
// POLICY BOUNDARY (read the package header before using this): a non-nil return
// means the tool RAN and ended badly, and the caller should return
// task.StatusErrored. It does NOT mean the tool was missing — that case is the
// error returned by Backend.Stream() itself and keeps its existing
// task.StatusSkipped handling.
//
// A nil channel returns nil immediately rather than blocking forever, so a
// backend that hands back (nil, nil) cannot deadlock its caller.
//
// Drain is the migration target for bare-drain call sites:
//
//	for range ch { //nolint:revive // intentional drain
//	}
//
// becomes:
//
//	if err := backend.Drain(ch); err != nil { ... }
func Drain(ch <-chan Event) error {
	return Collect(ch, nil)
}

// Collect reads ch until it is closed, invoking fn for every event that does NOT
// carry an error, and returns the FIRST non-nil Event.Err it observed (nil when
// the stream ended cleanly). fn may be nil, in which case Collect degrades to a
// pure drain — that is exactly how Drain is implemented.
//
// fn is deliberately NOT invoked for the error-carrying terminal event. That
// event exists only to transport Err; local.go emits it with an empty Line, so
// passing it to a line parser would push an empty record into the finding
// pipeline. Callers that want the error see it in the return value.
//
// Like Drain, Collect keeps reading after latching an error (Backend.Stream
// requires draining to completion) and returns nil immediately for a nil channel.
//
// POLICY BOUNDARY: identical to Drain — a non-nil return means the tool RAN and
// ended badly (non-zero exit or scanner overflow) and the caller should return
// task.StatusErrored; it does NOT mean the tool was missing. The missing-tool
// case is the error returned by Backend.Stream() itself and keeps its existing
// task.StatusSkipped handling.
//
// Collect is the migration target for ev-binding call sites:
//
//	for ev := range ch {
//	    parse(ev.Line)
//	}
//
// becomes:
//
//	if err := backend.Collect(ch, func(ev backend.Event) { parse(ev.Line) }); err != nil { ... }
func Collect(ch <-chan Event, fn func(Event)) error {
	if ch == nil {
		return nil
	}
	var termErr error
	for ev := range ch {
		if ev.Err != nil {
			if termErr == nil {
				termErr = ev.Err
			}
			// Keep draining: the producer is still holding the channel open.
			continue
		}
		if fn != nil {
			fn(ev)
		}
	}
	return termErr
}
