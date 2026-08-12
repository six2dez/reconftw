// Phase 10: DigestCoalescer — burst coalescing middleware (D-06).
//
// DigestCoalescer wraps an inner Notifier and buffers Notify calls,
// flushing them as a single digest message. This prevents channel
// flooding when a burst of critical findings arrives simultaneously.
//
// D-06 guarantee: nothing is dropped. When the rate limiter is at
// capacity, re-queued messages are held in the buffer for the next
// flush window.
//
// Implements both Notifier and Flusher:
//   - Notifier: buffers messages, starts a 30-second flush timer
//   - Flusher.FlushNow: forces immediate flush (called at scan-complete
//     and post-cycle in the monitor loop)
//
// Source: 10-02-PLAN.md Task 1 + 10-PATTERNS.md § DigestCoalescer.

package notifier

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// digestConfig is the minimal interface required by NewDigestCoalescer
// to pull configuration. *config.NotificationsConfig satisfies this via
// the concrete type passed from boot.go.
type digestConfig interface{}

// DigestCoalescer buffers Notify calls per-level and flushes them as a
// single summary message. Implements Notifier (drop-in for Multi when
// notifications are enabled) and Flusher.
type DigestCoalescer struct {
	inner       Notifier
	mu          sync.Mutex
	buffers     map[Level][]string
	limiter     *rate.Limiter
	flushWindow time.Duration
	flushTimer  *time.Timer
	target      string // included in the digest header line (empty = omit)
}

// NewDigestCoalescer constructs a DigestCoalescer wrapping inner.
// cfg is accepted as interface{} for forward-compatibility; rate-limit
// defaults to 3 digests/minute (safe default per plan — configurable in
// a follow-on phase when NotificationsConfig gains digest fields).
// target is included in the digest header; pass "" when target is not
// known at construction time (e.g. Boot time).
func NewDigestCoalescer(inner Notifier, cfg digestConfig, target string) *DigestCoalescer {
	_ = cfg // reserved for future per-field extraction
	return &DigestCoalescer{
		inner:       inner,
		buffers:     make(map[Level][]string),
		limiter:     rate.NewLimiter(rate.Every(time.Minute), 3), // 3 digests/min
		flushWindow: 30 * time.Second,
		target:      target,
	}
}

// Notify buffers msg under lvl and starts the flush timer if not already
// running. Always returns nil.
func (d *DigestCoalescer) Notify(ctx context.Context, lvl Level, msg string, attrs ...any) error {
	d.mu.Lock()
	d.buffers[lvl] = append(d.buffers[lvl], msg)
	if d.flushTimer == nil {
		d.flushTimer = time.AfterFunc(d.flushWindow, func() {
			_ = d.FlushNow(context.Background())
		})
	}
	d.mu.Unlock()
	return nil
}

// FlushNow forces an immediate flush, stopping the pending timer if set.
// Satisfies the Flusher interface. Called by Multi.FlushNow (via Flusher
// type assertion) from the monitor loop after each scan cycle.
func (d *DigestCoalescer) FlushNow(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flushTimer != nil {
		d.flushTimer.Stop()
		d.flushTimer = nil
	}
	return d.flushLocked(ctx)
}

// flushLocked collects all buffered messages, checks the rate limiter,
// and either dispatches a digest or re-queues the messages (D-06: nothing
// is dropped). Caller must hold d.mu.
func (d *DigestCoalescer) flushLocked(ctx context.Context) error {
	var all []string
	highest := LevelInfo
	for lvl, msgs := range d.buffers {
		all = append(all, msgs...)
		if lvl > highest {
			highest = lvl
		}
	}
	d.buffers = make(map[Level][]string)

	if len(all) == 0 {
		return nil
	}

	if !d.limiter.Allow() {
		// Rate-limited: re-queue under highest level so messages are not
		// dropped (D-06 guarantee).
		d.buffers[highest] = append(d.buffers[highest], all...)
		return nil
	}

	summary := formatDigest(d.target, all)
	return d.inner.Notify(ctx, highest, summary)
}

// formatDigest produces a single summary line:
// "[reconftw] target.com — 12 new items: 1. <first> / 2. <second> / … +N more — see reports/hotlist.json"
// When target is empty, the target header is omitted.
func formatDigest(target string, msgs []string) string {
	const maxShow = 3

	var header string
	if target != "" {
		header = fmt.Sprintf("[reconftw] %s — %d new items", target, len(msgs))
	} else {
		header = fmt.Sprintf("[reconftw] %d new items", len(msgs))
	}

	show := msgs
	extra := 0
	if len(msgs) > maxShow {
		show = msgs[:maxShow]
		extra = len(msgs) - maxShow
	}

	parts := make([]string, 0, len(show))
	for i, m := range show {
		parts = append(parts, fmt.Sprintf("%d. %s", i+1, m))
	}
	body := strings.Join(parts, " / ")

	if extra > 0 {
		body += fmt.Sprintf(" / +%d more", extra)
	}

	return header + ": " + body + " — see reports/hotlist.json"
}

var (
	_ Notifier = (*DigestCoalescer)(nil)
	_ Flusher  = (*DigestCoalescer)(nil)
)
