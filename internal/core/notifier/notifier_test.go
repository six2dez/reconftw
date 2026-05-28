// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 2
// behavior tests 6-12 — Notifier interface + LogSink + 3 stubs + Multi
// + XCUT-07 redactor passthrough sentinel.
package notifier_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	corelog "github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/notifier"
)

// helper: build a slog.Logger writing to buf, with the same
// RedactingHandler chain log.New uses. r is the redactor through which
// values registered here are scrubbed.
func loggerWithRedactor(buf *bytes.Buffer) (*slog.Logger, *corelog.Redactor) {
	r := &corelog.Redactor{}
	inner := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	h := corelog.NewRedactingHandler(inner, r)
	return slog.New(h), r
}

// Test 6: Notifier interface — LogSink satisfies.
func TestNotifierInterfaceSatisfied(t *testing.T) {
	var _ notifier.Notifier = (*notifier.LogSink)(nil)
	var _ notifier.Notifier = (*notifier.SlackNotifier)(nil)
	var _ notifier.Notifier = (*notifier.TelegramNotifier)(nil)
	var _ notifier.Notifier = (*notifier.DiscordNotifier)(nil)
	var _ notifier.Notifier = (*notifier.Multi)(nil)
}

// Test 7: LogSink writes at the corresponding slog level.
func TestLogSinkLevels(t *testing.T) {
	buf := &bytes.Buffer{}
	log, _ := loggerWithRedactor(buf)
	sink := notifier.NewLogSink(log)

	if err := sink.Notify(context.Background(), notifier.LevelInfo, "info-msg"); err != nil {
		t.Fatalf("Notify info: %v", err)
	}
	if err := sink.Notify(context.Background(), notifier.LevelWarn, "warn-msg"); err != nil {
		t.Fatalf("Notify warn: %v", err)
	}
	if err := sink.Notify(context.Background(), notifier.LevelError, "err-msg"); err != nil {
		t.Fatalf("Notify error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"msg":"info-msg"`) {
		t.Errorf("info record missing in output: %s", out)
	}
	if !strings.Contains(out, `"level":"WARN"`) {
		t.Errorf("WARN level missing in output: %s", out)
	}
	if !strings.Contains(out, `"level":"ERROR"`) {
		t.Errorf("ERROR level missing in output: %s", out)
	}
}

// Tests 8-10: Slack/Telegram/Discord stubs return nil and log a
// "<service>_notify_stub" event.
func TestStubsReturnNilAndLog(t *testing.T) {
	cases := []struct {
		name     string
		factory  func(*slog.Logger) notifier.Notifier
		wantTag  string
	}{
		{"slack", func(l *slog.Logger) notifier.Notifier { return notifier.NewSlack(l, "https://hooks.slack.com/x/y") }, "slack_notify_stub"},
		{"telegram", func(l *slog.Logger) notifier.Notifier { return notifier.NewTelegram(l, "bot:abc") }, "telegram_notify_stub"},
		{"discord", func(l *slog.Logger) notifier.Notifier { return notifier.NewDiscord(l, "https://discord.com/api/webhooks/x/y") }, "discord_notify_stub"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			log, _ := loggerWithRedactor(buf)
			n := c.factory(log)
			if err := n.Notify(context.Background(), notifier.LevelInfo, "hello"); err != nil {
				t.Fatalf("%s Notify error: %v", c.name, err)
			}
			out := buf.String()
			if !strings.Contains(out, c.wantTag) {
				t.Errorf("%s stub missing tag %q in output: %s", c.name, c.wantTag, out)
			}
		})
	}
}

// Test 11: Multi calls Notify on every wrapped sink and joins errors.
func TestMultiFanOutAndJoinErrors(t *testing.T) {
	buf := &bytes.Buffer{}
	log, _ := loggerWithRedactor(buf)
	good := notifier.NewLogSink(log)
	// stubErrSink errors out — used to test error joining.
	bad := &errSink{err: errors.New("dispatch-failed")}
	m := notifier.NewMulti(good, bad)
	err := m.Notify(context.Background(), notifier.LevelWarn, "broadcast")
	if err == nil {
		t.Fatal("Multi.Notify returned nil with erroring sink")
	}
	if !strings.Contains(err.Error(), "dispatch-failed") {
		t.Errorf("error chain missing dispatch-failed: %v", err)
	}

	// Empty Multi → nil error.
	if err := notifier.NewMulti().Notify(context.Background(), notifier.LevelInfo, "x"); err != nil {
		t.Errorf("empty Multi returned %v; want nil", err)
	}

	// Multi with nil sink mixed in — nil sink is skipped.
	mm := notifier.NewMulti(good, nil, good)
	if err := mm.Notify(context.Background(), notifier.LevelInfo, "ok"); err != nil {
		t.Errorf("Multi with nil sink errored: %v", err)
	}
}

// Test 12 (XCUT-07): Registering a secret with the Redactor and then
// calling LogSink.Notify(...) with the secret in the message produces
// output with the raw value absent.
func TestXCUT07NotifierRedactsRegisteredSecret(t *testing.T) {
	buf := &bytes.Buffer{}
	log, r := loggerWithRedactor(buf)

	secret := "supersecretvalue-1234"
	r.Register(secret)

	sink := notifier.NewLogSink(log)
	if err := sink.Notify(context.Background(), notifier.LevelInfo,
		"leaked: "+secret); err != nil {
		t.Fatalf("Notify error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, secret) {
		t.Errorf("XCUT-07 BREACH — raw secret %q appears in slog output: %s", secret, out)
	}
	if !strings.Contains(out, "***") {
		t.Errorf("expected redaction marker ***; got: %s", out)
	}
}

// Test 12b: XCUT-07 invariant also holds at the Slack/Telegram/Discord
// stub boundary — registered secrets must not appear in the
// "slack_notify_stub" line.
func TestXCUT07StubsRedactRegisteredSecret(t *testing.T) {
	secret := "stubsecret-VALUE9876"
	for _, name := range []string{"slack", "telegram", "discord"} {
		t.Run(name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			log, r := loggerWithRedactor(buf)
			r.Register(secret)
			var s notifier.Notifier
			switch name {
			case "slack":
				s = notifier.NewSlack(log, "https://hooks.slack.com/x")
			case "telegram":
				s = notifier.NewTelegram(log, "bot:abc")
			case "discord":
				s = notifier.NewDiscord(log, "https://discord.com/x")
			}
			if err := s.Notify(context.Background(), notifier.LevelInfo,
				"leaked: "+secret); err != nil {
				t.Fatalf("%s Notify error: %v", name, err)
			}
			out := buf.String()
			if strings.Contains(out, secret) {
				t.Errorf("%s leaked secret: %s", name, out)
			}
		})
	}
}

// errSink is a Notifier that returns its configured error from Notify.
type errSink struct{ err error }

func (e *errSink) Notify(context.Context, notifier.Level, string, ...any) error {
	return e.err
}
