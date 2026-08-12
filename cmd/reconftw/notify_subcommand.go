// notify_subcommand.go — reconftw notify --test
//
// Tests notification channel reachability by sending a test message to each
// configured channel (Slack, Telegram, Discord) and reporting per-channel
// pass/fail.
//
// Unlike scan-time notifications (which are best-effort per D-07 and always
// return nil), notify --test calls the private send() method on each notifier
// directly and DOES propagate errors — exiting non-zero if any channel fails.
//
// This is the explicit reachability path (D-07 exception) per 10-02-PLAN.md.
//
// NOTIF-01: webhook URLs and bot tokens are log.Secret-typed at the config
// boundary; this file receives plain strings from cfg. The test message is
// safe to display but the credentials themselves never appear in output.
//
// Analog: cmd/reconftw/stateful_subcommands.go runGenResolversCmd (standalone
// subcommand — no pipeline, just config load + one action).

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/notifier"
)

// newNotifyCmd returns the "notify" subcommand.
func newNotifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "notify",
		Short: "Test notification channel reachability",
		Long: `Send a test message to each configured notification channel (Slack, Telegram,
Discord) and report per-channel pass/fail. Exits non-zero if any channel fails.

Unlike scan-time notifications (which are best-effort per D-07), notify --test
DOES propagate failures and exits non-zero — use it to validate channels before
relying on them during a scan.

Requires at least one notification channel configured in reconftw.toml with
notifications.enabled = true.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runNotifyTestCmd(cmd)
		},
	}
	cmd.Flags().Bool("test", false, "Send a test message to all configured notification channels")
	return cmd
}

// runNotifyTestCmd loads config, iterates configured channels, calls the
// private send() method on each, and prints per-channel OK/FAIL.
// Returns a non-zero error if any channel failed (Pitfall 8).
func runNotifyTestCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	efs := parseEarlyFlags(os.Args[1:])
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("notify --test: config load: %w", err)
	}

	if !cfg.Notifications.Enabled {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "notify --test: notifications.enabled = false — no channels configured")
		return nil
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	testMsg := "[reconftw] notify --test: reachability check"

	var anyConfigured bool
	var failCount int

	// Slack
	if wh := string(cfg.Notifications.Slack.WebhookURL); wh != "" {
		anyConfigured = true
		s := notifier.NewSlack(nil, httpClient, wh)
		if sendErr := s.Send(ctx, testMsg); sendErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  slack:     FAIL — %v\n", sendErr)
			failCount++
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  slack:     OK")
		}
	}

	// Telegram
	if tok := string(cfg.Notifications.Telegram.BotToken); tok != "" {
		anyConfigured = true
		tg := notifier.NewTelegram(nil, httpClient, tok, cfg.Notifications.Telegram.ChatID)
		if sendErr := tg.Send(ctx, testMsg); sendErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  telegram:  FAIL — %v\n", sendErr)
			failCount++
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  telegram:  OK")
		}
	}

	// Discord
	if wh := string(cfg.Notifications.Discord.WebhookURL); wh != "" {
		anyConfigured = true
		d := notifier.NewDiscord(nil, httpClient, wh)
		if sendErr := d.Send(ctx, testMsg); sendErr != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "  discord:   FAIL — %v\n", sendErr)
			failCount++
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "  discord:   OK")
		}
	}

	if !anyConfigured {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "notify --test: no notification channels configured in reconftw.toml")
		return nil
	}

	if failCount > 0 {
		return fmt.Errorf("notify --test: %d channel(s) failed", failCount)
	}
	return nil
}
