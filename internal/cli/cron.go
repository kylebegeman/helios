package cli

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	apps "github.com/kylebegeman/helios/internal/app"
)

func newCron(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cron",
		Short: "Hold a cron workload's scheduled runs for a while, or release the hold.",
	}
	cmd.AddCommand(newCronHold(a), newCronRelease(a))
	return cmd
}

func newCronHold(a *app) *cobra.Command {
	var (
		planOnly      bool
		until, reason string
	)
	cmd := &cobra.Command{
		Use:   "hold <app> <workload>",
		Short: "Skip a cron workload's scheduled runs until a time, at most 14 days ahead, and say why. A run in progress finishes.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if until == "" {
				return errors.New("--until is required: when the hold ends, as an RFC 3339 time such as 2026-10-27T05:00:00Z")
			}
			end, err := time.Parse(time.RFC3339, until)
			if err != nil {
				return fmt.Errorf("--until %q is not an RFC 3339 time such as 2026-10-27T05:00:00Z", until)
			}
			return a.operate(cmd.Context(), apps.CronHoldKind, apps.CronHoldInput{App: args[0], Workload: args[1], Until: end, Reason: reason, By: requester()}, planOnly)
		},
	}
	cmd.Flags().StringVar(&until, "until", "", "when the hold ends, as an RFC 3339 time; required")
	cmd.Flags().StringVar(&reason, "reason", "", "why the workload is held; required")
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}

func newCronRelease(a *app) *cobra.Command {
	var planOnly bool
	cmd := &cobra.Command{
		Use:   "release <app> <workload>",
		Short: "End a cron workload's hold now. It runs again at its next scheduled time, with no catch-up run.",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.operate(cmd.Context(), apps.CronReleaseKind, apps.CronReleaseInput{App: args[0], Workload: args[1], By: requester()}, planOnly)
		},
	}
	a.mutatingFlags(cmd, &planOnly)
	return cmd
}
