package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kylebegeman/helios/internal/state"
	"github.com/kylebegeman/helios/internal/watch"
)

func newAlerts(a *app) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "What is wrong right now, and what was recently.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			all, err := store.IncidentHistory(ctx, limit)
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(all)
			}
			var open, past []state.Incident
			for _, inc := range all {
				if inc.Open() {
					open = append(open, inc)
				} else {
					past = append(past, inc)
				}
			}
			if len(open) == 0 {
				fmt.Fprintln(a.stdout, "nothing wrong right now")
			}
			for _, inc := range open {
				fmt.Fprintf(a.stdout, "OPEN  %s (%s) since %s: %s\n", inc.Subject, inc.Severity, inc.OpenedAt.Local().Format("2006-01-02 15:04"), inc.Message)
				// Some legs can have told you while another missed it.
				if !inc.NotifiedAt.IsZero() {
					fmt.Fprintf(a.stdout, "      told you at %s\n", inc.NotifiedAt.Local().Format("15:04"))
				}
				if inc.NotifyError != "" {
					fmt.Fprintf(a.stdout, "      NOT DELIVERED: %s\n", inc.NotifyError)
				}
			}
			for _, inc := range past {
				fmt.Fprintf(a.stdout, "past  %s: %s, from %s for %s\n", inc.Subject, inc.Message, inc.OpenedAt.Local().Format("2006-01-02 15:04"), inc.ResolvedAt.Sub(inc.OpenedAt).Round(time.Minute))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many resolved incidents to list; every open incident is included")
	var leg string
	test := &cobra.Command{
		Use:   "test",
		Short: "Send a test alert through each way alerts go out, and say how each did.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			hostname, _ := os.Hostname()
			results, err := watch.SendTestAlerts(cmd.Context(), a.secretsStore(), store, hostname, leg, time.Now().UTC())
			if a.json && results != nil {
				if err := json.NewEncoder(a.stdout).Encode(results); err != nil {
					return err
				}
			}
			for _, r := range results {
				if a.json {
					break
				}
				switch {
				case r.Error != "":
					fmt.Fprintf(a.stdout, "%s: FAILED: %s\n", r.Leg, r.Error)
				case r.Probe:
					fmt.Fprintf(a.stdout, "%s: probe reached %s, which turned it away as it should\n", r.Leg, r.To)
				default:
					fmt.Fprintf(a.stdout, "%s: test alert sent to %s\n", r.Leg, r.To)
				}
			}
			if err != nil {
				return err
			}
			failed := 0
			for _, r := range results {
				if r.Error != "" {
					failed++
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d failed; fix it, then run helios alerts test again", failed, len(results))
			}
			return nil
		},
	}
	test.Flags().StringVar(&leg, "leg", "", "test only this one: email, email2, pushover, ntfy or loom_webhook, which opens a Loom thread")
	cmd.AddCommand(test)
	return cmd
}

func newWatch(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Public URLs this machine checks from the outside, such as the other machine's sites.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			ws, err := store.Watches(cmd.Context())
			if err != nil {
				return err
			}
			if a.json {
				return json.NewEncoder(a.stdout).Encode(ws)
			}
			if len(ws) == 0 {
				fmt.Fprintln(a.stdout, "watching nothing; add a URL with helios watch add https://...")
			}
			for _, w := range ws {
				fmt.Fprintf(a.stdout, "%s (since %s)\n", w.URL, w.AddedAt.Local().Format("2006-01-02"))
			}
			return nil
		},
	}
	add := &cobra.Command{
		Use:   "add <url>",
		Short: "Check a URL every minute and alert when it stops answering 200.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			url := args[0]
			if !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://") {
				return errors.New("the URL must start with https:// or http://")
			}
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.AddWatch(cmd.Context(), url, time.Now().UTC()); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "watching %s\n", url)
			return nil
		},
	}
	remove := &cobra.Command{
		Use:   "remove <url>",
		Short: "Stop checking a URL.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := a.openState()
			if err != nil {
				return err
			}
			defer store.Close()
			if err := store.RemoveWatch(cmd.Context(), args[0]); errors.Is(err, state.ErrNotFound) {
				return fmt.Errorf("%s wasn't being watched", args[0])
			} else if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "no longer watching %s\n", args[0])
			return nil
		},
	}
	cmd.AddCommand(add, remove)
	return cmd
}
