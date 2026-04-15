// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// recoveryChoice enumerates the recoverable outcomes of the interactive
// recover workflow. Also accepted as the --choice flag value so scripts
// can drive the same workflow non-interactively.
type recoveryChoice string

const (
	choiceReleaseNone recoveryChoice = "release-none"
	choiceReleaseSoft recoveryChoice = "release-soft"
	choiceTerminate   recoveryChoice = "terminate"
	choiceLeave       recoveryChoice = "leave"
)

// recoverDispatcher is the seam the interactive wrapper calls to invoke
// downstream subcommands. The real implementation wraps the HTTP client;
// tests substitute a stub that records calls and returns fixed results.
type recoverDispatcher interface {
	Inspect(ctx context.Context, client *Client, key string, out io.Writer) error
	Explain(ctx context.Context, client *Client, key string, out io.Writer) error
	Release(ctx context.Context, client *Client, key, tier string, out io.Writer) error
	Terminate(ctx context.Context, client *Client, key string, out io.Writer) error
}

// httpDispatcher implements recoverDispatcher by calling the live client
// methods and rendering the results through the same helpers the
// non-interactive subcommands use.
type httpDispatcher struct{}

func (httpDispatcher) Inspect(ctx context.Context, client *Client, key string, out io.Writer) error {
	detail, err := client.Inspect(ctx, key)
	if err != nil {
		return err
	}
	return renderDetail(out, detail)
}

func (httpDispatcher) Explain(ctx context.Context, client *Client, key string, out io.Writer) error {
	exp, err := client.Explain(ctx, key)
	if err != nil {
		return err
	}
	return renderExplanation(out, exp)
}

func (httpDispatcher) Release(ctx context.Context, client *Client, key, tier string, out io.Writer) error {
	resp, err := client.Release(ctx, key, tier)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "released %s: %s -> %s\n", resp.Key, resp.PreviousTier, resp.NewTier)
	return nil
}

func (httpDispatcher) Terminate(ctx context.Context, client *Client, key string, out io.Writer) error {
	resp, err := client.Terminate(ctx, key)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "terminated %s: previous_tier=%s level=%s\n", resp.Key, resp.PreviousTier, resp.PreviousLevel)
	return nil
}

// recoverDispatcherFn is the variable tests override to inject a stub.
var recoverDispatcherFn func() recoverDispatcher = func() recoverDispatcher { return httpDispatcher{} }

func recoverCmd(flags *rootFlags) *cobra.Command {
	var choiceFlag string
	cmd := &cobra.Command{
		Use:   "recover <key>",
		Short: "Interactive recovery workflow: inspect, explain, choose action",
		Long: `Interactive recovery helper. Walks the operator through inspect and
explain for the given session, then prompts for an action: release
the session to none, release to soft, terminate, or leave it alone.

Use --choice to script the workflow non-interactively. Accepted
values: release-none, release-soft, terminate, leave.

Examples:
  pipelock session recover "agent|10.0.0.1"
  pipelock session recover "agent|10.0.0.1" --choice release-none`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&choiceFlag, "choice", "", "non-interactive choice (release-none|release-soft|terminate|leave)")

	cmd.RunE = func(c *cobra.Command, args []string) error {
		key := args[0]

		if choiceFlag != "" {
			if err := validateRecoverChoice(choiceFlag); err != nil {
				return cliutil.ExitCodeError(2, err)
			}
		}

		return runClientCmd(flags, c.Context(), c.OutOrStdout(), func(ctx context.Context, client *Client, out io.Writer) error {
			dispatcher := recoverDispatcherFn()

			_, _ = fmt.Fprintln(out, "== inspect ==")
			if err := dispatcher.Inspect(ctx, client, key, out); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(out, "")
			_, _ = fmt.Fprintln(out, "== explain ==")
			if err := dispatcher.Explain(ctx, client, key, out); err != nil {
				return err
			}

			choice := recoveryChoice(choiceFlag)
			if choiceFlag == "" {
				var err error
				choice, err = promptRecoveryChoice(c.InOrStdin(), out)
				if err != nil {
					return cliutil.ExitCodeError(2, err)
				}
			}

			return dispatchRecoveryChoice(ctx, dispatcher, client, key, choice, out)
		})
	}
	return cmd
}

// validateRecoverChoice rejects any raw string that does not map to a
// known recovery action. Returns an error naming the accepted values
// when the input is unrecognized. The canonical choice is constructed
// by the caller via recoveryChoice(raw) after this validation succeeds.
func validateRecoverChoice(raw string) error {
	switch recoveryChoice(raw) {
	case choiceReleaseNone, choiceReleaseSoft, choiceTerminate, choiceLeave:
		return nil
	}
	return errors.New("invalid --choice: must be release-none, release-soft, terminate, or leave")
}

// promptRecoveryChoice reads a numbered selection from in and returns
// the corresponding recoveryChoice. Any input that does not map to one
// of the four choices is treated as an error.
func promptRecoveryChoice(in io.Reader, out io.Writer) (recoveryChoice, error) {
	_, _ = fmt.Fprintln(out, "")
	_, _ = fmt.Fprintln(out, "Choose recovery action:")
	_, _ = fmt.Fprintln(out, "  1) release to none")
	_, _ = fmt.Fprintln(out, "  2) release to soft")
	_, _ = fmt.Fprintln(out, "  3) terminate (destructive)")
	_, _ = fmt.Fprintln(out, "  4) leave as-is")
	_, _ = fmt.Fprint(out, "> ")

	reader := bufio.NewReader(in)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read choice: %w", err)
	}
	line = strings.TrimSpace(line)

	switch line {
	case "1", "release-none":
		return choiceReleaseNone, nil
	case "2", "release-soft":
		return choiceReleaseSoft, nil
	case "3", "terminate":
		return choiceTerminate, nil
	case "4", "leave":
		return choiceLeave, nil
	}
	return "", fmt.Errorf("unrecognized choice %q — must be 1-4 or one of release-none, release-soft, terminate, leave", line)
}

// dispatchRecoveryChoice runs the operation matching the chosen action.
// "leave" is a no-op that confirms the session is unchanged.
func dispatchRecoveryChoice(
	ctx context.Context,
	dispatcher recoverDispatcher,
	client *Client,
	key string,
	choice recoveryChoice,
	out io.Writer,
) error {
	switch choice {
	case choiceReleaseNone:
		return dispatcher.Release(ctx, client, key, "none", out)
	case choiceReleaseSoft:
		return dispatcher.Release(ctx, client, key, "soft", out)
	case choiceTerminate:
		return dispatcher.Terminate(ctx, client, key, out)
	case choiceLeave:
		_, _ = fmt.Fprintf(out, "leaving %s unchanged\n", key)
		return nil
	}
	return fmt.Errorf("unhandled recovery choice %q", choice)
}
