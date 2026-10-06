// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func launchPropertiesCmd() *cobra.Command {
	var agentUser string
	cmd := &cobra.Command{
		Use:    "launch-properties",
		Short:  "Print systemd properties for one contained launch",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLaunchProperties(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), agentUser)
		},
	}
	cmd.Flags().StringVar(&agentUser, "agent-user", defaultAgentUser, "contained agent account")
	return cmd
}

func runLaunchProperties(ctx context.Context, stdout, _ io.Writer, agentUser string) error {
	env := defaultProbeEnv()
	if strings.TrimSpace(agentUser) != "" {
		env.agentUserName = agentUser
	}
	return writeLaunchProperties(ctx, stdout, env)
}

func writeLaunchProperties(ctx context.Context, stdout io.Writer, env *probeEnv) error {
	account, err := env.lookupUser(env.agentUserName)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", env.agentUserName, err)
	}
	home, err := cleanContainedAgentHomeDir(env.agentUserName, account.HomeDir)
	if err != nil {
		return err
	}
	env.agentHome = home
	in, err := filesystemProfileInputForProbe(env, home)
	if err != nil {
		return err
	}
	profile, err := filesystemProfileProperties(in)
	if err != nil {
		return err
	}
	lines, err := enforcedLaunchPropertyLines(ctx, env, in, profile)
	if err != nil {
		return err
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(stdout, line); err != nil {
			return err
		}
	}
	return nil
}

// enforcedLaunchPropertyLines returns the properties the canary already
// accepted. A later rebuild can observe a different filesystem, so enforce
// mode does not call containLaunchPropertyLines again. Off mode still prints
// only the display-socket bind.
func enforcedLaunchPropertyLines(ctx context.Context, env *probeEnv, in filesystemProfileInput, profile filesystemProfile) ([]string, error) {
	env.filesystem = profile
	if profile.Mode == config.ContainmentFilesystemModeEnforce {
		status, detail := probeFilesystemConfinement(ctx, env)
		if status != statusPass {
			return nil, fmt.Errorf("filesystem confinement canary: %s: %s", status, detail)
		}
		return append([]string(nil), profile.Properties...), nil
	}
	return containLaunchPropertyLines(in)
}
