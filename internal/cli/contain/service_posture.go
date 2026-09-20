// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

const servicePostureLauncher = "systemd-service-prestart:" + defaultLaunchScript

type servicePostureCommandEnv struct {
	supported func() bool
	root      func() bool
	run       func(*cobra.Command, containRunOptions, []string) error
}

// servicePostureCmd is invoked from an ExecStartPre=! line. systemd elevates
// only its credentials while retaining the unit's namespace restrictions; the
// command then verifies that live namespace before signing anything.
func servicePostureCmd() *cobra.Command {
	return servicePostureCmdWithEnv(servicePostureCommandEnv{
		supported: containRunSupported,
		root:      isRoot,
		run:       runDefaultServicePosture,
	})
}

func runDefaultServicePosture(cmd *cobra.Command, opts containRunOptions, args []string) error {
	env := defaultContainRunEnv()
	env.probe.port = opts.port
	return runContainRun(cmd.Context(), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), env, opts, args)
}

func servicePostureCmdWithEnv(commandEnv servicePostureCommandEnv) *cobra.Command {
	opts := containRunOptions{
		configFile:            defaultContainConfigPath,
		port:                  defaultProxyPort,
		postureOutput:         defaultContainPostureDir,
		servicePrestart:       true,
		workspaceDiffCapBytes: defaultWorkspaceDiffCapBytes,
	}
	cmd := &cobra.Command{
		Use:           "service-posture [flags] -- <tool> [args...]",
		Short:         "Sign posture for an unprivileged contained service launch",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("usage: pipelock contain service-posture -- <tool> [args...]")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validatePort(opts.port); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			if !commandEnv.supported() {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain service-posture is supported only on Linux"))
			}
			if !commandEnv.root() {
				return cliutil.ExitCodeError(cliutil.ExitConfig, errors.New("contain service-posture must run as root through the systemd credential-only privilege prefix"))
			}
			return commandEnv.run(cmd, opts, args)
		},
	}
	cmd.Flags().StringVarP(&opts.configFile, "config", "c", opts.configFile, "pipelock config file for the signed posture capsule")
	cmd.Flags().IntVar(&opts.port, "port", opts.port, "pipelock listen port to probe on loopback")
	cmd.Flags().StringVar(&opts.postureOutput, "posture-output", opts.postureOutput, "directory for the signed service posture capsule")
	return cmd
}

// verifyAgentCannotReadSigningKey checks the real access decision under the
// managed agent's credentials. Mode bits alone miss named ACLs; a successful
// read probe means the subject could forge its own containment evidence.
func verifyAgentCannotReadSigningKey(ctx context.Context, env *probeEnv, cfg *config.Config) error {
	if env == nil || env.runCmd == nil {
		return errors.New("signing-key isolation probe is unavailable")
	}
	keyPath := filepath.Clean(cfg.FlightRecorder.SigningKeyPath)
	if cfg.FlightRecorder.SigningKeyPath == "" || keyPath == "." {
		return errors.New("flight_recorder.signing_key_path is required for service posture")
	}
	out, code, err := env.runCmd(ctx, "sudo", "-n", "-u", env.agentUserName, "--", "test", "-r", keyPath)
	if err != nil {
		return fmt.Errorf("check signing-key isolation: %w", err)
	}
	switch code {
	case 0:
		return fmt.Errorf("refusing to sign: %s can read flight_recorder.signing_key_path and could forge its own containment evidence", env.agentUserName)
	case 1:
		return nil
	default:
		return fmt.Errorf("check whether %s can read flight_recorder.signing_key_path: sudo exit %d: %s", env.agentUserName, code, oneLine(out))
	}
}
