// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for pipelock-replay-capture, the capture rig
// for the Playground "Replay Audit Packet gallery".
//
// It drives controlled SYNTHETIC attack scenarios through a real Pipelock
// proxy/scanner/receipt-emitter in an isolated lab, captures the signed receipt
// chains, and assembles a gallery of public-safe Audit Packets (sdk/audit-packet
// v0) plus UI replay manifests. Every published packet verifies with the shipped
// `pipelock-verifier audit-packet` against the run's lab public key.
//
// The rig is deliberately separate from the `pipelock` firewall binary: it is a
// marketing/evidence-publishing tool, not part of the production proxy.
//
// Public-safe by construction: receipts are redacted before signing, the packet
// envelope is built from safe constants only, a fail-closed field allowlist
// gates every receipt, and an artifact linter sweeps every published byte. Any
// violation aborts the whole run; treat output as publishable only after a
// successful exit.
//
//	generate --out DIR    Capture every default scenario and write the gallery.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/replaycapture"
)

const exitError = 1

// opsecEnvVar names the env var pointing at an operator-private OPSEC marker
// file (one substring per line). Kept out of the repo by design.
const opsecEnvVar = "PIPELOCK_REPLAY_OPSEC_FILE"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(exitError)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "pipelock-replay-capture",
		Short: "Capture synthetic attack scenarios into public-safe signed Audit Packets",
		Long: `pipelock-replay-capture drives controlled synthetic attack scenarios through a
real Pipelock proxy and publishes a gallery of signed Audit Packets plus replay
manifests. Every input is synthetic; every artifact is public-safe by
construction and verifies with pipelock-verifier audit-packet.`,
		SilenceUsage:  true,
		SilenceErrors: false,
		Version:       cliutil.Version,
	}
	root.AddCommand(newGenerateCmd())
	return root
}

func newGenerateCmd() *cobra.Command {
	var (
		outDir  string
		version string
	)
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Capture all default scenarios and write the replay gallery",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if outDir == "" {
				return fmt.Errorf("--out is required")
			}
			if version == "" {
				version = cliutil.Version
			}
			return runGenerate(cmd, outDir, version)
		},
	}
	cmd.Flags().StringVar(&outDir, "out", "", "output directory for the gallery (required)")
	cmd.Flags().StringVar(&version, "version", "", "pipelock version stamp for manifests (default: build version)")
	return cmd
}

func runGenerate(cmd *cobra.Command, outDir, version string) error {
	// Per-scenario evidence scratch lives in a temp dir, NOT inside the gallery,
	// so the published output contains only packet directories and index files.
	work, err := os.MkdirTemp("", "pipelock-replay-capture-*")
	if err != nil {
		return fmt.Errorf("work dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(work) }()

	eng, err := replaycapture.NewEngine(work)
	if err != nil {
		return fmt.Errorf("engine: %w", err)
	}

	// Operator-specific OPSEC markers load from a private file out of the repo.
	markers, err := replaycapture.LoadSupplementalMarkers(os.Getenv(opsecEnvVar))
	if err != nil {
		return fmt.Errorf("opsec markers: %w", err)
	}
	eng.SetOpsecMarkers(markers)

	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Capturing %d scenarios through a real Pipelock proxy...\n", len(replaycapture.DefaultScenarios()))

	res, err := eng.Generate(replaycapture.DefaultScenarios(), outDir, version, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("generate: %w", err)
	}

	_, _ = fmt.Fprintf(out, "\nGallery written to %s\n", res.OutDir)
	_, _ = fmt.Fprintf(out, "Lab signer public key: %s\n", res.SignerKeyHex)
	_, _ = fmt.Fprintf(out, "\n%d packets (each verifies independently):\n", len(res.Packets))
	for _, p := range res.Packets {
		_, _ = fmt.Fprintf(out, "  - %-38s %d receipt(s)\n", p.Scenario.ID, p.Receipts)
	}
	_, _ = fmt.Fprintf(out, "\nVerify any packet from a clean machine:\n")
	_, _ = fmt.Fprintf(out, "  pipelock-verifier audit-packet %s/<scenario> --key %s\n", res.OutDir, res.SignerKeyHex)
	return nil
}
