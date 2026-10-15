// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

func newReplayKitsCmd() *cobra.Command {
	var bundlePath string
	f := &archiveReplayFlags{}
	cmd := &cobra.Command{
		Use:   "replay-kits",
		Short: "Build offline kits from an authorized replay without signing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			bundle, err := readBoundedBundle(bundlePath)
			if err != nil {
				return err
			}
			artifacts, err := playground.ExtractRunArtifactsFromBundle(bundle)
			if err != nil {
				return fmt.Errorf("read replay artifacts: %w", err)
			}
			report, err := playground.VerifyArchivedReplayArtifacts(artifacts, playground.PublishedOrchestratorPubKeyHex)
			if err != nil {
				return fmt.Errorf("verify replay archive: %w", err)
			}
			if !report.OK {
				return fmt.Errorf("replay archive refused: %s", report.FailureSummary())
			}
			kits, err := buildArchiveVerifyKits(f, bundle)
			if err != nil {
				return err
			}
			if err := publishArchiveKitDirectory(f.kitOutputDir, kits); err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "replay archive verified; wrote Linux, macOS, and Windows kits")
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&bundlePath, "bundle", "", "existing root-authorized replay bundle")
	flags.StringVar(&f.kitOutputDir, "output-dir", "", "new directory for all three verification kits")
	flags.StringVar(&f.linuxVerifier, "linux-verifier", "", "Linux verifier binary")
	flags.StringVar(&f.macOSVerifier, "macos-verifier", "", "macOS universal verifier binary")
	flags.StringVar(&f.windowsVerifier, "windows-verifier", "", "Windows verifier binary")
	for _, name := range []string{"bundle", "output-dir", "linux-verifier", "macos-verifier", "windows-verifier"} {
		_ = cmd.MarkFlagRequired(name)
	}
	return cmd
}

// readBoundedBundle reads at most playground.MaxBundleFileBytes, so an oversized
// bundle is refused before it is held in memory.
func readBoundedBundle(path string) ([]byte, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read replay bundle: %w", err)
	}
	defer func() { _ = file.Close() }()
	bundle, err := io.ReadAll(io.LimitReader(file, playground.MaxBundleFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read replay bundle: %w", err)
	}
	if len(bundle) > playground.MaxBundleFileBytes {
		return nil, fmt.Errorf("replay bundle exceeds %d bytes", playground.MaxBundleFileBytes)
	}
	return bundle, nil
}
