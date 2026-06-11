// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// Keep exported recorder public-key sidecars group-readable but not
// world-readable, matching init/contain provisioning. The key is public, but in
// contained installs group-read is the operator/proxy handoff path while agent
// users should not get broad key-directory visibility by default.
const recorderPublicKeyFileMode os.FileMode = 0o640

func pubkeyCmd() *cobra.Command {
	var keyFile string
	var configFile string
	var outPath string

	cmd := &cobra.Command{
		Use:   "pubkey",
		Short: "Export the flight-recorder signing public key",
		Long: `Prints the 64-hex Ed25519 public key for the flight-recorder
signing key. Use --key-file to read a private key directly, or --config to
derive the private key path from flight_recorder.signing_key_path. Without
either flag, the command uses standard config discovery.

Examples:
  pipelock signing pubkey --config /etc/pipelock/pipelock.yaml
  pipelock signing pubkey --key-file /etc/pipelock/keys/flight-recorder-signing.key
  pipelock signing pubkey --config /etc/pipelock/pipelock.yaml --out /etc/pipelock/keys/flight-recorder-signing.key.pub`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keyPath, err := resolveRecorderSigningKeyPath(keyFile, configFile)
			if err != nil {
				return err
			}
			pubHex, err := deriveRecorderPublicKeyHexFromPrivateFile(keyPath)
			if err != nil {
				return err
			}
			if outPath != "" {
				if err := writeRecorderPublicKeyHex(outPath, pubHex); err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), pubHex)
			return nil
		},
	}

	cmd.Flags().StringVar(&keyFile, "key-file", "", "private flight-recorder signing key file")
	cmd.Flags().StringVar(&configFile, "config", "", "pipelock config file with flight_recorder.signing_key_path")
	cmd.Flags().StringVar(&outPath, "out", "", "write the public key hex to this file with 0640 permissions")
	cmd.MarkFlagsMutuallyExclusive("key-file", "config")
	return cmd
}

func resolveRecorderSigningKeyPath(keyFile, configFile string) (string, error) {
	// Defensive guard for non-Cobra call sites; pubkeyCmd also declares these
	// flags mutually exclusive with cmd.MarkFlagsMutuallyExclusive.
	if keyFile != "" && configFile != "" {
		return "", fmt.Errorf("pass either --key-file or --config, not both")
	}
	if keyFile != "" {
		return filepath.Clean(keyFile), nil
	}
	if configFile == "" {
		configFile = cliutil.DiscoverConfigPath()
		if configFile == "" {
			return "", fmt.Errorf("no pipelock config found: pass --key-file or --config")
		}
	}
	cfg, err := config.Load(filepath.Clean(configFile))
	if err != nil {
		return "", fmt.Errorf("loading config %q: %w", configFile, err)
	}
	keyPath := strings.TrimSpace(cfg.FlightRecorder.SigningKeyPath)
	if keyPath == "" {
		return "", fmt.Errorf("config %q has no flight_recorder.signing_key_path", configFile)
	}
	return filepath.Clean(keyPath), nil
}

func deriveRecorderPublicKeyHexFromPrivateFile(keyPath string) (string, error) {
	cleanPath := filepath.Clean(keyPath)
	priv, err := domsigning.LoadPrivateKeyFile(cleanPath)
	if err != nil {
		if fileContainsPublicKey(cleanPath) {
			return "", fmt.Errorf("--key-file %s contains a public key; pass the private flight-recorder signing key file instead", cleanPath)
		}
		return "", fmt.Errorf("load private signing key %s: %w", cleanPath, err)
	}
	pubHex, err := domsigning.PublicKeyHexFromPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("derive public key: %w", err)
	}
	return pubHex, nil
}

func fileContainsPublicKey(path string) bool {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return false
	}
	_, err = domsigning.ParsePublicKey(string(raw))
	return err == nil
}

func writeRecorderPublicKeyHex(outPath, pubHex string) error {
	cleanPath := filepath.Clean(outPath)
	if _, err := domsigning.ParsePublicKey(pubHex); err != nil {
		return fmt.Errorf("invalid derived public key: %w", err)
	}
	if err := atomicfile.Write(cleanPath, []byte(pubHex+"\n"), recorderPublicKeyFileMode); err != nil {
		return fmt.Errorf("write public key %s: %w", cleanPath, err)
	}
	return nil
}
