// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/rules"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// ErrURLBlocked is returned when pipelock check --url detects a blocked URL.
var ErrURLBlocked = errors.New("url blocked")

func CheckCmd() *cobra.Command {
	var configFile string
	var scanURL string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate config or scan a URL",
		Long: `Validate a Pipelock config file and optionally scan a URL to test scanner behavior.

Examples:
  pipelock check --config pipelock.yaml
  pipelock check --config pipelock.yaml --url https://example.com
  pipelock check --url https://pastebin.com/raw/abc123`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load and validate config
			var cfg *config.Config
			if configFile != "" {
				var err error
				cfg, err = config.Load(configFile)
				if err != nil {
					cmd.PrintErrf("Config validation FAILED: %v\n", err)
					return err
				}
				cmd.Println("Config validation: OK")
				cmd.Printf("  Mode:           %s\n", cfg.Mode)
				cmd.Printf("  Listen:         %s\n", cfg.FetchProxy.Listen)
				cmd.Printf("  API allowlist:  %d domains\n", len(cfg.APIAllowlist))
				cmd.Printf("  Blocklist:      %d patterns\n", len(cfg.FetchProxy.Monitoring.Blocklist))
				cmd.Printf("  DLP patterns:   %d rules\n", len(cfg.DLP.Patterns))
				cmd.Printf("  Entropy thresh: %.1f bits\n", cfg.FetchProxy.Monitoring.EntropyThreshold)
				cmd.Printf("  Max URL length: %d chars\n", cfg.FetchProxy.Monitoring.MaxURLLength)
			} else {
				cfg = config.Defaults()
				cmd.Println("Using default config (no --config specified)")
			}

			// Surface semantic advisories (same checks as doctor,
			// non-fatal so exit 0 is preserved unless already failing).
			for _, advisory := range checkConfigAdvisories(cfg) {
				cmd.Printf("\n  [ADVISORY] %s\n", advisory)
			}
			if advisory := availableUnconfiguredAdvisory(cfg); advisory != "" {
				cmd.Printf("\n  [INFO] %s\n", advisory)
			}

			// Optionally scan a URL
			if scanURL != "" {
				cmd.Printf("\nScanning URL: %s\n", scanURL)
				bundleResult := rules.MergeIntoConfig(cfg, cliutil.Version)
				for _, e := range bundleResult.Errors {
					cmd.PrintErrf("pipelock: warning: bundle %s: %s\n", e.Name, e.Reason)
				}
				sc := scanner.New(cfg)
				result := sc.Scan(cmd.Context(), scanURL)
				if result.Allowed {
					cmd.Println("  Result:  ALLOWED")
				} else {
					cmd.Println("  Result:  BLOCKED")
					cmd.Printf("  Scanner: %s\n", result.Scanner)
					cmd.Printf("  Reason:  %s\n", result.Reason)
				}
				cmd.Printf("  Score:   %.2f\n", result.Score)

				if !result.Allowed {
					return ErrURLBlocked
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file path to validate")
	cmd.Flags().StringVar(&scanURL, "url", "", "URL to scan through the configured scanners")

	return cmd
}

// checkConfigAdvisories returns non-fatal advisory messages for the loaded
// config. These mirror doctor checks but are surfaced in check so that CI
// running only "pipelock check" still sees semantic inertness warnings.
func checkConfigAdvisories(cfg *config.Config) []string {
	var advisories []string

	// Inert suppress entries (mirrors checkDoctorSuppressEntries).
	for _, check := range checkDoctorConfigSemantics(cfg) {
		if check.Status == doctorStatusWarn && check.Detail != "" {
			advisories = append(advisories, check.Detail)
		}
	}

	// Flight recorder enabled but inert (no dir configured).
	if cfg.FlightRecorder.Enabled && cfg.FlightRecorder.Dir == "" {
		advisories = append(advisories, "flight_recorder is enabled but dir is unset; no receipts will be written")
	}

	if cfg.Conductor.Enabled {
		_, err := license.VerifyFleetWithOptions(fleetVerifyInputsFromConfig(cfg))
		if err != nil {
			advisories = append(advisories,
				"conductor.enabled is true but no license granting the \"fleet\" feature was found; "+
					"the proxy will refuse to start (install an Enterprise license with fleet or set PIPELOCK_LICENSE_KEY)")
		}
	}

	if cfg.Conductor.Enabled && cfg.FlightRecorder.SigningKeyPath != "" {
		advisories = append(advisories, conductorSigningKeyAdvisories(cfg)...)
	}

	return advisories
}

func fleetVerifyInputsFromConfig(cfg *config.Config) license.FleetVerifyInputs {
	return license.FleetVerifyInputs{
		LicenseKey:       cfg.LicenseKey,
		PublicKeyHex:     cfg.LicensePublicKey,
		CRLFile:          cfg.LicenseCRLFile,
		IntermediateFile: cfg.LicenseIntermediateFile,
		IntermediateCert: cfg.LicenseIntermediateCert,
		RequireSet:       true,
		Require:          cfg.LicenseRequireIntermediateResolved,
		MaxAge:           cfg.LicenseCRLMaxAgeResolved,
	}
}

// conductorSigningKeyAdvisories checks for mismatched key IDs and missing key
// files when conductor.enabled is true and flight_recorder.signing_key_path is
// set. Returns zero or more advisory strings.
func conductorSigningKeyAdvisories(cfg *config.Config) []string {
	var out []string
	keyPath := filepath.Clean(cfg.FlightRecorder.SigningKeyPath)
	// Read once: this read's failure is the missing/unreadable-file case, and the
	// same bytes feed the key_id advisory below (no untestable second read).
	data, err := os.ReadFile(keyPath) // #nosec G304 -- path comes from validated config
	if err != nil {
		out = append(out, fmt.Sprintf(
			"flight_recorder.signing_key_path %q cannot be loaded; the proxy will fail to start (required when conductor.enabled): %v",
			cfg.FlightRecorder.SigningKeyPath, err))
		return out
	}
	// Validate the file loads the way the runtime loads it (catches malformed or
	// too-permissive keys that would pass a shape check but fail at startup).
	priv, err := signing.LoadPrivateKeyFile(keyPath)
	if err != nil {
		out = append(out, fmt.Sprintf(
			"flight_recorder.signing_key_path %q is not a usable signing key; the proxy will fail to start (required when conductor.enabled): %v",
			cfg.FlightRecorder.SigningKeyPath, err))
		return out
	}
	for i := range priv {
		priv[i] = 0
	}

	// If the key file is a JSON keypair with a key_id field, check whether
	// conductor.recorder_key_id matches.
	var kf struct {
		KeyID string `json:"key_id"`
	}
	if json.Unmarshal(data, &kf) != nil || kf.KeyID == "" {
		// Raw (non-JSON) key or JSON without key_id — skip silently.
		return out
	}
	if cfg.Conductor.RecorderKeyID != "" && cfg.Conductor.RecorderKeyID != kf.KeyID {
		out = append(out, fmt.Sprintf(
			"conductor.recorder_key_id %q does not match the key_id %q in flight_recorder.signing_key_path; "+
				"omit recorder_key_id to auto-derive from instance_id, or set it to match",
			cfg.Conductor.RecorderKeyID, kf.KeyID))
	}
	return out
}
