// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

// Capsule format version.
const capsuleVersion = "1.0"

// Default capsule expiration (30 days).
const defaultExpiry = 720 * time.Hour

// File names for capsule outputs.
const (
	capsuleFileJSON = "proof.json"
	capsuleFileMD   = "proof.md"
	capsuleFileSVG  = "proof.svg"
)

// configHashDefaults is used when no config file is provided.
const configHashDefaults = "defaults"

// Badge color constants keyed by grade letter.
const (
	badgeColorGreen       = "#4c1"
	badgeColorYellowGreen = "#97ca00"
	badgeColorYellow      = "#dfb317"
	badgeColorOrange      = "#fe7d37"
	badgeColorRed         = "#e05d44"
)

// PostureCapsule is the proof artifact produced by `pipelock audit capsule`.
type PostureCapsule struct {
	Version     string       `json:"version"`
	GeneratedAt time.Time    `json:"generated_at"`
	ExpiresAt   time.Time    `json:"expires_at"`
	Score       *ScoreResult `json:"score"`
	ConfigHash  string       `json:"config_hash"`
	PipelockVer string       `json:"pipelock_version"`
}

func auditCapsuleCmd() *cobra.Command {
	var (
		configFile string
		outputDir  string
		formats    string
		expires    time.Duration
		ciGate     int
		jsonOutput bool
	)

	cmd := &cobra.Command{
		Use:   "capsule",
		Short: "Generate posture proof artifacts from a config score",
		Long: `Score a pipelock configuration and produce proof artifacts:
proof.json (machine-readable), proof.md (human-readable), proof.svg (badge).

These artifacts can be committed to repos, embedded in CI, or shared with auditors.

Examples:
  pipelock audit capsule --config pipelock.yaml
  pipelock audit capsule --config pipelock.yaml --json
  pipelock audit capsule --ci-gate 80
  pipelock audit capsule --format json,svg -o ./proofs
  pipelock audit capsule --expires 168h`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Load config and compute hash. For file configs, we read the raw
			// bytes for hashing, then load/parse. The config loader re-reads the
			// file, so a concurrent modification could cause the hash to diverge
			// from the scored config. This is acceptable for a CLI tool: the
			// capsule documents the config's state at generation time, not a
			// cryptographic proof of exact correspondence. A future LoadFromBytes
			// API would eliminate the gap entirely.
			cfg, err := cliutil.LoadConfigOrDefault(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			configHash, err := hashConfigFile(configFile)
			if err != nil {
				return fmt.Errorf("hashing config: %w", err)
			}

			result := ScoreConfig(cfg, configFile)

			now := time.Now().UTC()
			capsule := &PostureCapsule{
				Version:     capsuleVersion,
				GeneratedAt: now,
				ExpiresAt:   now.Add(expires),
				Score:       result,
				ConfigHash:  configHash,
				PipelockVer: cliutil.Version,
			}

			if jsonOutput {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(capsule); err != nil {
					return fmt.Errorf("encoding JSON: %w", err)
				}
				return checkCIGate(result, ciGate)
			}

			wantFormats := parseFormats(formats)
			if len(wantFormats) == 0 {
				return fmt.Errorf("--format must specify at least one of: json, md, svg")
			}

			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return fmt.Errorf("creating output directory: %w", err)
			}

			for _, f := range wantFormats {
				if err := writeCapsuleFile(capsule, outputDir, f); err != nil {
					return err
				}
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Wrote %s\n", filepath.Join(outputDir, f))
			}

			return checkCIGate(result, ciGate)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "config file to score (default: built-in defaults)")
	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", ".", "directory to write proof files")
	cmd.Flags().StringVar(&formats, "format", "json,md,svg", "comma-separated formats: json, md, svg")
	cmd.Flags().DurationVar(&expires, "expires", defaultExpiry, "duration until capsule expires")
	cmd.Flags().IntVar(&ciGate, "ci-gate", 0, "minimum score percentage to exit 0 (0 = no gate)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output JSON to stdout instead of writing files")

	return cmd
}

// checkCIGate returns an error when ciGate is set and the score falls below it.
func checkCIGate(result *ScoreResult, ciGate int) error {
	if ciGate > 0 && result.Percentage < ciGate {
		return fmt.Errorf("score %d%% is below CI gate threshold %d%%", result.Percentage, ciGate)
	}
	return nil
}

// hashConfigFile returns a hex-encoded SHA-256 hash of the config file, or
// "defaults" when no file was provided.
func hashConfigFile(path string) (string, error) {
	if path == "" {
		return configHashDefaults, nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("reading config for hash: %w", err)
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", h), nil
}

// parseFormats splits the comma-separated format string and returns only
// recognized format names.
func parseFormats(raw string) []string {
	known := map[string]bool{
		capsuleFileJSON: true,
		capsuleFileMD:   true,
		capsuleFileSVG:  true,
	}
	var out []string
	for _, tok := range strings.Split(raw, ",") {
		name := formatToFilename(strings.TrimSpace(tok))
		if known[name] {
			out = append(out, name)
		}
	}
	return out
}

// formatToFilename converts a short format name to its proof filename.
func formatToFilename(f string) string {
	switch f {
	case "json":
		return capsuleFileJSON
	case "md":
		return capsuleFileMD
	case "svg":
		return capsuleFileSVG
	default:
		return f
	}
}

// writeCapsuleFile writes a single proof artifact to the output directory.
func writeCapsuleFile(c *PostureCapsule, dir, filename string) error {
	path := filepath.Join(dir, filename)
	var data []byte
	var err error

	switch filename {
	case capsuleFileJSON:
		data, err = renderCapsuleJSON(c)
	case capsuleFileMD:
		data = renderCapsuleMD(c)
	case capsuleFileSVG:
		data = renderCapsuleSVG(c)
	default:
		return fmt.Errorf("unknown capsule format: %s", filename)
	}
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

func renderCapsuleJSON(c *PostureCapsule) ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling capsule JSON: %w", err)
	}
	data = append(data, '\n')
	return data, nil
}

func renderCapsuleMD(c *PostureCapsule) []byte {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "# Pipelock Security Posture\n\n")
	_, _ = fmt.Fprintf(&b, "**Score:** %d/%d (%s)\n", c.Score.TotalScore, c.Score.MaxScore, c.Score.Grade)
	_, _ = fmt.Fprintf(&b, "**Generated:** %s\n", c.GeneratedAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "**Expires:** %s\n", c.ExpiresAt.Format(time.RFC3339))
	_, _ = fmt.Fprintf(&b, "**Config hash:** %s\n", c.ConfigHash)
	_, _ = fmt.Fprintf(&b, "**Pipelock version:** %s\n\n", c.PipelockVer)

	_, _ = fmt.Fprintf(&b, "## Categories\n\n")
	_, _ = fmt.Fprintf(&b, "| Category | Score | Max |\n")
	_, _ = fmt.Fprintf(&b, "|----------|-------|-----|\n")
	for _, cat := range c.Score.Categories {
		_, _ = fmt.Fprintf(&b, "| %s | %d | %d |\n", cat.Name, cat.Score, cat.MaxScore)
	}

	if len(c.Score.Findings) > 0 {
		_, _ = fmt.Fprintf(&b, "\n## Findings\n\n")
		for _, f := range c.Score.Findings {
			icon := findingIcon(f.Severity)
			_, _ = fmt.Fprintf(&b, "- %s [%s] %s\n", icon, f.Severity, f.Message)
		}
	}

	return []byte(b.String())
}

// findingIcon returns a Unicode indicator for the finding severity.
func findingIcon(sev string) string {
	switch sev {
	case scoreSevCritical:
		return "\u274c" // red cross
	case scoreSevWarning:
		return "\u26a0\ufe0f" // warning sign
	default:
		return "\u2139\ufe0f" // info
	}
}

func renderCapsuleSVG(c *PostureCapsule) []byte {
	color := badgeColor(c.Score.Grade)
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20">
  <rect width="90" height="20" fill="#555"/>
  <rect x="90" width="70" height="20" fill="%s"/>
  <text x="45" y="14" fill="#fff" text-anchor="middle" font-size="11" font-family="sans-serif">pipelock</text>
  <text x="125" y="14" fill="#fff" text-anchor="middle" font-size="11" font-family="sans-serif">%s %d%%</text>
</svg>
`, color, c.Score.Grade, c.Score.Percentage)
	return []byte(svg)
}

// badgeColor maps a score grade to a shields.io-style hex color.
func badgeColor(grade string) string {
	switch grade {
	case "A":
		return badgeColorGreen
	case "B":
		return badgeColorYellowGreen
	case "C":
		return badgeColorYellow
	case "D":
		return badgeColorOrange
	default:
		return badgeColorRed
	}
}
