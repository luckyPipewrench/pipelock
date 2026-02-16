package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/integrity"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// ErrIntegrityViolation is returned when pipelock integrity check finds violations.
var ErrIntegrityViolation = errors.New("integrity violations found")

func integrityCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "integrity",
		Short: "File integrity monitoring for agent workspaces",
		Long: `Generate, check, and update SHA256 integrity manifests for agent
workspace directories. Detects unauthorized file modifications, additions,
and deletions.

Examples:
  pipelock integrity init /path/to/workspace
  pipelock integrity check /path/to/workspace
  pipelock integrity update /path/to/workspace`,
	}

	cmd.AddCommand(integrityInitCmd())
	cmd.AddCommand(integrityCheckCmd())
	cmd.AddCommand(integrityUpdateCmd())
	return cmd
}

func integrityInitCmd() *cobra.Command {
	var manifestPath string
	var excludes []string
	var signManifest bool
	var agentName string
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "init [directory]",
		Short: "Generate a new integrity manifest for a workspace",
		Long: `Walks the directory, computes SHA256 hashes for every file, and writes
an integrity manifest. The manifest records file hashes, sizes, and permissions.

The manifest is saved as .integrity-manifest.json in the target directory by default.

Examples:
  pipelock integrity init .
  pipelock integrity init /path/to/workspace --exclude "*.log" --exclude "tmp/**"
  pipelock integrity init . --manifest /secure/location/manifest.json
  pipelock integrity init . --sign --agent claude-code`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolveDir(args)
			if err != nil {
				return err
			}

			mPath := resolveManifestPath(manifestPath, dir)
			if _, statErr := os.Stat(mPath); statErr == nil {
				return fmt.Errorf("manifest already exists at %s (use 'update' to regenerate)", mPath)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return fmt.Errorf("checking for existing manifest: %w", statErr)
			}

			allExcludes := appendManifestExclude(excludes, mPath, dir)
			m, err := integrity.Generate(dir, allExcludes)
			if err != nil {
				return err
			}

			if err := m.Save(mPath); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out,
				"Manifest created: %s (%d %s)\n", mPath, len(m.Files), pluralFile(len(m.Files)))

			if signManifest {
				if err := signManifestFile(mPath, agentName, keystoreDir, out); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path (default: .integrity-manifest.json in target dir)")
	cmd.Flags().StringArrayVar(&excludes, "exclude", nil, "glob patterns to exclude (repeatable)")
	cmd.Flags().BoolVar(&signManifest, "sign", false, "sign the manifest with an agent key")
	cmd.Flags().StringVar(&agentName, "agent", "", "agent name for signing (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	return cmd
}

func integrityCheckCmd() *cobra.Command {
	var manifestPath string
	var jsonOutput bool
	var verifySignature bool
	var agentName string
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "check [directory]",
		Short: "Check workspace integrity against stored manifest",
		Long: `Compares the current state of a directory against a previously generated
integrity manifest. Reports any modified, added, or removed files.

Returns a non-zero exit code if violations are found or an error occurs.

Use --verify to validate the manifest's Ed25519 signature before trusting it.

Examples:
  pipelock integrity check /path/to/workspace
  pipelock integrity check . --json
  pipelock integrity check . --manifest /secure/location/manifest.json
  pipelock integrity check . --verify --agent claude-code`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolveDir(args)
			if err != nil {
				return err
			}

			mPath := resolveManifestPath(manifestPath, dir)
			out := cmd.OutOrStdout()

			// Verify the manifest signature before trusting its contents.
			if verifySignature {
				if err := verifyManifestFile(mPath, agentName, keystoreDir, out); err != nil {
					return err
				}
			}

			m, err := integrity.Load(mPath)
			if err != nil {
				return fmt.Errorf("loading manifest: %w", err)
			}

			// Ensure the manifest file itself is excluded from the check,
			// even when using a custom --manifest path inside the workspace.
			m.Excludes = appendManifestExclude(m.Excludes, mPath, dir)

			violations, err := integrity.Check(dir, m)
			if err != nil {
				return err
			}

			// Sort violations for deterministic output.
			sort.Slice(violations, func(i, j int) bool {
				return violations[i].Path < violations[j].Path
			})

			if jsonOutput {
				if err := writeJSONCheck(out, violations); err != nil {
					return err
				}
			} else if len(violations) == 0 {
				_, _ = fmt.Fprintln(out, "All files match manifest.")
			} else {
				writeTextCheck(out, violations)
			}

			if len(violations) > 0 {
				return ErrIntegrityViolation
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path (default: .integrity-manifest.json in target dir)")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "output results as JSON")
	cmd.Flags().BoolVar(&verifySignature, "verify", false, "verify manifest signature before checking")
	cmd.Flags().StringVar(&agentName, "agent", "", "agent name for signature verification (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	return cmd
}

// checkResult is the JSON output structure for integrity check.
type checkResult struct {
	OK         bool                  `json:"ok"`
	Violations []integrity.Violation `json:"violations"`
}

func writeJSONCheck(out io.Writer, violations []integrity.Violation) error {
	result := checkResult{
		OK:         len(violations) == 0,
		Violations: violations,
	}
	if result.Violations == nil {
		result.Violations = []integrity.Violation{}
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	_, _ = fmt.Fprintln(out, string(data))
	return nil
}

func writeTextCheck(out io.Writer, violations []integrity.Violation) {
	_, _ = fmt.Fprintf(out, "Integrity check: %d violation(s) found\n\n", len(violations))

	for _, v := range violations {
		switch v.Type {
		case integrity.ViolationModified:
			_, _ = fmt.Fprintf(out, "  MODIFIED  %s\n", v.Path)
			_, _ = fmt.Fprintf(out, "    expected: sha256:%s\n", v.Expected)
			_, _ = fmt.Fprintf(out, "    actual:   sha256:%s\n\n", v.Actual)
		case integrity.ViolationAdded:
			_, _ = fmt.Fprintf(out, "  ADDED     %s\n", v.Path)
			_, _ = fmt.Fprintf(out, "    not in manifest (unexpected new file)\n\n")
		case integrity.ViolationRemoved:
			_, _ = fmt.Fprintf(out, "  REMOVED   %s\n", v.Path)
			_, _ = fmt.Fprintf(out, "    in manifest but missing from disk\n\n")
		case integrity.ViolationPermissions:
			_, _ = fmt.Fprintf(out, "  PERMS     %s\n", v.Path)
			_, _ = fmt.Fprintf(out, "    expected: %s\n", v.Expected)
			_, _ = fmt.Fprintf(out, "    actual:   %s\n\n", v.Actual)
		}
	}

	_, _ = fmt.Fprintln(out, "Run 'pipelock integrity update' after reviewing changes.")
}

func integrityUpdateCmd() *cobra.Command {
	var manifestPath string
	var excludes []string
	var signManifest bool
	var agentName string
	var keystoreDir string

	cmd := &cobra.Command{
		Use:   "update [directory]",
		Short: "Update manifest to reflect current workspace state",
		Long: `Re-scans the directory and overwrites the existing manifest with current
file hashes. Use this after reviewing and approving changes detected by 'check'.

If --exclude flags are provided, they replace the excludes in the existing manifest.
Otherwise, the existing excludes are preserved.

Examples:
  pipelock integrity update /path/to/workspace
  pipelock integrity update . --exclude "*.log" --exclude "tmp/**"
  pipelock integrity update . --sign --agent claude-code`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolveDir(args)
			if err != nil {
				return err
			}

			mPath := resolveManifestPath(manifestPath, dir)

			// Load existing manifest to preserve created time and excludes.
			existing, err := integrity.Load(mPath)
			if err != nil {
				return fmt.Errorf("loading existing manifest: %w", err)
			}

			// Use existing excludes unless overridden.
			useExcludes := existing.Excludes
			if len(excludes) > 0 {
				useExcludes = excludes
			}

			allExcludes := appendManifestExclude(useExcludes, mPath, dir)
			m, err := integrity.Generate(dir, allExcludes)
			if err != nil {
				return err
			}

			// Preserve original creation time.
			m.Created = existing.Created

			if err := m.Save(mPath); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out,
				"Manifest updated: %s (%d %s)\n", mPath, len(m.Files), pluralFile(len(m.Files)))

			if signManifest {
				if err := signManifestFile(mPath, agentName, keystoreDir, out); err != nil {
					return err
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&manifestPath, "manifest", "", "manifest file path (default: .integrity-manifest.json in target dir)")
	cmd.Flags().StringArrayVar(&excludes, "exclude", nil, "glob patterns to exclude (repeatable, replaces existing)")
	cmd.Flags().BoolVar(&signManifest, "sign", false, "sign the manifest with an agent key")
	cmd.Flags().StringVar(&agentName, "agent", "", "agent name for signing (or set PIPELOCK_AGENT)")
	cmd.Flags().StringVar(&keystoreDir, "keystore", "", "keystore directory (default ~/.pipelock)")
	return cmd
}

// resolveDir resolves the target directory from command args, defaulting to ".".
func resolveDir(args []string) (string, error) {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}

	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolving directory: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("accessing directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", abs)
	}

	return abs, nil
}

func resolveManifestPath(explicit, dir string) string {
	if explicit != "" {
		if abs, err := filepath.Abs(explicit); err == nil {
			return abs
		}
		return explicit
	}
	return filepath.Join(dir, integrity.DefaultManifestFile)
}

// appendManifestExclude adds the manifest's relative path to the excludes list
// if the manifest resides inside the workspace directory and has a non-default
// name. The default manifest name is already handled by alwaysExcluded.
func appendManifestExclude(excludes []string, manifestPath, dir string) []string {
	rel, err := filepath.Rel(dir, manifestPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return excludes
	}
	rel = filepath.ToSlash(rel)
	// The default manifest name and its .sig companion are already in alwaysExcluded.
	if rel == integrity.DefaultManifestFile {
		return excludes
	}
	// For custom manifest paths, exclude both the manifest and its .sig companion.
	for _, p := range []string{rel, rel + ".sig"} {
		found := false
		for _, e := range excludes {
			if e == p {
				found = true
				break
			}
		}
		if !found {
			excludes = append(excludes, p)
		}
	}
	return excludes
}

func pluralFile(n int) string {
	if n == 1 {
		return "file"
	}
	return "files"
}

// signManifestFile signs a manifest file and saves the detached signature.
func signManifestFile(mPath, agentName, keystoreDir string, out io.Writer) error {
	agent, err := resolveAgentName(agentName)
	if err != nil {
		return err
	}

	dir, err := resolveKeystoreDir(keystoreDir)
	if err != nil {
		return err
	}
	ks := signing.NewKeystore(dir)

	privKey, err := ks.LoadPrivateKey(agent)
	if err != nil {
		return fmt.Errorf("loading key for agent %q: %w", agent, err)
	}

	sig, err := signing.SignFile(mPath, privKey)
	if err != nil {
		return fmt.Errorf("signing manifest: %w", err)
	}

	sigPath := mPath + signing.SigExtension
	if err := signing.SaveSignature(sig, sigPath); err != nil {
		return fmt.Errorf("saving manifest signature: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Manifest signed by agent %q\n", agent)
	return nil
}

// verifyManifestFile verifies a manifest's detached signature.
func verifyManifestFile(mPath, agentName, keystoreDir string, out io.Writer) error {
	agent, err := resolveAgentName(agentName)
	if err != nil {
		return err
	}

	dir, err := resolveKeystoreDir(keystoreDir)
	if err != nil {
		return err
	}
	ks := signing.NewKeystore(dir)

	pubKey, err := ks.ResolvePublicKey(agent)
	if err != nil {
		return fmt.Errorf("loading key for agent %q: %w", agent, err)
	}

	if err := signing.VerifyFile(mPath, "", pubKey); err != nil {
		return fmt.Errorf("manifest signature verification failed: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Manifest signature verified (agent: %s)\n", agent)
	return nil
}
