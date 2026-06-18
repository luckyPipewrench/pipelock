//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/fleetreport"
	clisigning "github.com/luckyPipewrench/pipelock/internal/cli/signing"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

type fleetReportOptions struct {
	storageDir       string
	orgID            string
	fleetID          string
	from             string
	to               string
	signingKey       string
	signingKeyID     string
	out              string
	conductorID      string
	conductorVersion string
	trustedAuditKeys []string
	limit            int
	licenseCRLFile   string
}

func fleetReportCmd() *cobra.Command {
	opts := fleetReportOptions{
		conductorID: "conductor",
	}
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Mint a Fleet Receipt Report from local Conductor audit evidence",
		Long: `Mint a DSSE-wrapped Fleet Receipt Report from locally accepted Conductor
audit batches.

This command reads the local SQLite audit store under --storage-dir. It does not
use the remote audit query API and does not expose raw audit payloads over the
network.

Pass --out - to write the DSSE envelope to stdout instead of a file. The
human-readable summary then goes to stderr, so the report can be piped straight
into the offline verifier:

  pipelock conductor fleet report --out - ... | \
    pipelock verify-receipt /dev/stdin --fleet-report --key fleet-report.pub`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := license.VerifyFleetWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile}); err != nil {
				return err
			}
			return runFleetReport(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.storageDir, "storage-dir", "", "directory for Conductor policy bundles and audit store")
	cmd.Flags().StringVar(&opts.orgID, "org-id", "", "org id to report (required)")
	cmd.Flags().StringVar(&opts.fleetID, "fleet-id", "", "fleet id to report (required)")
	cmd.Flags().StringVar(&opts.from, "from", "", "inclusive received-at window start, RFC3339 (required)")
	cmd.Flags().StringVar(&opts.to, "to", "", "exclusive received-at window end, RFC3339 (required)")
	cmd.Flags().StringVar(&opts.signingKey, "signing-key", "", "fleet-report-signing private key file (required)")
	cmd.Flags().StringVar(&opts.signingKeyID, "signing-key-id", "", "override fleet report signing key id")
	cmd.Flags().StringVar(&opts.out, "out", "", "output DSSE envelope path (required); use \"-\" to write the envelope to stdout for piping out of a distroless pod")
	cmd.Flags().StringVar(&opts.conductorID, "conductor-id", opts.conductorID, "Conductor id to stamp into the report")
	cmd.Flags().StringVar(&opts.conductorVersion, "conductor-version", "", "Conductor version to stamp into the report")
	cmd.Flags().StringArrayVar(&opts.trustedAuditKeys, "trusted-audit-key", nil,
		"optional trusted audit signing key as comma-separated kv pairs: 'id=ID,(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path),org=ORG[,fleet=FLEET][,instance=INSTANCE]'; repeatable")
	cmd.Flags().IntVar(&opts.limit, "limit", 0, "fail closed if the window holds more than this many audit batches (0 uses the default cap); never silently truncates the report's evidence set")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	return cmd
}

func runFleetReport(cmd *cobra.Command, opts fleetReportOptions) error {
	if err := validateFleetReportOptions(opts); err != nil {
		return err
	}
	start, err := time.Parse(time.RFC3339, opts.from)
	if err != nil {
		return fmt.Errorf("parse --from: %w", err)
	}
	end, err := time.Parse(time.RFC3339, opts.to)
	if err != nil {
		return fmt.Errorf("parse --to: %w", err)
	}
	keyID, priv, err := loadFleetReportSigningKey(opts.signingKey)
	if err != nil {
		return err
	}
	defer zeroizeKey(priv)
	if strings.TrimSpace(opts.signingKeyID) != "" {
		keyID = strings.TrimSpace(opts.signingKeyID)
	}
	var auditKeys controlplane.AuditKeyResolver
	if len(opts.trustedAuditKeys) > 0 {
		auditKeys, err = buildAuditKeyResolver(opts.trustedAuditKeys)
		if err != nil {
			return err
		}
	}
	store, err := openFleetReportAuditStore(cmd, opts.storageDir)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	result, err := fleetreport.Build(cmd.Context(), store, fleetreport.Options{
		OrgID:            opts.orgID,
		FleetID:          opts.fleetID,
		WindowStart:      start,
		WindowEnd:        end,
		ConductorID:      opts.conductorID,
		ConductorVersion: opts.conductorVersion,
		SignerKeyID:      keyID,
		Signer:           priv,
		AuditKeys:        auditKeys,
		Limit:            opts.limit,
	})
	if err != nil {
		return err
	}
	// "--out -" writes the DSSE envelope to stdout so an operator can pipe the
	// report out of a distroless pod (which has no shell/cat/tar to extract a
	// file). The human-readable summary then goes to stderr to keep stdout a
	// clean DSSE envelope for piping into the offline verifier.
	if opts.out == stdoutSentinel {
		if err := writeFleetReportEnvelopeTo(cmd.OutOrStdout(), result.Envelope); err != nil {
			return err
		}
		summary := cmd.ErrOrStderr()
		_, _ = fmt.Fprintln(summary, "fleet receipt report written: <stdout>")
		_, _ = fmt.Fprintf(summary, "  report_id: %s\n", result.Statement.Predicate.ReportID)
		_, _ = fmt.Fprintf(summary, "  source_batches: %d\n", len(result.Statement.Predicate.SourceBatches))
		_, _ = fmt.Fprintf(summary, "  total_actions: %d\n", result.Statement.Predicate.Summary.TotalActions)
		return nil
	}
	if err := writeFleetReportEnvelope(opts.out, result.Envelope); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "fleet receipt report written: %s\n", opts.out)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  report_id: %s\n", result.Statement.Predicate.ReportID)
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  source_batches: %d\n", len(result.Statement.Predicate.SourceBatches))
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "  total_actions: %d\n", result.Statement.Predicate.Summary.TotalActions)
	return nil
}

// stdoutSentinel is the conventional "-" value for --out meaning "write to
// stdout" rather than a file path.
const stdoutSentinel = "-"

func openFleetReportAuditStore(cmd *cobra.Command, storageDir string) (*controlplane.SQLiteAuditStore, error) {
	auditPath := filepath.Join(storageDir, "audit.db")
	info, err := os.Stat(filepath.Clean(auditPath))
	if err != nil {
		return nil, fmt.Errorf("stat Conductor audit store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("conductor audit store is not a regular file: %s", auditPath)
	}
	return controlplane.OpenSQLiteAuditStore(cmd.Context(), auditPath)
}

func validateFleetReportOptions(opts fleetReportOptions) error {
	for _, item := range []struct {
		flag  string
		value string
	}{
		{"--storage-dir", opts.storageDir},
		{"--org-id", opts.orgID},
		{"--fleet-id", opts.fleetID},
		{"--from", opts.from},
		{"--to", opts.to},
		{"--signing-key", opts.signingKey},
		{"--out", opts.out},
		{"--conductor-id", opts.conductorID},
	} {
		if strings.TrimSpace(item.value) == "" {
			return fmt.Errorf("%s is required", item.flag)
		}
	}
	if opts.limit < 0 {
		return errors.New("--limit must be non-negative")
	}
	return nil
}

func loadFleetReportSigningKey(path string) (string, ed25519.PrivateKey, error) {
	cleanPath := filepath.Clean(path)
	raw, err := clisigning.ReadKeyFileBytes(cleanPath, true)
	if err != nil {
		return "", nil, fmt.Errorf("read --signing-key %q: %w", cleanPath, err)
	}
	var kf publishKeyFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kf); err != nil {
		return "", nil, fmt.Errorf("decode --signing-key %q: %w", cleanPath, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", nil, fmt.Errorf("decode --signing-key %q: trailing JSON after key object", cleanPath)
	}
	if kf.SchemaVersion != keyFileSchemaVersion {
		return "", nil, fmt.Errorf("--signing-key %q: unsupported schema_version %d (expected %d)", cleanPath, kf.SchemaVersion, keyFileSchemaVersion)
	}
	purpose := signing.KeyPurpose(kf.Purpose)
	if err := purpose.Validate(); err != nil {
		return "", nil, fmt.Errorf("--signing-key %q: %w", cleanPath, err)
	}
	if purpose != signing.PurposeFleetReportSigning {
		return "", nil, fmt.Errorf("--signing-key %q: wrong key purpose %q, want %q", cleanPath, kf.Purpose, signing.PurposeFleetReportSigning)
	}
	if strings.TrimSpace(kf.KeyID) == "" {
		return "", nil, fmt.Errorf("--signing-key %q: missing key_id", cleanPath)
	}
	pubBytes, err := hex.DecodeString(kf.Public)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("--signing-key %q: malformed public key", cleanPath)
	}
	privBytes, err := hex.DecodeString(kf.Private)
	if err != nil || len(privBytes) != ed25519.PrivateKeySize {
		return "", nil, fmt.Errorf("--signing-key %q: malformed private key", cleanPath)
	}
	priv := ed25519.PrivateKey(privBytes)
	if err := signing.ValidatePrivateKeyConsistency(priv); err != nil {
		return "", nil, fmt.Errorf("--signing-key %q: %w", cleanPath, err)
	}
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, pubBytes) {
		return "", nil, fmt.Errorf("--signing-key %q: private key does not match its public key", cleanPath)
	}
	return kf.KeyID, priv, nil
}

func marshalFleetReportEnvelope(envelope any) ([]byte, error) {
	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal fleet report envelope: %w", err)
	}
	return append(data, '\n'), nil
}

func writeFleetReportEnvelope(path string, envelope any) error {
	data, err := marshalFleetReportEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		return fmt.Errorf("write --out: %w", err)
	}
	return nil
}

func writeFleetReportEnvelopeTo(w io.Writer, envelope any) error {
	data, err := marshalFleetReportEnvelope(envelope)
	if err != nil {
		return err
	}
	// io.Copy loops until all bytes are written, guarding against a short write
	// that would emit a truncated DSSE envelope and break offline verification.
	if _, err := io.Copy(w, bytes.NewReader(data)); err != nil {
		return fmt.Errorf("write fleet report to stdout: %w", err)
	}
	return nil
}
