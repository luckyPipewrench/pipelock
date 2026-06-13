// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/secperm"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// Status strings reused across the report. Kept as constants so the JSON shape
// is stable and goconst stays quiet.
const (
	statusOK   = "ok"
	statusWarn = "warn"
	statusInfo = "info"
	statusFail = "fail"
)

// keyType is the parsed-form classification reported in the "valid" column. All
// shipped signing keys are Ed25519; the field exists so a future key type is a
// data change, not a schema change.
const keyTypeEd25519 = "ed25519"

// Source-kind labels describe HOW a purpose's key reaches Pipelock. Each kind
// changes what "present" and "valid" can mean, which the report surfaces in the
// note column.
const (
	// sourceConfigPrivate: a private key file whose path comes from a config
	// field. Present = file exists + readable; valid = parses as Ed25519
	// private key.
	sourceConfigPrivate = "config-private-key-file"
	// sourceDeploymentFile: a deployment-level key file produced by
	// `pipelock signing key generate`. The path is operator-chosen (the
	// generate --out flag) and not recorded in a single config field, so the
	// status command cannot locate it automatically.
	sourceDeploymentFile = "deployment-key-file"
	// sourceRoster: a PUBLIC key pinned in the deployment trust roster. The
	// private half lives off-host with the signer; followers only verify.
	sourceRoster = "trust-roster-public-key"
	// sourceBundledPublic: a PUBLIC verification key configured inline (e.g.
	// rules.trusted_keys) or shipped with the official rules bundle.
	sourceBundledPublic = "bundled-public-key"
	// sourceEmbeddedOrEnv: the license verification PUBLIC key, embedded at
	// build time on official releases and overridable by env only on dev
	// builds. This is not one of the wire KeyPurpose values; it is reported
	// alongside them because operators think of it as "a Pipelock key".
	sourceEmbeddedOrEnv = "embedded-at-build-or-env"
)

// keyStatusReport is the top-level JSON shape emitted by `keys status`.
type keyStatusReport struct {
	ConfigFile    string          `json:"config_file"`
	RootRunBanner string          `json:"root_run_banner,omitempty"`
	Summary       keyStatusTally  `json:"summary"`
	Keys          []keyStatusItem `json:"keys"`
}

// keyStatusTally counts items by report status for the human summary line.
type keyStatusTally struct {
	OK   int `json:"ok"`
	Warn int `json:"warn"`
	Info int `json:"info"`
	Fail int `json:"fail"`
}

// keyStatusItem is one signing-key purpose row. It never carries key material:
// Fingerprint is the sha256 of the PUBLIC key only, and is populated only when
// present and valid.
type keyStatusItem struct {
	// Purpose is the wire-format purpose string, or "license-verification"
	// for the non-wire license verify key row.
	Purpose string `json:"purpose"`
	// SourceKind is one of the source* constants above.
	SourceKind string `json:"source_kind"`
	// Source is a human description of where the key is expected to come from
	// (config field name and/or default path), never a secret.
	Source string `json:"source"`
	// Path is the resolved filesystem path when SourceKind locates one;
	// empty otherwise.
	Path string `json:"path,omitempty"`
	// Present reports whether a key file exists at Path and is readable by the
	// calling user. Meaningful only for file-backed sources; false for sources
	// the command cannot locate (deployment files, roster, embedded/env).
	Present bool `json:"present"`
	// Readable mirrors Present for file-backed sources; for the embedded
	// license key it reports whether a key is available (embedded or env).
	Readable bool `json:"readable"`
	// Valid reports whether the located material parses as the expected key
	// type. Only meaningful when Present is true.
	Valid bool `json:"valid"`
	// KeyType is the parsed key type (keyTypeEd25519) when Valid; empty
	// otherwise.
	KeyType string `json:"key_type,omitempty"`
	// Fingerprint is the canonical "sha256:" public-key fingerprint when the
	// PUBLIC key is available and valid. Never derived from or revealing of
	// private material.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Status is one of the status* constants, summarising the row.
	Status string `json:"status"`
	// Note carries any caveat: unlocatable source, reserved purpose, embedded
	// vs env precedence, or the parse error (never key bytes).
	Note string `json:"note,omitempty"`
}

// rootBannerText mirrors doctor's caveat: when run as root, DAC is bypassed and
// any file the kernel can stat looks readable, so the readability column
// reflects root's view, not the service user's.
const rootBannerText = "running as root: readability checks reflect root's view, not the pipelock service user's. Re-run as the service user for an accurate readability report."

func statusCmd() *cobra.Command {
	var configFile string
	var jsonOutput bool
	var homeDir string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show every signing-key purpose, its source, presence, and validity",
		Long: `Print a unified view of every signing-key purpose Pipelock recognises:
the purpose, where its key is expected to come from (config field and/or
default path), whether it is present and readable by the calling user, whether
it parses as the expected key type (Ed25519), and any relevant note.

This command performs no network access and never prints private key material.
For present public keys it prints the canonical sha256 fingerprint only.

Readability reflects the calling user's view. When run as root (sudo), DAC
checks are bypassed and any file the kernel can stat looks readable. Re-run as
the pipelock service user for an accurate "can the service read this" report.

Source kinds:
  config-private-key-file    private key located via a config field
  deployment-key-file        operator-chosen file from 'pipelock signing key generate'
  trust-roster-public-key    public key pinned in the deployment trust roster
  bundled-public-key         public verification key (e.g. rules.trusted_keys)
  embedded-at-build-or-env   license verify key, embedded on official builds

Examples:
  pipelock keys status
  pipelock keys status --config /etc/pipelock/pipelock.yaml
  pipelock keys status --json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// A --home on this command overrides the root persistent flag for
			// path resolution, matching keygen/trust ergonomics.
			if homeDir != "" {
				cliutil.PipelockHome = homeDir
			}
			cfg, cfgLabel, err := loadStatusConfig(configFile)
			if err != nil {
				return cliutil.ExitCodeError(2, err)
			}
			report := buildKeyStatusReport(cfg, cfgLabel)
			if jsonOutput {
				report.RootRunBanner = rootBannerMessage()
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return fmt.Errorf("encode keys status JSON: %w", err)
				}
				return nil
			}
			printKeyStatusReport(cmd, report, cliutil.UseColor())
			return nil
		},
	}

	cmd.Flags().StringVarP(&configFile, flagConfig, "c", "", usageConfig)
	cmd.Flags().BoolVar(&jsonOutput, flagJSON, false, usageJSON)
	cmd.Flags().StringVar(&homeDir, flagHome, "", usageHome)
	return cmd
}

// loadStatusConfig resolves and loads the config, mirroring doctor's behavior:
// an empty path uses built-in defaults rather than erroring, so the command is
// useful on a clean checkout.
func loadStatusConfig(path string) (*config.Config, string, error) {
	if path == "" {
		return config.Defaults(), "(built-in defaults)", nil
	}
	cfg, err := config.Load(filepath.Clean(path))
	if err != nil {
		return nil, "", fmt.Errorf("config load error: %w", err)
	}
	return cfg, path, nil
}

// buildKeyStatusReport enumerates every wire KeyPurpose from the authoritative
// source enum (never a hardcoded list) and resolves each against the loaded
// config, then appends the non-wire license verification key row.
func buildKeyStatusReport(cfg *config.Config, cfgLabel string) keyStatusReport {
	report := keyStatusReport{ConfigFile: cfgLabel}
	for _, purpose := range domsigning.KnownPurposes() {
		report.Keys = append(report.Keys, resolvePurpose(cfg, purpose))
	}
	report.Keys = append(report.Keys, resolveLicenseVerifyKey(cfg))

	for _, item := range report.Keys {
		switch item.Status {
		case statusOK:
			report.Summary.OK++
		case statusWarn:
			report.Summary.Warn++
		case statusFail:
			report.Summary.Fail++
		default:
			report.Summary.Info++
		}
	}
	return report
}

// resolvePurpose builds the status row for one wire purpose. The source mapping
// is a deliberate, code-reviewed switch over the real enum values: it is the
// one place that encodes which scattered surface each purpose's key lives on.
func resolvePurpose(cfg *config.Config, purpose domsigning.KeyPurpose) keyStatusItem {
	item := keyStatusItem{Purpose: purpose.String()}

	switch purpose {
	case domsigning.PurposeReceiptSigning:
		// Receipt/checkpoint signing key. Mediation envelopes have their own
		// HTTP message-signing key and do not satisfy this purpose.
		item.SourceKind = sourceConfigPrivate
		item.Source = "config field flight_recorder.signing_key_path"
		path := strings.TrimSpace(cfg.FlightRecorder.SigningKeyPath)
		return finishPrivateKeyFile(item, path,
			"no flight_recorder.signing_key_path configured")

	case domsigning.PurposeRulesOfficialSigning:
		// Official rules package signing: Pipelock only holds the PUBLIC
		// verification keys (rules.trusted_keys, plus the bundle's shipped
		// key). The private signer lives with the project.
		item.SourceKind = sourceBundledPublic
		item.Source = "config field rules.trusted_keys[] and the official rules bundle public key"
		return finishPublicKeyList(item, rulesTrustedPublicKeys(cfg),
			"no rules.trusted_keys configured; the official bundle public key ships with releases")

	case domsigning.PurposeRosterRoot, domsigning.PurposeRecoveryRoot:
		// Deployment-local trust roots: PUBLIC keys pinned in the roster,
		// chained from a pinned root fingerprint. Followers only verify.
		item.SourceKind = sourceRoster
		item.Source = "deployment trust roster (conductor.trust_roster_path / pinned root fingerprint)"
		return finishRosterRef(item, rosterReference(cfg))

	case domsigning.PurposePolicyBundleSigning,
		domsigning.PurposePolicyBundleRollback,
		domsigning.PurposeRemoteKillSigning,
		domsigning.PurposeTrustRootRotation,
		domsigning.PurposeEnrollmentTokenSigning:
		// Conductor control-plane purposes. On a FOLLOWER (the only side a
		// pipelock config describes) these are PUBLIC keys verified via the
		// roster; the private signers live on the leader / with approvers.
		item.SourceKind = sourceRoster
		item.Source = "Conductor trust roster (leader-side private signer; follower verifies via roster)"
		out := finishRosterRef(item, rosterReference(cfg))
		out.Note = appendNote(out.Note, conductorPurposeNote(purpose))
		return out

	case domsigning.PurposeAuditBatchSigning:
		// Runtime audit batches are signed by the follower's flight-recorder
		// private key. The Conductor audit sink enrolls/trusts the public half
		// under conductor.audit_signing_key_id.
		item.SourceKind = sourceConfigPrivate
		item.Source = "config field flight_recorder.signing_key_path (conductor.audit_signing_key_id names the audit signer)"
		out := finishPrivateKeyFile(item, strings.TrimSpace(cfg.FlightRecorder.SigningKeyPath),
			"no flight_recorder.signing_key_path configured; conductor audit batch producer cannot sign batches")
		out.Note = appendNote(out.Note, "flight-recorder signing key doubles as the Conductor audit-batch signer; public key is enrolled/trusted by the Conductor audit sink")
		return out

	case domsigning.PurposeContractCompileSigning,
		domsigning.PurposeContractActivationSigning:
		// Deployment-level operator keys produced by
		// `pipelock signing key generate --purpose <p> --out <path>`. The path
		// is operator-chosen and not stored in a single config field, so the
		// status command cannot locate them automatically.
		item.SourceKind = sourceDeploymentFile
		item.Source = "key file from 'pipelock signing key generate --purpose " + purpose.String() + " --out <path>'"
		item.Status = statusInfo
		item.Note = "operator-chosen path; not discoverable from config. Public half is pinned in the trust roster."
		return item

	case domsigning.PurposeFleetReportSigning:
		// Enterprise Fleet Receipt Report signing key, produced by
		// `pipelock signing key generate --purpose fleet-report-signing --out <path>`
		// and held by the Conductor leader that mints reports. The path is
		// operator-chosen and not stored in config; the public half is published
		// for offline report verification (`verify-receipt --fleet-report --key`).
		item.SourceKind = sourceDeploymentFile
		item.Source = "key file from 'pipelock signing key generate --purpose fleet-report-signing --out <path>'"
		item.Status = statusInfo
		item.Note = "Enterprise Conductor report signer; operator-chosen path, not discoverable from config. Public half is published for offline report verification."
		return item

	default:
		// Defensive: a new purpose added to the enum without a mapping here
		// is reported honestly rather than silently dropped.
		item.SourceKind = sourceDeploymentFile
		item.Source = "unmapped purpose"
		item.Status = statusWarn
		item.Note = "no source mapping for this purpose; update keys status when adding a purpose"
		return item
	}
}

// finishPrivateKeyFile resolves a private-key file path: presence, readability,
// and parse validity. It NEVER returns or logs the parsed private bytes; the
// only public-derived value emitted is the fingerprint.
func finishPrivateKeyFile(item keyStatusItem, path, absentNote string) keyStatusItem {
	if path == "" {
		item.Status = statusInfo
		item.Note = absentNote
		return item
	}
	clean := filepath.Clean(path)
	item.Path = clean

	info, err := os.Lstat(clean)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			item.Status = statusInfo
			item.Note = "configured but no file at path (not yet provisioned)"
		case errors.Is(err, os.ErrPermission):
			item.Status = statusFail
			item.Note = "configured path is not stat-readable by this user"
		default:
			item.Status = statusWarn
			item.Note = "configured path could not be inspected"
		}
		return item
	}
	if info.Mode()&os.ModeSymlink == 0 && !info.Mode().IsRegular() {
		item.Present = true
		item.Status = statusFail
		item.Note = "path is not a regular file"
		return item
	}
	item.Present = true

	// Permission gate: a private key that is group/other-accessible is a
	// finding even if technically readable. Mirrors LoadPrivateKeyFile's mask.
	if secperm.Enforced {
		if pinfo, statErr := os.Stat(clean); statErr == nil &&
			secperm.TooPermissive(pinfo.Mode().Perm(), 0o037) {
			item.Readable = true
			item.Status = statusWarn
			item.Note = fmt.Sprintf("permissions %04o are too permissive for a private key (want 0600 or 0640)", pinfo.Mode().Perm())
			return item
		}
	}

	priv, loadErr := domsigning.LoadPrivateKeyFile(clean)
	if loadErr != nil {
		// Distinguish "can't read" from "read but won't parse" without
		// leaking the error's potential path/byte detail beyond the category.
		item.Readable = pathReadable(clean)
		item.Status = statusFail
		item.Note = "present but failed to load as an Ed25519 private key"
		return item
	}
	item.Readable = true
	item.Valid = true
	item.KeyType = keyTypeEd25519
	if pubHex, fpErr := publicFingerprintFromPrivate(priv); fpErr == nil {
		item.Fingerprint = pubHex
	}
	// Discard the private key immediately; nothing below references it.
	priv = nil
	_ = priv
	item.Status = statusOK
	return item
}

// publicFingerprintFromPrivate derives the canonical PUBLIC fingerprint from a
// private key without ever exposing private bytes. It uses the public half that
// Ed25519 private keys carry.
func publicFingerprintFromPrivate(priv ed25519.PrivateKey) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("derive public key from private key")
	}
	return domsigning.Fingerprint(pub)
}

// finishPublicKeyList reports a set of configured PUBLIC verification keys.
func finishPublicKeyList(item keyStatusItem, keys []ed25519.PublicKey, absentNote string) keyStatusItem {
	if len(keys) == 0 {
		item.Status = statusInfo
		item.Note = absentNote
		return item
	}
	// All configured keys must parse; report the first fingerprint and a count.
	item.Present = true
	item.Readable = true
	item.Valid = true
	item.KeyType = keyTypeEd25519
	if fp, err := domsigning.Fingerprint(keys[0]); err == nil {
		item.Fingerprint = fp
	}
	item.Status = statusOK
	if len(keys) > 1 {
		item.Note = fmt.Sprintf("%d trusted public keys configured (showing first fingerprint)", len(keys))
	}
	return item
}

// finishRosterRef reports a roster-backed (public-key, off-host signer) purpose.
func finishRosterRef(item keyStatusItem, ref rosterRef) keyStatusItem {
	if ref.path == "" && ref.fingerprint == "" {
		item.Status = statusInfo
		item.Note = "no trust roster configured (conductor disabled or follower role unset)"
		return item
	}
	if ref.path != "" {
		item.Path = ref.path
		if pathReadable(ref.path) {
			item.Present = true
			item.Readable = true
		}
	}
	if ref.fingerprint != "" {
		item.Note = appendNote(item.Note, "pinned root fingerprint "+ref.fingerprint)
	}
	switch {
	case item.Present:
		item.Status = statusOK
	case ref.fingerprint != "":
		item.Status = statusInfo
		item.Note = appendNote(item.Note, "roster path not readable here; public key is pinned by fingerprint")
	default:
		item.Status = statusInfo
		item.Note = appendNote(item.Note, "roster path not readable from this user/host")
	}
	return item
}

// resolveLicenseVerifyKey reports the license VERIFICATION public key. This is
// not a wire KeyPurpose; it is included because operators reason about it as a
// Pipelock key. Embedded (build-time) key wins; env override is a dev fallback.
func resolveLicenseVerifyKey(cfg *config.Config) keyStatusItem {
	item := keyStatusItem{
		Purpose:    "license-verification",
		SourceKind: sourceEmbeddedOrEnv,
		Source:     "embedded at build (official releases) or config license_public_key / PIPELOCK_LICENSE_PUBLIC_KEY (dev builds)",
	}
	if key := license.EmbeddedPublicKey(); key != nil {
		item.Present = true
		item.Readable = true
		item.Valid = true
		item.KeyType = keyTypeEd25519
		if fp, err := domsigning.Fingerprint(key); err == nil {
			item.Fingerprint = fp
		}
		item.Status = statusOK
		item.Note = "embedded build-time key in use; env override is ignored on this build"
		return item
	}
	// Dev build: fall back to config / env public key.
	envKey := strings.TrimSpace(os.Getenv(license.EnvLicensePublicKey))
	cfgKey := strings.TrimSpace(cfg.LicensePublicKey)
	source := cfgKey
	via := "config license_public_key"
	if source == "" && envKey != "" {
		source = envKey
		via = "env " + license.EnvLicensePublicKey
	}
	if source == "" {
		item.Status = statusInfo
		item.Note = "no embedded key (dev build) and no license_public_key/env override; license verification will fail"
		return item
	}
	pub, err := parsePublicKeyHex(source)
	if err != nil {
		item.Present = true
		item.Status = statusFail
		item.Note = "override present (" + via + ") but is not a valid Ed25519 public key"
		return item
	}
	item.Present = true
	item.Readable = true
	item.Valid = true
	item.KeyType = keyTypeEd25519
	if fp, fpErr := domsigning.Fingerprint(pub); fpErr == nil {
		item.Fingerprint = fp
	}
	item.Status = statusWarn
	item.Note = "dev-build override via " + via + "; official builds embed the verify key"
	return item
}
