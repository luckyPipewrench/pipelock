// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// rosterBuildSchemaVersion is the only KeyRoster schema version this command
// emits today. Wire compat with the runtime loader requires it stays at 1
// until contract.KeyRoster bumps and a parallel loader change ships.
const rosterBuildSchemaVersion = 1

// rosterDefaultDataClass is the default data_class_root if --data-class is
// not supplied. Matches the conservative default the runtime expects: most
// roster bodies carry internal-classification keys.
const rosterDefaultDataClass = string(contract.DataClassInternal)

// includeSpec is one parsed --include entry. Operator supplies these as
// repeatable comma-separated key=value pairs.
type includeSpec struct {
	ID      string
	KeyPath string
	Purpose string
	Status  string
	Role    string
}

func rosterBuildCmd() *cobra.Command {
	var rootPath string
	var includes []string
	var dataClass string
	var schemaVersion int
	var outPath string
	var force bool

	cmd := &cobra.Command{
		Use:   "build",
		Short: "Compose and sign a key roster from a root and a set of includes",
		Long: `Builds a signed RosterEnvelope from a root key file and one or more
public-key includes. The output is a JSON roster file that
"pipelock signing roster verify" accepts and that the live-lock runtime loader
binds against learn_lock.pinned_root_fingerprint.

The --root flag points at a JSON keypair file produced by
"pipelock signing key generate --purpose roster-root". The --include flag is
repeatable and accepts comma-separated key=value pairs:

  id=<key_id>          required, unique within the roster
  key=<path>           required, path to a public-key file (JSON keyFile or
                       agent keystore .pub)
  purpose=<purpose>    required, one of the recognised wire purposes
  status=<status>      optional, default active. One of: active, revoked
  role=<text>          optional, operator-facing principal label

The roster's root entry is auto-included from --root; do not pass an
--include for the root.

Examples:
  pipelock signing roster build \
    --root /etc/pipelock/keys/fleet-root.json \
    --include id=activation-primary,key=/etc/pipelock/keys/activation.pub.json,purpose=contract-activation-signing,role=operator \
    --include id=compile-agentA,key=$HOME/.pipelock/agents/agentA/id_ed25519.pub,purpose=contract-compile-signing \
    --data-class internal \
    --out /etc/pipelock/roster.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			if !filepath.IsAbs(outPath) {
				return fmt.Errorf("--out must be absolute, got %q", outPath)
			}
			cleanOut := filepath.Clean(outPath)

			if !force {
				if _, statErr := os.Stat(cleanOut); statErr == nil {
					return fmt.Errorf("output file %q already exists (use --force to overwrite)", cleanOut)
				} else if !errors.Is(statErr, os.ErrNotExist) {
					return fmt.Errorf("stat output file %q: %w", cleanOut, statErr)
				}
			}

			if schemaVersion != rosterBuildSchemaVersion {
				return fmt.Errorf("--schema-version %d unsupported (expected %d)", schemaVersion, rosterBuildSchemaVersion)
			}

			if err := contract.DataClass(dataClass).Validate(); err != nil {
				return err
			}
			if dataClass == string(contract.DataClassRegulated) {
				return fmt.Errorf("--data-class regulated is forbidden in signed artifacts")
			}

			rootFile, rootPub, rootPriv, err := loadKeyFile(rootPath, domsigning.PurposeRosterRoot)
			if err != nil {
				return fmt.Errorf("load root key: %w", err)
			}

			specs, err := parseIncludeSpecs(includes)
			if err != nil {
				return err
			}

			now := time.Now().UTC().Format(time.RFC3339)
			seenIDs := make(map[string]struct{}, len(specs)+1)
			seenIDs[rootFile.KeyID] = struct{}{}

			keys := make([]contract.KeyInfo, 0, len(specs)+1)
			keys = append(keys, contract.KeyInfo{
				KeyID:        rootFile.KeyID,
				KeyPurpose:   string(domsigning.PurposeRosterRoot),
				PublicKeyHex: hex.EncodeToString(rootPub),
				ValidFrom:    now,
				ValidUntil:   nil,
				Status:       contract.KeyStatusRoot,
				Principal:    "root",
			})

			for _, spec := range specs {
				if _, dup := seenIDs[spec.ID]; dup {
					return fmt.Errorf("duplicate --include id %q (root takes id %q)", spec.ID, rootFile.KeyID)
				}
				seenIDs[spec.ID] = struct{}{}

				flagPurpose := domsigning.KeyPurpose(spec.Purpose)
				if err := flagPurpose.Validate(); err != nil {
					return fmt.Errorf("--include id=%q: %w", spec.ID, err)
				}
				if flagPurpose == domsigning.PurposeRosterRoot {
					return fmt.Errorf("--include id=%q: roster-root entries are auto-included from --root and must not be passed as --include", spec.ID)
				}

				pubBytes, filePurpose, err := readPublicKeyForRoster(spec.KeyPath)
				if err != nil {
					return fmt.Errorf("--include id=%q: %w", spec.ID, err)
				}
				if filePurpose != "" && filePurpose != spec.Purpose {
					return fmt.Errorf("--include id=%q: purpose flag %q disagrees with key file purpose %q", spec.ID, spec.Purpose, filePurpose)
				}

				status := spec.Status
				if status == "" {
					status = contract.KeyStatusActive
				}
				switch status {
				case contract.KeyStatusActive, contract.KeyStatusRevoked:
					// allowed for non-root entries
				case contract.KeyStatusRoot:
					return fmt.Errorf("--include id=%q: status=root is reserved for the auto-included root entry", spec.ID)
				default:
					return fmt.Errorf("--include id=%q: unknown status %q (allowed: active, revoked)", spec.ID, status)
				}

				keys = append(keys, contract.KeyInfo{
					KeyID:        spec.ID,
					KeyPurpose:   spec.Purpose,
					PublicKeyHex: hex.EncodeToString(pubBytes),
					ValidFrom:    now,
					ValidUntil:   nil,
					Status:       status,
					Principal:    spec.Role,
				})
			}

			body := contract.KeyRoster{
				SchemaVersion:  schemaVersion,
				RosterSignedBy: rootFile.KeyID,
				Keys:           keys,
				DataClassRoot:  dataClass,
			}
			if err := body.Validate(); err != nil {
				return fmt.Errorf("roster body validation: %w", err)
			}

			preimage, err := body.SignablePreimage()
			if err != nil {
				return fmt.Errorf("compute signable preimage: %w", err)
			}
			sig := ed25519.Sign(rootPriv, preimage)
			envelope := contract.RosterEnvelope{
				Body:      body,
				Signature: "ed25519:" + hex.EncodeToString(sig),
			}

			data, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal roster envelope: %w", err)
			}
			data = append(data, '\n')

			if err := atomicfile.Write(cleanOut, data, 0o600); err != nil {
				return fmt.Errorf("write roster: %w", err)
			}

			fp, err := domsigning.Fingerprint(rootPub)
			if err != nil {
				return fmt.Errorf("compute root fingerprint: %w", err)
			}
			_, _ = fmt.Fprintf(out, "Built signed roster\n")
			_, _ = fmt.Fprintf(out, "  keys:                %d\n", len(keys))
			_, _ = fmt.Fprintf(out, "  root_signed_by:      %s\n", rootFile.KeyID)
			_, _ = fmt.Fprintf(out, "  root_fingerprint:    %s\n", fp)
			_, _ = fmt.Fprintf(out, "  data_class_root:     %s\n", dataClass)
			_, _ = fmt.Fprintf(out, "  out:                 %s\n", cleanOut)
			return nil
		},
	}

	cmd.Flags().StringVar(&rootPath, "root", "", "path to root key JSON file (output of 'pipelock signing key generate --purpose roster-root')")
	cmd.Flags().StringArrayVar(&includes, "include", nil, "include entry as id=ID,key=PATH,purpose=PURPOSE[,status=STATUS][,role=ROLE]; repeatable")
	cmd.Flags().StringVar(&dataClass, "data-class", rosterDefaultDataClass, "data_class_root for the roster body (public, internal, or sensitive)")
	cmd.Flags().IntVar(&schemaVersion, "schema-version", rosterBuildSchemaVersion, "key_roster schema_version")
	cmd.Flags().StringVar(&outPath, "out", "", "absolute output path for the signed roster JSON")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing output file")
	_ = cmd.MarkFlagRequired("root")
	_ = cmd.MarkFlagRequired("include")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

// parseIncludeSpecs converts the repeatable --include strings into structured
// entries. Returns a typed error per malformed entry that names the offending
// flag value so the operator can correct it without grepping the source.
func parseIncludeSpecs(raw []string) ([]includeSpec, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("at least one --include is required")
	}
	out := make([]includeSpec, 0, len(raw))
	for i, entry := range raw {
		spec, err := parseIncludeSpec(entry)
		if err != nil {
			return nil, fmt.Errorf("--include[%d] %q: %w", i, entry, err)
		}
		out = append(out, spec)
	}
	return out, nil
}

// parseIncludeSpec parses one comma-separated key=value entry. Required keys:
// id, key, purpose. Optional: status, role. Unknown keys reject so a
// fat-fingered operator does not silently lose data. Duplicate keys also
// reject; otherwise "id=A,id=B" silently wins B and the operator-intended
// roster differs from what got signed.
func parseIncludeSpec(entry string) (includeSpec, error) {
	var spec includeSpec
	seen := make(map[string]struct{}, 5)
	for _, raw := range strings.Split(entry, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			return includeSpec{}, fmt.Errorf("expected key=value, got %q", raw)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if _, dup := seen[k]; dup {
			return includeSpec{}, fmt.Errorf("duplicate key %q", k)
		}
		seen[k] = struct{}{}
		switch k {
		case "id":
			spec.ID = v
		case "key":
			spec.KeyPath = v
		case "purpose":
			spec.Purpose = v
		case "status":
			spec.Status = v
		case "role":
			spec.Role = v
		default:
			return includeSpec{}, fmt.Errorf("unknown key %q (allowed: id, key, purpose, status, role)", k)
		}
	}
	if spec.ID == "" {
		return includeSpec{}, fmt.Errorf("missing required field id")
	}
	if spec.KeyPath == "" {
		return includeSpec{}, fmt.Errorf("missing required field key")
	}
	if spec.Purpose == "" {
		return includeSpec{}, fmt.Errorf("missing required field purpose")
	}
	return spec, nil
}
