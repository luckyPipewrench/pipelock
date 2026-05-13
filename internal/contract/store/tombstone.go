// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const tombstoneDirname = "tombstones"

var (
	// ErrContractTombstoned signals that a manifest references a contract
	// hash for which a signed tombstone exists. Re-promoting a tombstoned
	// hash is rejected at activation time.
	ErrContractTombstoned = errors.New("contract store: prior contract is tombstoned and cannot be re-promoted")

	// ErrTombstoneSignature signals that a stored tombstone failed
	// signature verification or structural validation during load. Bad
	// tombstones are a hard error rather than a silent skip so a forged
	// or corrupted tombstone file cannot mask a re-promotion attempt.
	ErrTombstoneSignature = errors.New("contract store: tombstone signature invalid")

	// ErrTombstoneDecode signals that a tombstone file could not be
	// parsed via strict decoding.
	ErrTombstoneDecode = errors.New("contract store: tombstone decode failed")
)

// PutTombstone records a signed tombstone for a prior contract hash. The
// tombstone body is decoded strictly (JSON), structurally validated,
// signature-verified against the activation-signing roster, and written
// write-once to <root>/tombstones/sha256-<hex>.json. Returns the
// prior_contract_hash on success.
func (s Store) PutTombstone(raw []byte, opts Options) (string, error) {
	env, err := decodeTombstone(raw)
	if err != nil {
		return "", err
	}
	if err := env.Body.Validate(); err != nil {
		return "", fmt.Errorf("%w: tombstone: %w", ErrStructural, err)
	}
	if err := validateHash(env.Body.PriorContractHash); err != nil {
		return "", fmt.Errorf("%w: tombstone prior_contract_hash: %w", ErrStructural, err)
	}
	if err := verifyTombstoneSignature(env, opts); err != nil {
		return "", err
	}
	path, err := s.tombstonePath(env.Body.PriorContractHash)
	if err != nil {
		return "", err
	}
	if err := s.withLock(func() error {
		return writeOnce(path, append(bytes.TrimSpace(raw), '\n'))
	}); err != nil {
		return "", err
	}
	return env.Body.PriorContractHash, nil
}

// LoadTombstone returns the signed tombstone for priorContractHash. If no
// tombstone exists, returns (TombstoneEnvelope{}, false, nil). The canonical
// store object is JSON; legacy learn-forget YAML tombstones are also accepted
// so existing operator evidence in tombstones/ is enforced. Any decode or
// signature error is fail-closed: the caller cannot trust this hash to be
// either tombstoned or clean, so validation must refuse to proceed.
func (s Store) LoadTombstone(priorContractHash string, opts Options) (contract.TombstoneEnvelope, bool, error) {
	if err := validateHash(priorContractHash); err != nil {
		return contract.TombstoneEnvelope{}, false, err
	}
	candidates, err := s.tombstoneCandidates(priorContractHash)
	if err != nil {
		return contract.TombstoneEnvelope{}, false, err
	}
	for _, candidate := range candidates {
		raw, err := readFile(candidate.path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return contract.TombstoneEnvelope{}, false, fmt.Errorf("%w: read tombstone: %w", ErrTombstoneDecode, err)
		}
		env, err := candidate.decode(raw)
		if err != nil {
			return contract.TombstoneEnvelope{}, false, err
		}
		if err := validateLoadedTombstone(env, priorContractHash, opts); err != nil {
			return contract.TombstoneEnvelope{}, false, err
		}
		return env, true, nil
	}
	return contract.TombstoneEnvelope{}, false, nil
}

func validateLoadedTombstone(env contract.TombstoneEnvelope, priorContractHash string, opts Options) error {
	if err := env.Body.Validate(); err != nil {
		return fmt.Errorf("%w: tombstone: %w", ErrStructural, err)
	}
	if env.Body.PriorContractHash != priorContractHash {
		return fmt.Errorf("%w: tombstone body prior_contract_hash %q does not match filename hash %q",
			ErrTombstoneSignature, env.Body.PriorContractHash, priorContractHash)
	}
	if err := verifyTombstoneSignature(env, opts); err != nil {
		return err
	}
	return nil
}

// tombstoneCheck rejects a manifest whose selectors reference any
// contract hash for which a valid signed tombstone exists. Called from
// ValidateEnvelope after signature + contract-history resolution so the
// tombstone cross-check is the last gate before acceptance.
func (s Store) tombstoneCheck(selectors []contract.ManifestSelector, opts Options) error {
	for _, selector := range selectors {
		env, found, err := s.LoadTombstone(selector.ContractHash, opts)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		return fmt.Errorf("%w: selector_id=%q contract_hash=%s redacted_at=%q authorization=%q signer_key_id=%q",
			ErrContractTombstoned,
			selector.SelectorID,
			env.Body.PriorContractHash,
			env.Body.RedactedAt,
			env.Body.RedactionAuthorizationID,
			env.Body.SignerKeyID,
		)
	}
	return nil
}

// decodeTombstone parses a signed tombstone envelope from JSON. Tombstone
// records on disk are JSON-encoded (consistent with the manifest store);
// the operator-facing tools accept YAML on input but normalize to JSON
// before calling PutTombstone. LoadTombstone also accepts legacy YAML
// evidence files written by earlier learn-forget workflows.
func decodeTombstone(raw []byte) (contract.TombstoneEnvelope, error) {
	var env contract.TombstoneEnvelope
	if err := contract.DecodeStrictJSON(raw, &env); err != nil {
		return contract.TombstoneEnvelope{}, fmt.Errorf("%w: tombstone: %w", ErrTombstoneDecode, err)
	}
	return env, nil
}

func decodeTombstoneYAML(raw []byte) (contract.TombstoneEnvelope, error) {
	var env contract.TombstoneEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		return contract.TombstoneEnvelope{}, fmt.Errorf("%w: tombstone: %w", ErrTombstoneDecode, err)
	}
	return env, nil
}

// verifyTombstoneSignature checks the detached signature on a tombstone
// envelope against the activation-signing roster. Tombstones share the
// contract-activation-signing key purpose with active-manifest signers:
// the operator authority to mint a tombstone is the same authority that
// promotes contracts in the first place. A bad signature is a hard
// error, not a silent skip, because a forged tombstone file would
// otherwise let an attacker either DoS legitimate manifests or hide an
// authentic tombstone behind a corrupted one.
func verifyTombstoneSignature(env contract.TombstoneEnvelope, opts Options) error {
	if opts.Roster == nil {
		return fmt.Errorf("%w: roster is required", ErrTombstoneSignature)
	}
	if env.Body.KeyPurpose != signing.PurposeContractActivationSigning.String() {
		return fmt.Errorf("%w: key_id=%q purpose=%q", ErrTombstoneSignature, env.Body.SignerKeyID, env.Body.KeyPurpose)
	}
	key, err := opts.Roster.ResolveKey(env.Body.SignerKeyID, now(opts))
	if err != nil {
		return fmt.Errorf("%w: key_id=%q: %w", ErrTombstoneSignature, env.Body.SignerKeyID, err)
	}
	if key.KeyPurpose != signing.PurposeContractActivationSigning.String() {
		return fmt.Errorf("%w: key_id=%q roster purpose=%q", ErrTombstoneSignature, env.Body.SignerKeyID, key.KeyPurpose)
	}
	sigBytes, err := parseSignature(env.Signature)
	if err != nil {
		return fmt.Errorf("%w: key_id=%q: %w", ErrTombstoneSignature, env.Body.SignerKeyID, err)
	}
	pub, err := hex.DecodeString(key.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("%w: key_id=%q public key: %w", ErrTombstoneSignature, env.Body.SignerKeyID, err)
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("%w: tombstone preimage: %w", ErrTombstoneSignature, err)
	}
	if !contract.VerifyEd25519PureEdDSA(pub, preimage, sigBytes) {
		return fmt.Errorf("%w: key_id=%q", ErrTombstoneSignature, env.Body.SignerKeyID)
	}
	return nil
}

func (s Store) tombstoneDir() string {
	return filepath.Join(s.root, tombstoneDirname)
}

func (s Store) tombstonePath(priorContractHash string) (string, error) {
	return objectPath(s.tombstoneDir(), priorContractHash, jsonExt)
}

func (s Store) legacyTombstonePath(priorContractHash string) (string, error) {
	return objectPath(s.tombstoneDir(), priorContractHash, ".tombstone.yaml")
}

type tombstoneCandidate struct {
	path   string
	decode func([]byte) (contract.TombstoneEnvelope, error)
}

func (s Store) tombstoneCandidates(priorContractHash string) ([]tombstoneCandidate, error) {
	jsonPath, err := s.tombstonePath(priorContractHash)
	if err != nil {
		return nil, err
	}
	legacyPath, err := s.legacyTombstonePath(priorContractHash)
	if err != nil {
		return nil, err
	}
	return []tombstoneCandidate{
		{path: jsonPath, decode: decodeTombstone},
		{path: legacyPath, decode: decodeTombstoneYAML},
	}, nil
}
