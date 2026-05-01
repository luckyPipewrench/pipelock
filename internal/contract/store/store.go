// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package store loads and persists signed active contract manifests.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var (
	readFile = os.ReadFile
	readDir  = os.ReadDir
	mkdirAll = os.MkdirAll
	openFile = func(name string, flag int, perm os.FileMode) (writableFile, error) {
		return os.OpenFile(filepath.Clean(name), flag, perm)
	}
	atomicWrite = atomicfile.Write
	marshalJSON = json.Marshal
)

type writableFile interface {
	Write([]byte) (int, error)
	Close() error
}

const (
	defaultMinSignatures = 1
	dirPerm              = 0o750
	filePerm             = 0o600

	activeFilename  = "active.json"
	historyDirname  = "history"
	manifestDirname = "manifests"
	journalFilename = ".activation_journal.jsonl"

	hashPrefix      = "sha256:"
	hashFilePrefix  = "sha256-"
	jsonExt         = ".json"
	yamlExt         = ".yaml"
	signaturePrefix = "ed25519:"
)

var (
	ErrDecode              = errors.New("contract store: decode failed")
	ErrStructural          = errors.New("contract store: structural validation failed")
	ErrSignature           = errors.New("contract store: manifest signature invalid")
	ErrContractSignature   = errors.New("contract store: contract signature invalid")
	ErrDualControl         = errors.New("contract store: dual control requirement not met")
	ErrEnvironmentMismatch = errors.New("contract store: manifest environment mismatch")
	ErrGeneration          = errors.New("contract store: manifest generation is not monotonic")
	ErrPriorManifest       = errors.New("contract store: prior manifest hash mismatch")
	ErrContractHistory     = errors.New("contract store: contract history invalid")
	ErrWriteOnceConflict   = errors.New("contract store: write-once object already exists with different bytes")
	ErrNoActiveManifest    = errors.New("contract store: active manifest does not exist")
)

// Store is rooted at the contracts directory.
type Store struct {
	root string
}

// New returns a Store rooted at dir.
func New(dir string) Store {
	return Store{root: filepath.Clean(dir)}
}

// Options controls manifest reload validation.
type Options struct {
	Environment        contract.Environment
	Roster             *signing.LoadedRoster
	PreviousHash       string
	PreviousGeneration uint64
	MinSignatures      int
	ReadOnly           bool
	Now                func() time.Time
}

// State is the accepted manifest and resolved contract set.
type State struct {
	Envelope     contract.ActiveManifestEnvelope
	ManifestHash string
	Contracts    map[string]contract.ContractEnvelope
	AcceptedPath string
}

// JournalEntry is appended for accepted and rejected reload attempts.
type JournalEntry struct {
	Timestamp         time.Time `json:"ts"`
	Outcome           string    `json:"outcome"`
	ManifestHash      string    `json:"manifest_hash,omitempty"`
	Generation        uint64    `json:"generation,omitempty"`
	PriorManifestHash string    `json:"prior_manifest_hash,omitempty"`
	Reason            string    `json:"reason,omitempty"`
	SignerKeyIDs      []string  `json:"signer_key_ids,omitempty"`
}

// Reload validates active.json and returns the accepted state. If validation
// fails, the caller keeps its previous in-memory state.
func (s Store) Reload(opts Options) (State, error) {
	var state State
	err := s.withLock(func() error {
		raw, err := readFile(s.activePath())
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: %w", ErrNoActiveManifest, err)
			}
			return fmt.Errorf("%w: read active manifest: %w", ErrDecode, err)
		}
		accepted, err := s.ValidateEnvelope(raw, opts)
		if err != nil {
			if !opts.ReadOnly {
				// Audit write failures do not hide the validation failure.
				_ = s.appendJournalLocked(JournalEntry{
					Timestamp: now(opts),
					Outcome:   "rejected",
					Reason:    err.Error(),
				})
			}
			return err
		}
		acceptedPath := ""
		if !opts.ReadOnly {
			encoded, encErr := encodeForStorage(accepted.Envelope)
			if encErr != nil {
				return encErr
			}
			path, pathErr := s.manifestPath(accepted.ManifestHash)
			if pathErr != nil {
				return pathErr
			}
			if writeErr := writeOnce(path, encoded); writeErr != nil {
				return writeErr
			}
			if journalErr := s.appendJournalLocked(JournalEntry{
				Timestamp:         now(opts),
				Outcome:           "accepted",
				ManifestHash:      accepted.ManifestHash,
				Generation:        accepted.Envelope.Body.Generation,
				PriorManifestHash: accepted.Envelope.Body.PriorManifestHash,
				SignerKeyIDs:      signerKeyIDs(accepted.Envelope.Signatures),
			}); journalErr != nil {
				return journalErr
			}
			acceptedPath = path
		}
		state = State{
			Envelope:     accepted.Envelope,
			ManifestHash: accepted.ManifestHash,
			Contracts:    accepted.Contracts,
			AcceptedPath: acceptedPath,
		}
		return nil
	})
	if err != nil {
		return State{}, err
	}
	return state, nil
}

// ValidateEnvelope runs strict decode, signature checks, CAS checks, and
// contract-history resolution without mutating store files.
func (s Store) ValidateEnvelope(raw []byte, opts Options) (State, error) {
	var env contract.ActiveManifestEnvelope
	if err := contract.DecodeStrictJSON(raw, &env); err != nil {
		return State{}, fmt.Errorf("%w: active manifest: %w", ErrDecode, err)
	}
	if err := env.Body.Validate(); err != nil {
		return State{}, fmt.Errorf("%w: active manifest: %w", ErrStructural, err)
	}
	hash, err := ActiveManifestHash(env.Body)
	if err != nil {
		return State{}, err
	}
	if err := verifyEnvironment(env.Body.Environment, opts.Environment); err != nil {
		return State{}, err
	}
	if env.Body.Generation <= opts.PreviousGeneration {
		return State{}, fmt.Errorf("%w: got %d, previous %d", ErrGeneration, env.Body.Generation, opts.PreviousGeneration)
	}
	if opts.PreviousHash != "" && env.Body.PriorManifestHash != opts.PreviousHash {
		return State{}, fmt.Errorf("%w: got %q, want %q", ErrPriorManifest, env.Body.PriorManifestHash, opts.PreviousHash)
	}
	if err := verifyManifestSignatures(env, opts); err != nil {
		return State{}, err
	}
	contracts, err := s.loadContracts(env.Body.Selectors, opts)
	if err != nil {
		return State{}, err
	}
	return State{Envelope: env, ManifestHash: hash, Contracts: contracts}, nil
}

// WriteActive validates and atomically writes active.json. The advisory lock
// serializes local same-host writers so the prior-manifest check is not stale.
func (s Store) WriteActive(raw []byte, opts Options) (string, error) {
	var manifestHash string
	err := s.withLock(func() error {
		lockedOpts := opts
		current, err := s.currentActiveLocked(opts)
		if err != nil && !errors.Is(err, ErrNoActiveManifest) {
			return err
		}
		if err == nil {
			lockedOpts.PreviousHash = current.ManifestHash
			lockedOpts.PreviousGeneration = current.Envelope.Body.Generation
		}
		state, err := s.ValidateEnvelope(raw, lockedOpts)
		if err != nil {
			return err
		}
		manifestHash = state.ManifestHash
		if err := mkdirAll(s.root, dirPerm); err != nil {
			return fmt.Errorf("create contract store root: %w", err)
		}
		if err := atomicWrite(s.activePath(), append(bytes.TrimSpace(raw), '\n'), filePerm); err != nil {
			return fmt.Errorf("write active manifest: %w", err)
		}
		return nil
	})
	return manifestHash, err
}

// PutHistoryContract stores a signed contract envelope by its contract_hash.
func (s Store) PutHistoryContract(raw []byte, opts Options) (string, error) {
	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(raw, &env); err != nil {
		return "", fmt.Errorf("%w: contract history: %w", ErrDecode, err)
	}
	hash, err := ContractHash(env.Body)
	if err != nil {
		return "", err
	}
	if env.Body.ContractHash != hash {
		return "", fmt.Errorf("%w: contract_hash got %q, computed %q", ErrContractHistory, env.Body.ContractHash, hash)
	}
	if err := env.Body.Validate(); err != nil {
		return "", fmt.Errorf("%w: contract: %w", ErrStructural, err)
	}
	if err := verifyContractSignature(env, opts); err != nil {
		return "", err
	}
	path, err := s.historyPath(hash)
	if err != nil {
		return "", err
	}
	if err := s.withLock(func() error {
		return writeOnce(path, append(bytes.TrimSpace(raw), '\n'))
	}); err != nil {
		return "", err
	}
	return hash, nil
}

// LatestAccepted returns the highest-generation immutable accepted manifest.
func (s Store) LatestAccepted(opts Options) (State, error) {
	entries, err := readDir(s.manifestDir())
	if err != nil {
		return State{}, fmt.Errorf("read accepted manifests: %w", err)
	}
	candidates := map[string]acceptedManifest{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), hashFilePrefix) || !strings.HasSuffix(entry.Name(), jsonExt) {
			continue
		}
		candidate, err := s.loadAcceptedManifestFile(filepath.Join(s.manifestDir(), entry.Name()), entry.Name(), opts)
		if err != nil {
			return State{}, err
		}
		candidates[candidate.hash] = candidate
	}
	var latest acceptedManifest
	for hash, candidate := range candidates {
		if err := s.acceptedChainContinuous(hash, candidates, opts, map[string]struct{}{}); err != nil {
			continue
		}
		if candidate.env.Body.Generation > latest.env.Body.Generation {
			latest = candidate
		}
	}
	if latest.hash == "" {
		return State{}, os.ErrNotExist
	}
	contracts, err := s.loadContracts(latest.env.Body.Selectors, opts)
	if err != nil {
		return State{}, err
	}
	return State{
		Envelope:     latest.env,
		ManifestHash: latest.hash,
		Contracts:    contracts,
		AcceptedPath: latest.path,
	}, nil
}

// Accepted returns an immutable accepted manifest by manifest hash.
func (s Store) Accepted(hash string, opts Options) (State, error) {
	accepted, err := s.loadAcceptedManifestByHash(hash, opts)
	if err != nil {
		return State{}, err
	}
	if err := s.acceptedChainContinuous(hash, map[string]acceptedManifest{hash: accepted}, opts, map[string]struct{}{}); err != nil {
		return State{}, err
	}
	contracts, err := s.loadContracts(accepted.env.Body.Selectors, opts)
	if err != nil {
		return State{}, err
	}
	return State{
		Envelope:     accepted.env,
		ManifestHash: accepted.hash,
		Contracts:    contracts,
		AcceptedPath: accepted.path,
	}, nil
}

type acceptedManifest struct {
	env  contract.ActiveManifestEnvelope
	hash string
	path string
}

func (s Store) loadAcceptedManifestFile(path, filename string, opts Options) (acceptedManifest, error) {
	raw, err := readFile(path)
	if err != nil {
		return acceptedManifest{}, fmt.Errorf("read accepted manifest: %w", err)
	}
	var env contract.ActiveManifestEnvelope
	if err := contract.DecodeStrictJSON(raw, &env); err != nil {
		return acceptedManifest{}, fmt.Errorf("%w: accepted manifest: %w", ErrDecode, err)
	}
	if err := env.Body.Validate(); err != nil {
		return acceptedManifest{}, fmt.Errorf("%w: accepted manifest: %w", ErrStructural, err)
	}
	hash, err := ActiveManifestHash(env.Body)
	if err != nil {
		return acceptedManifest{}, err
	}
	expectedName, err := hashFilename(hash, jsonExt)
	if err != nil {
		return acceptedManifest{}, err
	}
	if expectedName != filename {
		return acceptedManifest{}, fmt.Errorf("%w: accepted manifest filename/hash mismatch", ErrContractHistory)
	}
	if err := verifyEnvironment(env.Body.Environment, opts.Environment); err != nil {
		return acceptedManifest{}, err
	}
	if err := verifyManifestSignatures(env, opts); err != nil {
		return acceptedManifest{}, err
	}
	acceptedPath, err := s.manifestPath(hash)
	if err != nil {
		return acceptedManifest{}, err
	}
	return acceptedManifest{env: env, hash: hash, path: acceptedPath}, nil
}

func (s Store) acceptedChainContinuous(hash string, candidates map[string]acceptedManifest, opts Options, visiting map[string]struct{}) error {
	candidate, ok := candidates[hash]
	if !ok {
		loaded, err := s.loadAcceptedManifestByHash(hash, opts)
		if err != nil {
			return err
		}
		candidate = loaded
		candidates[hash] = loaded
	}
	if _, ok := visiting[hash]; ok {
		return fmt.Errorf("%w: accepted manifest prior chain cycle at %s", ErrContractHistory, hash)
	}
	visiting[hash] = struct{}{}
	defer delete(visiting, hash)

	if candidate.env.Body.Generation <= 1 {
		return nil
	}
	prior := candidate.env.Body.PriorManifestHash
	if err := validateHash(prior); err != nil {
		return fmt.Errorf("%w: generation %d prior manifest %q is not an accepted hash",
			ErrContractHistory, candidate.env.Body.Generation, prior)
	}
	priorCandidate, ok := candidates[prior]
	if !ok {
		loaded, err := s.loadAcceptedManifestByHash(prior, opts)
		if err != nil {
			return fmt.Errorf("%w: prior manifest %s: %w", ErrContractHistory, prior, err)
		}
		priorCandidate = loaded
		candidates[prior] = loaded
	}
	if priorCandidate.env.Body.Generation >= candidate.env.Body.Generation {
		return fmt.Errorf("%w: prior generation %d is not below %d",
			ErrContractHistory, priorCandidate.env.Body.Generation, candidate.env.Body.Generation)
	}
	return s.acceptedChainContinuous(prior, candidates, opts, visiting)
}

func (s Store) loadAcceptedManifestByHash(hash string, opts Options) (acceptedManifest, error) {
	path, err := s.manifestPath(hash)
	if err != nil {
		return acceptedManifest{}, err
	}
	name, err := hashFilename(hash, jsonExt)
	if err != nil {
		return acceptedManifest{}, err
	}
	return s.loadAcceptedManifestFile(path, name, opts)
}

// ActiveManifestHash returns sha256 over the manifest body's canonical preimage.
func ActiveManifestHash(m contract.ActiveManifest) (string, error) {
	preimage, err := m.SignablePreimage()
	if err != nil {
		return "", fmt.Errorf("manifest preimage: %w", err)
	}
	sum := sha256.Sum256(preimage)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}

// ContractHash returns sha256 over the canonical contract body with
// contract_hash cleared, matching the compiler's signed body hash.
func ContractHash(c contract.Contract) (string, error) {
	c.ContractHash = ""
	preimage, err := c.SignablePreimage()
	if err != nil {
		return "", fmt.Errorf("contract preimage: %w", err)
	}
	sum := sha256.Sum256(preimage)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}

func (s Store) loadContracts(selectors []contract.ManifestSelector, opts Options) (map[string]contract.ContractEnvelope, error) {
	out := make(map[string]contract.ContractEnvelope, len(selectors))
	for _, selector := range selectors {
		path, err := s.historyPath(selector.ContractHash)
		if err != nil {
			return nil, err
		}
		raw, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: read %s: %w", ErrContractHistory, selector.ContractHash, err)
		}
		var env contract.ContractEnvelope
		if err := contract.DecodeStrictYAML(raw, &env); err != nil {
			return nil, fmt.Errorf("%w: decode %s: %w", ErrDecode, selector.ContractHash, err)
		}
		hash, err := ContractHash(env.Body)
		if err != nil {
			return nil, err
		}
		if env.Body.ContractHash != selector.ContractHash || hash != selector.ContractHash {
			return nil, fmt.Errorf("%w: selector %q points to %q, body has %q computed %q",
				ErrContractHistory, selector.SelectorID, selector.ContractHash, env.Body.ContractHash, hash)
		}
		if err := env.Body.Validate(); err != nil {
			return nil, fmt.Errorf("%w: contract %s: %w", ErrStructural, selector.ContractHash, err)
		}
		if err := verifyContractSignature(env, opts); err != nil {
			return nil, err
		}
		out[selector.SelectorID] = env
	}
	return out, nil
}

func (s Store) currentActiveLocked(opts Options) (State, error) {
	raw, err := readFile(s.activePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return State{}, fmt.Errorf("%w: %w", ErrNoActiveManifest, err)
		}
		return State{}, fmt.Errorf("%w: read active manifest: %w", ErrDecode, err)
	}
	currentOpts := opts
	currentOpts.PreviousHash = ""
	currentOpts.PreviousGeneration = 0
	return s.ValidateEnvelope(raw, currentOpts)
}

func verifyManifestSignatures(env contract.ActiveManifestEnvelope, opts Options) error {
	if opts.Roster == nil {
		return fmt.Errorf("%w: roster is required", ErrSignature)
	}
	required := opts.MinSignatures
	if required <= 0 {
		required = defaultMinSignatures
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("manifest preimage: %w", err)
	}
	nowTime := now(opts)
	seenPrincipals := map[string]struct{}{}
	seenKeys := map[string]struct{}{}
	valid := 0
	for _, sig := range env.Signatures {
		if sig.KeyPurpose != signing.PurposeContractActivationSigning.String() {
			return fmt.Errorf("%w: key_id=%q purpose=%q", ErrSignature, sig.KeyID, sig.KeyPurpose)
		}
		if sig.Algorithm != "ed25519" {
			return fmt.Errorf("%w: key_id=%q algorithm=%q", ErrSignature, sig.KeyID, sig.Algorithm)
		}
		key, err := opts.Roster.ResolveKey(sig.KeyID, nowTime)
		if err != nil {
			return fmt.Errorf("%w: key_id=%q: %w", ErrSignature, sig.KeyID, err)
		}
		if key.KeyPurpose != signing.PurposeContractActivationSigning.String() {
			return fmt.Errorf("%w: key_id=%q roster purpose=%q", ErrSignature, sig.KeyID, key.KeyPurpose)
		}
		if key.Principal == "" {
			return fmt.Errorf("%w: key_id=%q missing activation principal", ErrSignature, sig.KeyID)
		}
		if sig.Principal != "" && key.Principal != "" && sig.Principal != key.Principal {
			return fmt.Errorf("%w: key_id=%q principal mismatch", ErrSignature, sig.KeyID)
		}
		sigBytes, err := parseSignature(sig.Signature)
		if err != nil {
			return fmt.Errorf("%w: key_id=%q: %w", ErrSignature, sig.KeyID, err)
		}
		pub, err := hex.DecodeString(key.PublicKeyHex)
		if err != nil {
			return fmt.Errorf("%w: key_id=%q public key: %w", ErrSignature, sig.KeyID, err)
		}
		if !contract.VerifyEd25519PureEdDSA(pub, preimage, sigBytes) {
			return fmt.Errorf("%w: key_id=%q", ErrSignature, sig.KeyID)
		}
		if _, dup := seenKeys[sig.KeyID]; dup {
			continue
		}
		principal := key.Principal
		if _, dup := seenPrincipals[principal]; dup {
			continue
		}
		seenKeys[sig.KeyID] = struct{}{}
		seenPrincipals[principal] = struct{}{}
		valid++
	}
	if valid < required {
		return fmt.Errorf("%w: got %d valid distinct signatures, want %d", ErrDualControl, valid, required)
	}
	return nil
}

func verifyContractSignature(env contract.ContractEnvelope, opts Options) error {
	if opts.Roster == nil {
		return fmt.Errorf("%w: roster is required", ErrContractSignature)
	}
	if env.Body.KeyPurpose != signing.PurposeContractCompileSigning.String() {
		return fmt.Errorf("%w: key_id=%q purpose=%q", ErrContractSignature, env.Body.SignerKeyID, env.Body.KeyPurpose)
	}
	key, err := opts.Roster.ResolveKey(env.Body.SignerKeyID, now(opts))
	if err != nil {
		return fmt.Errorf("%w: key_id=%q: %w", ErrContractSignature, env.Body.SignerKeyID, err)
	}
	if key.KeyPurpose != signing.PurposeContractCompileSigning.String() {
		return fmt.Errorf("%w: key_id=%q roster purpose=%q", ErrContractSignature, env.Body.SignerKeyID, key.KeyPurpose)
	}
	sigBytes, err := parseSignature(env.Signature)
	if err != nil {
		return fmt.Errorf("%w: key_id=%q: %w", ErrContractSignature, env.Body.SignerKeyID, err)
	}
	pub, err := hex.DecodeString(key.PublicKeyHex)
	if err != nil {
		return fmt.Errorf("%w: key_id=%q public key: %w", ErrContractSignature, env.Body.SignerKeyID, err)
	}
	preimage, err := env.Body.SignablePreimage()
	if err != nil {
		return fmt.Errorf("%w: contract preimage: %w", ErrContractSignature, err)
	}
	if !contract.VerifyEd25519PureEdDSA(pub, preimage, sigBytes) {
		return fmt.Errorf("%w: key_id=%q", ErrContractSignature, env.Body.SignerKeyID)
	}
	return nil
}

func verifyEnvironment(got, want contract.Environment) error {
	if want == (contract.Environment{}) {
		return nil
	}
	if got != want {
		return fmt.Errorf("%w: got %+v want %+v", ErrEnvironmentMismatch, got, want)
	}
	return nil
}

func writeOnce(path string, data []byte) error {
	path = filepath.Clean(path)
	if err := mkdirAll(filepath.Dir(path), dirPerm); err != nil {
		return fmt.Errorf("create store directory: %w", err)
	}
	existing, err := readFile(path)
	if err == nil {
		if bytes.Equal(existing, data) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrWriteOnceConflict, path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read write-once object: %w", err)
	}
	if err := atomicWrite(path, data, filePerm); err != nil {
		return fmt.Errorf("write write-once object: %w", err)
	}
	return nil
}

func (s Store) appendJournalLocked(entry JournalEntry) error {
	if err := mkdirAll(s.root, dirPerm); err != nil {
		return fmt.Errorf("create contract store root: %w", err)
	}
	raw, err := marshalJSON(entry)
	if err != nil {
		return fmt.Errorf("marshal activation journal entry: %w", err)
	}
	raw = append(raw, '\n')
	f, err := openFile(s.journalPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, filePerm)
	if err != nil {
		return fmt.Errorf("open activation journal: %w", err)
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return fmt.Errorf("write activation journal: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close activation journal: %w", err)
	}
	return nil
}

func encodeForStorage(v any) ([]byte, error) {
	raw, err := marshalJSON(v)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}
	return append(raw, '\n'), nil
}

func parseSignature(sig string) ([]byte, error) {
	if !strings.HasPrefix(sig, signaturePrefix) {
		return nil, fmt.Errorf("missing %q prefix", signaturePrefix)
	}
	hexPart := strings.TrimPrefix(sig, signaturePrefix)
	if len(hexPart) != 128 {
		return nil, fmt.Errorf("signature hex length %d, want 128", len(hexPart))
	}
	out, err := hex.DecodeString(hexPart)
	if err != nil {
		return nil, fmt.Errorf("signature hex decode: %w", err)
	}
	return out, nil
}

func (s Store) activePath() string {
	return filepath.Join(s.root, activeFilename)
}

func (s Store) manifestDir() string {
	return filepath.Join(s.root, manifestDirname)
}

func (s Store) manifestPath(hash string) (string, error) {
	return objectPath(s.manifestDir(), hash, jsonExt)
}

func (s Store) historyPath(hash string) (string, error) {
	return objectPath(filepath.Join(s.root, historyDirname), hash, yamlExt)
}

func (s Store) journalPath() string {
	return filepath.Join(s.root, journalFilename)
}

func objectPath(dir, hash, ext string) (string, error) {
	name, err := hashFilename(hash, ext)
	if err != nil {
		return "", err
	}
	cleanDir := filepath.Clean(dir)
	path := filepath.Join(cleanDir, name)
	rel, err := filepath.Rel(cleanDir, path)
	if err != nil {
		return "", fmt.Errorf("%w: object path: %w", ErrContractHistory, err)
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: object path escapes store root", ErrContractHistory)
	}
	return path, nil
}

func hashFilename(hash, ext string) (string, error) {
	if err := validateHash(hash); err != nil {
		return "", err
	}
	return hashFilePrefix + strings.TrimPrefix(hash, hashPrefix) + ext, nil
}

func validateHash(hash string) error {
	if !strings.HasPrefix(hash, hashPrefix) {
		return fmt.Errorf("%w: hash %q missing %q prefix", ErrContractHistory, hash, hashPrefix)
	}
	hexPart := strings.TrimPrefix(hash, hashPrefix)
	if len(hexPart) != 64 {
		return fmt.Errorf("%w: hash %q length %d, want 64 hex chars", ErrContractHistory, hash, len(hexPart))
	}
	for _, r := range hexPart {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return fmt.Errorf("%w: hash %q is not lowercase hex", ErrContractHistory, hash)
		}
	}
	return nil
}

func signerKeyIDs(sigs []contract.ManifestSignature) []string {
	out := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, sig.KeyID)
	}
	return out
}

func now(opts Options) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}
