// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	RecoverySealKind             = "recovery_seal"
	RecoverySealVersion          = 1
	recoverySealDomain           = "pipelock-recovery-seal-v1\x00"
	maxRecoveryInteger           = uint64(1<<53 - 1)
	FindingInvalidRecoverySeal   = "invalid_recovery_seal"
	FindingAttestedDiscontinuity = "attested_discontinuity"
)

// RecoverySeal attests an observed discontinuity, never uninterrupted history.
// It shares ChainLink's exclusive predecessor claim filename, but has its own
// schema and signature domain. An old strict link decoder rejects its kind.
// Paths are relative basenames so archives remain portable. The raw shard hash
// includes the damaged suffix; the complete-prefix and successor-open bindings
// prevent a signature-valid artifact from being replayed onto different runs.
type RecoverySeal struct {
	Kind                 string `json:"kind"`
	Version              int    `json:"version"`
	PredecessorSession   string `json:"predecessor_session"`
	Shard                string `json:"shard"`
	ShardSize            uint64 `json:"shard_size"`
	ShardSHA256          string `json:"shard_sha256"`
	DamageOffset         uint64 `json:"damage_offset"`
	LastGoodSeq          uint64 `json:"last_good_seq"`
	LastGoodHash         string `json:"last_good_hash"`
	PredecessorTailSeq   uint64 `json:"predecessor_tail_seq"`
	PredecessorTailHash  string `json:"predecessor_tail_hash"`
	PredecessorSignerKey string `json:"predecessor_signer_key"`
	SuccessorSession     string `json:"successor_session"`
	SuccessorSignerKey   string `json:"successor_signer_key"`
	SuccessorOpenHash    string `json:"successor_open_hash"`
	ObservedAt           string `json:"observed_at"`
	Signature            string `json:"signature,omitempty"`
}

func validateRecoverySeal(s RecoverySeal) error {
	if s.Kind != RecoverySealKind || s.Version != RecoverySealVersion {
		return errors.New("unsupported recovery seal kind or version")
	}
	for _, session := range []string{s.PredecessorSession, s.SuccessorSession} {
		if strings.TrimSpace(session) == "" || strings.ContainsAny(session, `/\`) || !utf8.ValidString(session) {
			return errors.New("invalid recovery seal session")
		}
	}
	base, ok := RunSessionBase(s.SuccessorSession)
	if !ok || !isBaseChain(s.PredecessorSession, base) || s.PredecessorSession == s.SuccessorSession {
		return errors.New("recovery seal must bind distinct sessions of one base")
	}
	shardSession, _, valid := evidencename.Parse(s.Shard)
	if !valid || shardSession != s.PredecessorSession || strings.ContainsAny(s.Shard, `/\`) {
		return errors.New("recovery seal shard identity mismatch")
	}
	if s.ShardSize == 0 || s.DamageOffset >= s.ShardSize {
		return errors.New("invalid recovery seal damage offset")
	}
	for _, n := range []uint64{s.ShardSize, s.DamageOffset, s.LastGoodSeq, s.PredecessorTailSeq} {
		if n > maxRecoveryInteger {
			return errors.New("recovery seal integer exceeds v1 safe range")
		}
	}
	for _, h := range []string{s.ShardSHA256, s.SuccessorOpenHash} {
		if !validSHA256Hex(h) {
			return errors.New("invalid recovery seal hash")
		}
	}
	for _, h := range []string{s.LastGoodHash, s.PredecessorTailHash} {
		if h != GenesisHash && !validSHA256Hex(h) {
			return errors.New("invalid recovery seal head")
		}
	}
	if !validEd25519PublicKeyHex(s.PredecessorSignerKey) || !validEd25519PublicKeyHex(s.SuccessorSignerKey) {
		return errors.New("invalid recovery seal signer key")
	}
	t, err := time.Parse(time.RFC3339Nano, s.ObservedAt)
	if err != nil || t.IsZero() || s.ObservedAt != t.UTC().Format(time.RFC3339Nano) {
		return errors.New("recovery seal observed_at must be canonical UTC RFC3339Nano")
	}
	return nil
}

func recoverySealDigest(s RecoverySeal) ([]byte, error) {
	s.Signature = ""
	return canonicalArtifactBytes(recoverySealDomain, s)
}

// canonicalArtifactBytes uses the same ordered Go JSON and escape normalization
// as the existing signed predecessor link format.
func canonicalArtifactBytes(domain string, value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), jsonscan.NormalizeReplacementEscapes(b)...), nil
}

func SignRecoverySeal(s RecoverySeal, key ed25519.PrivateKey) (RecoverySeal, error) {
	if len(key) != ed25519.PrivateKeySize {
		return RecoverySeal{}, errors.New("invalid recovery seal private key")
	}
	s.Kind, s.Version, s.Signature = RecoverySealKind, RecoverySealVersion, ""
	s.SuccessorSignerKey = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := validateRecoverySeal(s); err != nil {
		return RecoverySeal{}, err
	}
	digest, err := recoverySealDigest(s)
	if err != nil {
		return RecoverySeal{}, err
	}
	s.Signature = signaturePrefix + hex.EncodeToString(ed25519.Sign(key, digest))
	return s, nil
}

func VerifyRecoverySeal(s RecoverySeal) error {
	if err := validateRecoverySeal(s); err != nil {
		return err
	}
	key, _ := hex.DecodeString(s.SuccessorSignerKey)
	sigHex, ok := strings.CutPrefix(s.Signature, signaturePrefix)
	sig, err := hex.DecodeString(sigHex)
	if !ok || err != nil || len(sig) != ed25519.SignatureSize || sigHex != strings.ToLower(sigHex) {
		return errors.New("invalid recovery seal signature format")
	}
	digest, err := recoverySealDigest(s)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, digest, sig) {
		return errors.New("recovery seal signature verification failed")
	}
	return nil
}

func UnmarshalRecoverySeal(raw []byte) (RecoverySeal, error) {
	if !utf8.Valid(raw) {
		return RecoverySeal{}, errors.New("recovery seal JSON is not UTF-8")
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return RecoverySeal{}, err
	}
	if err := rejectStructAliases(raw, reflect.TypeFor[RecoverySeal]()); err != nil {
		return RecoverySeal{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return RecoverySeal{}, err
	}
	t := reflect.TypeFor[RecoverySeal]()
	for i := 0; i < t.NumField(); i++ {
		name := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return RecoverySeal{}, fmt.Errorf("recovery seal field %s is required and non-null", name)
		}
	}
	var s RecoverySeal
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return RecoverySeal{}, err
	}
	if err := d.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return RecoverySeal{}, errors.New("recovery seal trailing tokens")
	}
	return s, VerifyRecoverySeal(s)
}

// observeRecovery validates all readable records, including a valid final JSON
// record missing its newline, while binding only the durable complete prefix.
func observeRecovery(dir, predecessor, observerKey string, trusted []string, maxBytes int64) (RecoverySeal, error) {
	return observeRecoveryWithOptions(dir, predecessor, observerKey, recoveryObservationOptions{trusted: trusted, maxBytes: maxBytes})
}

type recoveryObservationOptions struct {
	trusted        []string
	maxBytes       int64
	signaturesOnly bool
}

func observeRecoveryWithOptions(dir, predecessor, observerKey string, opts recoveryObservationOptions) (RecoverySeal, error) {
	trusted, maxBytes := opts.trusted, opts.maxBytes
	if len(trusted) == 0 {
		trusted = nil
	}
	files, err := recorderFiles(dir, predecessor)
	if err != nil || len(files) == 0 {
		return RecoverySeal{}, fmt.Errorf("recovery predecessor shards unavailable: %w", err)
	}
	v, err := newRecoveryPrefixVerifier(predecessor, trusted, opts.signaturesOnly)
	if err != nil {
		return RecoverySeal{}, err
	}
	s := RecoverySeal{PredecessorSession: predecessor, LastGoodHash: GenesisHash, PredecessorTailHash: GenesisHash, PredecessorSignerKey: observerKey}
	complete := func(e recorder.Entry) error {
		s.LastGoodSeq, s.LastGoodHash = e.Sequence, e.Hash
		if e.Type != recorderEntryType {
			return nil
		}
		r, err := receiptFromEntry(e)
		if err != nil {
			return err
		}
		s.PredecessorTailSeq, s.PredecessorSignerKey = r.ActionRecord.ChainSeq, r.SignerKey
		s.PredecessorTailHash, err = ReceiptHash(*r)
		return err
	}
	for _, f := range files[:len(files)-1] {
		validate := func(e recorder.Entry) error {
			if err := v.add(e); err != nil {
				return err
			}
			return complete(e)
		}
		if maxBytes > 0 {
			// Offline reads keep their independent per-shard ceiling. Only
			// this one bounded shard is retained, never the whole archive.
			raw, readErr := recorder.ReadEvidenceFileBounded(f, maxBytes)
			if readErr != nil {
				return RecoverySeal{}, readErr
			}
			es, readErr := recorder.ReadEntriesFromReader(bytes.NewReader(raw))
			if readErr != nil {
				return RecoverySeal{}, readErr
			}
			for _, e := range es {
				if err := validate(e); err != nil {
					return RecoverySeal{}, err
				}
			}
		} else if err := recorder.ValidateEvidenceFile(f, validate); err != nil {
			return RecoverySeal{}, err
		}
	}
	lastFile := files[len(files)-1]
	snapshot, err := recorder.CaptureTornEvidence(lastFile, maxBytes, v.add, complete)
	if err != nil {
		return RecoverySeal{}, err
	}
	if snapshot.Size < 0 || snapshot.Offset < 0 {
		return RecoverySeal{}, errors.New("invalid recovery snapshot bounds")
	}
	if err := v.finish(); err != nil {
		return RecoverySeal{}, err
	}
	s.Shard, s.ShardSize, s.ShardSHA256, s.DamageOffset = filepath.Base(lastFile), uint64(snapshot.Size), snapshot.SHA256, uint64(snapshot.Offset)
	return s, nil
}

// recoveryPrefixVerifier retains only the outer chain head and the receipt
// verifiers' walking state. A readable final record without LF advances this
// state, but never advances the independently captured durable heads.
type recoveryPrefixVerifier struct {
	session        string
	trusted        []string
	previous       *recorder.Entry
	v1             *StreamingVerifier
	v2             *contractreceipt.StreamingVerifier
	signaturesOnly bool
}

func newRecoveryPrefixVerifier(session string, trusted []string, signaturesOnly bool) (*recoveryPrefixVerifier, error) {
	if len(trusted) == 0 {
		trusted = nil
	}
	keys, err := normalizeTrustedKeys(trusted)
	if err != nil {
		return nil, err
	}
	newVerifier := func(integrityOnly bool) *chainVerifier {
		set := make(map[string]struct{}, len(keys))
		for _, k := range keys {
			set[k] = struct{}{}
		}
		return &chainVerifier{trusted: set, runNonces: make(map[string]string), closedRuns: make(map[string]bool), integrityOnly: integrityOnly}
	}
	return &recoveryPrefixVerifier{session: session, trusted: trusted, signaturesOnly: signaturesOnly, v1: &StreamingVerifier{v: newVerifier(false), integrity: newVerifier(true)}}, nil
}

func (v *recoveryPrefixVerifier) add(e recorder.Entry) error {
	if err := validateTailEntry(e, v.session, v.trusted); err != nil {
		return err
	}
	if err := recorder.ValidateEntrySchema(e); err != nil {
		return err
	}
	if v.previous == nil {
		if e.Sequence != 0 || e.PrevHash != recorder.GenesisHash {
			return errors.New("recovery recorder genesis mismatch")
		}
	} else {
		p := v.previous
		if p.Sequence == ^uint64(0) || e.Sequence != p.Sequence+1 || e.PrevHash != p.Hash {
			return errors.New("recovery recorder sequence or hash link mismatch")
		}
		if recorder.EntryVersionHasNamespace(e.Version) != recorder.EntryVersionHasNamespace(p.Version) || (recorder.EntryVersionHasNamespace(e.Version) && (e.ChainKind != p.ChainKind || e.WriterInstanceID != p.WriterInstanceID)) {
			return errors.New("recovery recorder namespace changed")
		}
	}
	// Retain only fields used by the next outer-chain check, not raw detail.
	v.previous = &recorder.Entry{Version: e.Version, Sequence: e.Sequence, Hash: e.Hash, ChainKind: e.ChainKind, WriterInstanceID: e.WriterInstanceID}
	if e.Type == recorderEntryType {
		raw, err := receiptBytesFromEntry(e)
		if err != nil {
			return err
		}
		if v.signaturesOnly {
			r, err := Unmarshal(raw)
			if err != nil {
				return err
			}
			// Diagnostic observation proves each segment's signatures and
			// placement without granting its signer operator authority. The
			// chain walks still require a valid transition to change curKey.
			v.v1.v.trusted = map[string]struct{}{r.SignerKey: {}}
			v.v1.integrity.trusted = map[string]struct{}{r.SignerKey: {}}
		}
		if err := v.v1.Add(raw); err != nil {
			return fmt.Errorf("recovery receipt prefix: %w", err)
		}
		if o := sessionOpen(v.v1.last.ActionRecord.SessionControl); o != nil && o.RecorderSession != v.session {
			return errors.New("recovery receipt session binding mismatch")
		}
	}
	// The shared extractor also rejects unknown recorder entry types and
	// preserves the original wire bytes required by secret-egress receipts.
	evidence, err := contractreceipt.ExtractEvidenceReceiptsFromEntries([]recorder.Entry{e})
	if err != nil {
		return err
	}
	if len(evidence) > 0 {
		if v.v2 == nil {
			key, err := decodeEd25519Hex(strings.ToLower(strings.TrimSpace(evidence[0].Signature.SignerKeyID)))
			if err != nil {
				return err
			}
			v.v2, err = contractreceipt.NewPinnedStreamingVerifier(key)
			if err != nil {
				return err
			}
		}
		raw, err := receiptBytesFromEntry(e)
		if err != nil {
			return err
		}
		if err := v.v2.AddRaw(raw); err != nil {
			return fmt.Errorf("recovery v2 prefix: %w", err)
		}
	}
	return nil
}

func (v *recoveryPrefixVerifier) finish() error {
	if v.v1.count > 0 {
		res := v.v1.Finish()
		if !res.Valid && (res.FailureKind != ChainFailureLifecycleOpen || !res.IntegrityVerified) {
			return fmt.Errorf("recovery receipt prefix: %s", res.Error)
		}
	}
	if v.v2 != nil {
		if res := v.v2.Finish(); !res.Valid {
			return fmt.Errorf("recovery v2 prefix: %s", res.Error)
		}
	}
	return nil
}

func verifyRecoveryPrefix(session string, entries []recorder.Entry, trusted []string) error {
	return verifyRecoveryPrefixWithOptions(session, entries, trusted, false)
}

func verifyRecoveryPrefixWithOptions(session string, entries []recorder.Entry, trusted []string, signaturesOnly bool) error {
	v, err := newRecoveryPrefixVerifier(session, trusted, signaturesOnly)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := v.add(e); err != nil {
			return err
		}
	}
	return v.finish()
}

// VerifyRecoveryBinding verifies the observation against the current archive,
// not just the artifact's embedded key. A valid result still means damage.
func VerifyRecoveryBinding(dir string, seal RecoverySeal, trusted []string) error {
	return verifyRecoveryBinding(dir, seal, trusted, false)
}

func verifyRecoveryBinding(dir string, seal RecoverySeal, trusted []string, signaturesOnly bool) error {
	if err := VerifyRecoverySeal(seal); err != nil {
		return err
	}
	got, err := observeRecoveryWithOptions(dir, seal.PredecessorSession, seal.SuccessorSignerKey, recoveryObservationOptions{trusted: trusted, maxBytes: recorder.MaxEvidenceReadFileBytes, signaturesOnly: signaturesOnly})
	if err != nil {
		return err
	}
	// This comparison is the replay barrier: signatures alone prove no placement.
	if got.Shard != seal.Shard || got.ShardSize != seal.ShardSize || got.ShardSHA256 != seal.ShardSHA256 || got.DamageOffset != seal.DamageOffset || got.LastGoodSeq != seal.LastGoodSeq || got.LastGoodHash != seal.LastGoodHash || got.PredecessorTailSeq != seal.PredecessorTailSeq || got.PredecessorTailHash != seal.PredecessorTailHash || got.PredecessorSignerKey != seal.PredecessorSignerKey {
		return errors.New("recovery seal shard or prefix binding mismatch")
	}
	entries, err := readSessionEntries(dir, seal.SuccessorSession)
	if err != nil {
		return err
	}
	if err := verifyRecoveryPrefixWithOptions(seal.SuccessorSession, entries, trusted, signaturesOnly); err != nil {
		return err
	}
	var first *Receipt
	for _, e := range entries {
		if e.Type != recorderEntryType {
			continue
		}
		first, err = receiptFromEntry(e)
		if err != nil {
			return err
		}
		break
	}
	if first == nil {
		return errors.New("recovery successor opening receipt unavailable")
	}
	open := sessionOpen(first.ActionRecord.SessionControl)
	hash, err := ReceiptHash(*first)
	if err != nil {
		return err
	}
	if open == nil || open.RecorderSession != seal.SuccessorSession || first.ActionRecord.ChainSeq != 0 || first.ActionRecord.ChainPrevHash != ComputeSessionOpenGenesis(*open) || first.SignerKey != seal.SuccessorSignerKey || hash != seal.SuccessorOpenHash {
		return errors.New("recovery seal successor opening binding mismatch")
	}
	return nil
}

func checkRecoveryClaims(dir, base string, claims []chainLinkRecord, data map[string]*baseChainData, opts BaseVerifyOptions, successors map[string][]string, add func(string, string, string)) {
	for _, claim := range claims {
		s := claim.seal
		if s == nil {
			continue
		}
		successors[s.PredecessorSession] = append(successors[s.PredecessorSession], s.SuccessorSession)
		fail := func(detail string) { add(FindingInvalidRecoverySeal, s.SuccessorSession, detail) }
		if claim.namePred != s.PredecessorSession || !isBaseChain(s.PredecessorSession, base) || !isBaseChain(s.SuccessorSession, base) {
			fail("recovery seal filename or base mismatch")
			continue
		}
		d := data[s.SuccessorSession]
		if d == nil || !d.chain.Valid || d.chain.Link != nil || d.chain.RecoverySeal != nil {
			fail("recovery successor unavailable, invalid, or already linked")
			continue
		}
		if !opts.LinksOnly && s.SuccessorSignerKey != s.PredecessorSignerKey && !slices.Contains(opts.TrustedKeys, s.SuccessorSignerKey) {
			fail("recovery successor key is not explicitly trusted")
			continue
		}
		trusted := opts.TrustedKeys
		if opts.LinksOnly {
			// Doctor checks signatures and placement, not operator key trust.
			trusted = nil
		}
		if err := verifyRecoveryBinding(dir, *s, trusted, opts.LinksOnly); err != nil {
			fail(err.Error())
			continue
		}
		d.chain.RecoverySeal = s
		add(FindingAttestedDiscontinuity, s.SuccessorSession, fmt.Sprintf("linked across attested discontinuity from %s: shard %s byte %d; evidence remains damaged", s.PredecessorSession, s.Shard, s.DamageOffset))
	}
}

func publishRecoverySeal(req linkRequest, predecessor string) (*RecoverySeal, error) {
	key := hex.EncodeToString(req.privKey.Public().(ed25519.PublicKey))
	s, err := observeRecoveryWithOptions(req.dir, predecessor, key, recoveryObservationOptions{trusted: req.signerKeys, signaturesOnly: req.signerKeys == nil})
	if err != nil {
		return nil, err
	}
	entries, err := readSessionEntries(req.dir, req.self)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Type != recorderEntryType {
			continue
		}
		r, readErr := receiptFromEntry(e)
		if readErr != nil {
			return nil, readErr
		}
		o := sessionOpen(r.ActionRecord.SessionControl)
		if o == nil || o.RecorderSession != req.self || r.ActionRecord.ChainSeq != 0 {
			return nil, errors.New("recovery requires a bound successor session_open")
		}
		// Apply the verifier's successor checks before signing, so a seal is
		// never published that every verifier would reject.
		if r.SignerKey != key {
			return nil, errors.New("recovery successor session_open was signed by a different key than the seal")
		}
		if r.ActionRecord.ChainPrevHash != ComputeSessionOpenGenesis(*o) {
			return nil, errors.New("recovery successor session_open does not start from its genesis")
		}
		s.SuccessorOpenHash, err = ReceiptHash(*r)
		if err != nil {
			return nil, err
		}
		break
	}
	if s.SuccessorOpenHash == "" {
		return nil, errors.New("recovery requires a successor session_open before sealing")
	}
	if err := verifyRecoveryPrefixWithOptions(req.self, entries, req.signerKeys, req.signerKeys == nil); err != nil {
		return nil, err
	}
	s.SuccessorSession, s.ObservedAt = req.self, req.now.UTC().Format(time.RFC3339Nano)
	s, err = SignRecoverySeal(s, req.privKey)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if err := publishChainLinkFile(req.dir, ChainLinkFileName(predecessor), append(body, '\n')); err != nil {
		if !errors.Is(err, errLinkNameTaken) {
			return nil, err
		}
		// A retry after an uncertain fsync may find its own completed claim.
		raw, readErr := readClaimBytes(filepath.Join(req.dir, ChainLinkFileName(predecessor)))
		if readErr != nil {
			return nil, readErr
		}
		prior, readErr := UnmarshalRecoverySeal(raw)
		if readErr != nil {
			return nil, readErr
		}
		prior.ObservedAt, prior.Signature = s.ObservedAt, s.Signature
		if prior != s {
			return nil, errors.New("recovery predecessor already claimed by different evidence")
		}
	}
	return &s, nil
}
