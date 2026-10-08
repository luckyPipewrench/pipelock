// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	groupOpenDomain       = "pipelock/receipt-group-open/v1"
	groupCloseDomain      = "pipelock/receipt-group-close/v1"
	groupTransitionDomain = "pipelock/receipt-group-transition/v1"
	maxGroupFileBytes     = 128 << 10
	maxGroupInteger       = uint64(1<<53 - 1)
)

// ReceiptGroupShard is one member of a group, in ascending index order.
type ReceiptGroupShard struct {
	ShardIndex int    `json:"shard_index"`
	SessionID  string `json:"session_id"`
}

// ReceiptGroupOpen is the signed membership statement published before traffic.
type ReceiptGroupOpen struct {
	Version                    int                 `json:"version"`
	Kind                       string              `json:"kind"`
	GroupID                    string              `json:"group_id"`
	BaseSession                string              `json:"base_session"`
	ShardCount                 int                 `json:"shard_count"`
	ProcessShardIndex          int                 `json:"process_shard_index"`
	SignerKey                  string              `json:"signer_key"`
	Shards                     []ReceiptGroupShard `json:"shards"`
	PreviousGroupID            string              `json:"previous_group_id"`
	PreviousOpenManifestSHA256 string              `json:"previous_open_manifest_sha256"`
	CreatedAt                  string              `json:"created_at"`
	Signature                  string              `json:"signature,omitempty"`
}

// ReceiptGroupShardHead commits one complete shard's final evidence heads.
type ReceiptGroupShardHead struct {
	ShardIndex           int    `json:"shard_index"`
	SessionID            string `json:"session_id"`
	FinalChainSeq        uint64 `json:"final_chain_seq"`
	FinalChainHash       string `json:"final_chain_hash"`
	ReceiptCount         uint64 `json:"receipt_count"`
	SessionCloseHash     string `json:"session_close_hash"`
	TranscriptRootHash   string `json:"transcript_root_hash"`
	CheckpointHash       string `json:"checkpoint_hash"`
	NativeAELFinalSeq    uint64 `json:"native_ael_final_seq"`
	NativeAELFinalHash   string `json:"native_ael_final_hash"`
	NativeAELRecordCount uint64 `json:"native_ael_record_count"`
}

// ReceiptGroupClose commits every shard head after durable closure.
type ReceiptGroupClose struct {
	Version            int                     `json:"version"`
	Kind               string                  `json:"kind"`
	GroupID            string                  `json:"group_id"`
	OpenManifestSHA256 string                  `json:"open_manifest_sha256"`
	Status             string                  `json:"status"`
	Shards             []ReceiptGroupShardHead `json:"shards"`
	ClosedAt           string                  `json:"closed_at"`
	SignerKey          string                  `json:"signer_key"`
	Signature          string                  `json:"signature,omitempty"`
}

// ReceiptGroupPredecessor is one previous group's verified final head.
type ReceiptGroupPredecessor struct {
	ShardIndex         int    `json:"shard_index"`
	SessionID          string `json:"session_id"`
	FinalChainSeq      uint64 `json:"final_chain_seq"`
	FinalChainHash     string `json:"final_chain_hash"`
	RecoverySealSHA256 string `json:"recovery_seal_sha256"`
}

// ReceiptGroupTransition binds one successor to one predecessor group.
type ReceiptGroupTransition struct {
	Version                     int                       `json:"version"`
	Kind                        string                    `json:"kind"`
	NewGroupID                  string                    `json:"new_group_id"`
	NewOpenManifestSHA256       string                    `json:"new_open_manifest_sha256"`
	PreviousGroupID             string                    `json:"previous_group_id"`
	PreviousOpenManifestSHA256  string                    `json:"previous_open_manifest_sha256"`
	PreviousCloseManifestSHA256 string                    `json:"previous_close_manifest_sha256"`
	Predecessors                []ReceiptGroupPredecessor `json:"predecessors"`
	CreatedAt                   string                    `json:"created_at"`
	SignerKey                   string                    `json:"signer_key"`
	Signature                   string                    `json:"signature,omitempty"`
}

// ReceiptGroupFileName returns the unique name for a signed group artifact.
func ReceiptGroupFileName(groupID, phase string) (string, error) {
	if !groupHex(groupID, 32) {
		return "", errors.New("invalid receipt group ID")
	}
	switch phase {
	case "open", "close", "transition":
		return "receipt-group-" + groupID + "-" + phase + ".json", nil
	default:
		return "", errors.New("invalid receipt group artifact phase")
	}
}

func groupHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, b := range []byte(value) {
		if b < '0' || (b > '9' && b < 'a') || b > 'f' {
			return false
		}
	}
	return true
}

func groupTime(value string) bool {
	t, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !t.IsZero() && value == t.UTC().Format(time.RFC3339Nano)
}

func groupSigner(value string) bool { return groupHex(value, ed25519.PublicKeySize*2) }

func groupRunSession(base, session string) bool {
	const infix = ".run."
	return strings.HasPrefix(session, base+infix) && groupHex(strings.TrimPrefix(session, base+infix), 32)
}

func validateGroupOpen(o ReceiptGroupOpen) error {
	if o.Version != 1 || o.Kind != "receipt_group_open" || !groupHex(o.GroupID, 32) {
		return errors.New("invalid receipt group open identity")
	}
	if err := evidencename.ValidateOperatorSessionID(o.BaseSession); err != nil {
		return fmt.Errorf("invalid receipt group base session: %w", err)
	}
	if o.ShardCount < 2 || o.ShardCount > 32 || len(o.Shards) != o.ShardCount || o.ProcessShardIndex < 0 || o.ProcessShardIndex >= o.ShardCount {
		return errors.New("invalid receipt group shard count or process index")
	}
	if !groupSigner(o.SignerKey) || !groupTime(o.CreatedAt) {
		return errors.New("invalid receipt group signer or timestamp")
	}
	if (o.PreviousGroupID == "") != (o.PreviousOpenManifestSHA256 == "") {
		return errors.New("receipt group predecessor pair is incomplete")
	}
	if o.PreviousGroupID != "" && (!groupHex(o.PreviousGroupID, 32) || !groupHex(o.PreviousOpenManifestSHA256, 64) || o.PreviousGroupID == o.GroupID) {
		return errors.New("invalid receipt group predecessor")
	}
	seen := make(map[string]struct{}, len(o.Shards))
	for i, shard := range o.Shards {
		if shard.ShardIndex != i || !groupRunSession(o.BaseSession, shard.SessionID) {
			return fmt.Errorf("invalid receipt group shard %d", i)
		}
		if _, exists := seen[shard.SessionID]; exists {
			return errors.New("duplicate receipt group session")
		}
		seen[shard.SessionID] = struct{}{}
	}
	return nil
}

func validateGroupClose(c ReceiptGroupClose, open ReceiptGroupOpen, openHash string) error {
	if c.Version != 1 || c.Kind != "receipt_group_close" || c.Status != "complete" || c.GroupID != open.GroupID || !groupHex(openHash, 64) || c.OpenManifestSHA256 != openHash || c.SignerKey != open.SignerKey || !groupTime(c.ClosedAt) {
		return errors.New("receipt group close does not bind opening manifest")
	}
	if len(c.Shards) != len(open.Shards) {
		return errors.New("receipt group close shard set differs from open")
	}
	for i, h := range c.Shards {
		if h.ShardIndex != i || h.SessionID != open.Shards[i].SessionID {
			return fmt.Errorf("receipt group close shard %d differs from open", i)
		}
		if h.FinalChainSeq > maxGroupInteger || h.ReceiptCount > maxGroupInteger || h.NativeAELFinalSeq > maxGroupInteger || h.NativeAELRecordCount > maxGroupInteger {
			return fmt.Errorf("receipt group close shard %d integer exceeds safe range", i)
		}
		for _, digest := range []string{h.FinalChainHash, h.SessionCloseHash, h.TranscriptRootHash, h.CheckpointHash, h.NativeAELFinalHash} {
			if !groupHex(digest, 64) {
				return fmt.Errorf("receipt group close shard %d has invalid hash", i)
			}
		}
	}
	return nil
}

func validateGroupTransition(tr ReceiptGroupTransition, successor, predecessor ReceiptGroupOpen, newHash, oldHash, closeHash string) error {
	if tr.Version != 1 || tr.Kind != "receipt_group_transition" || !groupTime(tr.CreatedAt) || !groupSigner(tr.SignerKey) {
		return errors.New("invalid receipt group transition header")
	}
	if !groupHex(newHash, 64) || !groupHex(oldHash, 64) || (closeHash != "" && !groupHex(closeHash, 64)) {
		return errors.New("invalid receipt group transition manifest digest")
	}
	if tr.NewGroupID != successor.GroupID || tr.NewOpenManifestSHA256 != newHash || tr.PreviousGroupID != predecessor.GroupID || tr.PreviousOpenManifestSHA256 != oldHash || tr.PreviousCloseManifestSHA256 != closeHash {
		return errors.New("receipt group transition does not match predecessor and successor")
	}
	if successor.PreviousGroupID != tr.PreviousGroupID || successor.PreviousOpenManifestSHA256 != tr.PreviousOpenManifestSHA256 || tr.SignerKey != successor.SignerKey || len(tr.Predecessors) != len(predecessor.Shards) {
		return errors.New("receipt group transition predecessor set differs")
	}
	for i, h := range tr.Predecessors {
		if h.ShardIndex != i || h.SessionID != predecessor.Shards[i].SessionID || h.FinalChainSeq > maxGroupInteger || !groupHex(h.FinalChainHash, 64) || (h.RecoverySealSHA256 != "" && !groupHex(h.RecoverySealSHA256, 64)) {
			return fmt.Errorf("invalid receipt group transition predecessor %d", i)
		}
	}
	return nil
}

func signGroupArtifact(domain string, value any, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("invalid receipt group private key")
	}
	data, err := canonicalArtifactBytes(domain, value)
	if err != nil {
		return "", err
	}
	return signaturePrefix + hex.EncodeToString(ed25519.Sign(key, data)), nil
}

func verifyGroupArtifact(domain string, value any, signature, signer string, trusted []string) error {
	if !groupSigner(signer) {
		return errors.New("invalid receipt group signer key")
	}
	if !slicesContains(trusted, signer) {
		return errors.New("receipt group signer is not trusted")
	}
	sigHex, ok := strings.CutPrefix(signature, signaturePrefix)
	if !ok || !groupHex(sigHex, ed25519.SignatureSize*2) {
		return errors.New("invalid receipt group signature encoding")
	}
	sig, _ := hex.DecodeString(sigHex)
	key, _ := hex.DecodeString(signer)
	data, err := canonicalArtifactBytes(domain, value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, data, sig) {
		return errors.New("receipt group signature verification failed")
	}
	return nil
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func strictGroupArtifact[T any](raw []byte) (T, error) {
	var out T
	if len(raw) == 0 || len(raw) > maxGroupFileBytes || !utf8.Valid(raw) {
		return out, errors.New("invalid receipt group artifact bytes")
	}
	if err := jsonscan.RejectDuplicateKeys(raw); err != nil {
		return out, err
	}
	if err := rejectStructAliases(raw, reflect.TypeFor[T]()); err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, err
	}
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return out, errors.New("receipt group artifact has trailing tokens")
	}
	canonical, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(raw, jsonscan.NormalizeReplacementEscapes(canonical)) {
		return out, errors.New("receipt group artifact is not canonical published JSON")
	}
	return out, nil
}

// SignReceiptGroupOpen signs a validated group opening with its member key.
func SignReceiptGroupOpen(open ReceiptGroupOpen, key ed25519.PrivateKey) (ReceiptGroupOpen, error) {
	open.Version, open.Kind, open.Signature = 1, "receipt_group_open", ""
	if len(key) != ed25519.PrivateKeySize {
		return ReceiptGroupOpen{}, errors.New("invalid receipt group private key")
	}
	open.SignerKey = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := validateGroupOpen(open); err != nil {
		return ReceiptGroupOpen{}, err
	}
	sig, err := signGroupArtifact(groupOpenDomain, open, key)
	open.Signature = sig
	return open, err
}

// UnmarshalReceiptGroupOpen accepts only canonical signed bytes under a trusted key.
func UnmarshalReceiptGroupOpen(raw []byte, trusted []string) (ReceiptGroupOpen, error) {
	open, err := strictGroupArtifact[ReceiptGroupOpen](raw)
	if err != nil {
		return open, err
	}
	if err := validateGroupOpen(open); err != nil {
		return open, err
	}
	signature := open.Signature
	open.Signature = ""
	if err := verifyGroupArtifact(groupOpenDomain, open, signature, open.SignerKey, trusted); err != nil {
		return ReceiptGroupOpen{}, err
	}
	open.Signature = signature
	return open, nil
}

// SignReceiptGroupClose signs an exact close set with the original opening key.
func SignReceiptGroupClose(manifest ReceiptGroupClose, open ReceiptGroupOpen, openHash string, key ed25519.PrivateKey) (ReceiptGroupClose, error) {
	manifest.Version, manifest.Kind, manifest.Signature = 1, "receipt_group_close", ""
	manifest.Status = "complete"
	if len(key) != ed25519.PrivateKeySize || hex.EncodeToString(key.Public().(ed25519.PublicKey)) != open.SignerKey {
		return ReceiptGroupClose{}, errors.New("receipt group close requires opening private key")
	}
	manifest.SignerKey = open.SignerKey
	if err := validateGroupClose(manifest, open, openHash); err != nil {
		return ReceiptGroupClose{}, err
	}
	sig, err := signGroupArtifact(groupCloseDomain, manifest, key)
	manifest.Signature = sig
	return manifest, err
}

// UnmarshalReceiptGroupClose verifies signature and exact opening membership.
func UnmarshalReceiptGroupClose(raw []byte, open ReceiptGroupOpen, openHash string, trusted []string) (ReceiptGroupClose, error) {
	manifest, err := strictGroupArtifact[ReceiptGroupClose](raw)
	if err != nil {
		return manifest, err
	}
	if err := validateGroupClose(manifest, open, openHash); err != nil {
		return manifest, err
	}
	signature := manifest.Signature
	manifest.Signature = ""
	if err := verifyGroupArtifact(groupCloseDomain, manifest, signature, manifest.SignerKey, trusted); err != nil {
		return ReceiptGroupClose{}, err
	}
	manifest.Signature = signature
	return manifest, nil
}

// SignReceiptGroupTransition signs one exact successor claim.
func SignReceiptGroupTransition(tr ReceiptGroupTransition, successor, predecessor ReceiptGroupOpen, newHash, oldHash, closeHash string, key ed25519.PrivateKey) (ReceiptGroupTransition, error) {
	tr.Version, tr.Kind, tr.Signature = 1, "receipt_group_transition", ""
	if len(key) != ed25519.PrivateKeySize {
		return ReceiptGroupTransition{}, errors.New("invalid receipt group private key")
	}
	tr.SignerKey = hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := validateGroupTransition(tr, successor, predecessor, newHash, oldHash, closeHash); err != nil {
		return ReceiptGroupTransition{}, err
	}
	sig, err := signGroupArtifact(groupTransitionDomain, tr, key)
	tr.Signature = sig
	return tr, err
}

// UnmarshalReceiptGroupTransition verifies the exact predecessor and successor pair.
func UnmarshalReceiptGroupTransition(raw []byte, successor, predecessor ReceiptGroupOpen, newHash, oldHash, closeHash string, trusted []string) (ReceiptGroupTransition, error) {
	tr, err := strictGroupArtifact[ReceiptGroupTransition](raw)
	if err != nil {
		return tr, err
	}
	if err := validateGroupTransition(tr, successor, predecessor, newHash, oldHash, closeHash); err != nil {
		return tr, err
	}
	signature := tr.Signature
	tr.Signature = ""
	if err := verifyGroupArtifact(groupTransitionDomain, tr, signature, tr.SignerKey, trusted); err != nil {
		return ReceiptGroupTransition{}, err
	}
	tr.Signature = signature
	return tr, nil
}

// PublishReceiptGroupArtifact durably publishes canonical signed bytes once.
// The caller must hold the evidence-directory ceremony lock.
func PublishReceiptGroupArtifact(dir, name string, value any) (string, error) {
	const prefix = "receipt-group-"
	if !strings.HasPrefix(name, prefix) || len(name) < len(prefix)+32+len("-open.json") {
		return "", errors.New("invalid receipt group artifact name")
	}
	groupID := name[len(prefix) : len(prefix)+32]
	phase := strings.TrimSuffix(strings.TrimPrefix(name[len(prefix)+32:], "-"), ".json")
	want, err := ReceiptGroupFileName(groupID, phase)
	if err != nil || name != want {
		return "", errors.New("invalid receipt group artifact name")
	}
	switch artifact := value.(type) {
	case ReceiptGroupOpen:
		if phase != "open" || artifact.GroupID != groupID || artifact.Signature == "" {
			return "", errors.New("receipt group open publication identity mismatch")
		}
	case ReceiptGroupClose:
		if phase != "close" || artifact.GroupID != groupID || artifact.Signature == "" {
			return "", errors.New("receipt group close publication identity mismatch")
		}
	case ReceiptGroupTransition:
		if phase != "transition" || artifact.NewGroupID != groupID || artifact.Signature == "" {
			return "", errors.New("receipt group transition publication identity mismatch")
		}
	default:
		return "", errors.New("unsupported receipt group artifact publication type")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	body = jsonscan.NormalizeReplacementEscapes(body)
	if len(body) > maxGroupFileBytes {
		return "", errors.New("receipt group artifact exceeds size bound")
	}
	if err := publishChainLinkFile(dir, name, body); err != nil {
		return "", err
	}
	published, err := recorder.ReadEvidenceLocationFileBounded(
		recorder.EvidenceLocation{Root: dir, Dir: dir}, name, maxGroupFileBytes)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(body, published) {
		return "", errors.New("published receipt group bytes changed")
	}
	sum := sha256.Sum256(published)
	return hex.EncodeToString(sum[:]), nil
}
