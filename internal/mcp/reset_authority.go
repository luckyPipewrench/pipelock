// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	resetDelegationSchemaVersion = 1
	resetDelegationPrefix        = "pipelock-mcp-reset-delegation-v1\n"
	resetDelegationMaxBytes      = 16 * 1024
	resetDelegationMaxTTL        = 15 * time.Minute
	resetDelegationClockSkew     = time.Minute
	resetNonceBytes              = 16
	resetInstanceBytes           = 16
)

// ResetKind scopes a delegation to one de-escalation.
type ResetKind string

const (
	ResetKindDrift    ResetKind = "drift"
	ResetKindAdaptive ResetKind = "adaptive"
)

func (k ResetKind) valid() bool { return k == ResetKindDrift || k == ResetKindAdaptive }

// ResetDelegation is the signed reset-control-file envelope.
type ResetDelegation struct {
	SchemaVersion     int       `json:"schema_version"`
	Purpose           string    `json:"purpose"`
	Kind              ResetKind `json:"kind"`
	Target            string    `json:"target"`
	InstanceID        string    `json:"instance_id"`
	Epoch             uint64    `json:"epoch"`
	IssuedUnix        int64     `json:"issued_unix"`
	ExpiresUnix       int64     `json:"expires_unix"`
	Nonce             string    `json:"nonce"`
	Issuer            string    `json:"issuer"`
	IssuerFingerprint string    `json:"issuer_fingerprint"`
	Signature         string    `json:"signature"`
}

type resetPayload struct {
	SchemaVersion     int       `json:"schema_version"`
	Purpose           string    `json:"purpose"`
	Kind              ResetKind `json:"kind"`
	Target            string    `json:"target"`
	InstanceID        string    `json:"instance_id"`
	Epoch             uint64    `json:"epoch"`
	IssuedUnix        int64     `json:"issued_unix"`
	ExpiresUnix       int64     `json:"expires_unix"`
	Nonce             string    `json:"nonce"`
	Issuer            string    `json:"issuer"`
	IssuerFingerprint string    `json:"issuer_fingerprint"`
}

// ResetAuthorityResult is an auditable verifier outcome.
type ResetAuthorityResult string

const (
	ResetAuthorityAccepted      ResetAuthorityResult = "accepted"
	ResetAuthorityAbsent        ResetAuthorityResult = "absent"
	ResetAuthorityUnreadable    ResetAuthorityResult = "unreadable"
	ResetAuthorityMalformed     ResetAuthorityResult = "malformed"
	ResetAuthorityUnsigned      ResetAuthorityResult = "unsigned"
	ResetAuthorityWrongKey      ResetAuthorityResult = "wrong_key"
	ResetAuthorityWrongPurpose  ResetAuthorityResult = "wrong_purpose"
	ResetAuthorityExpired       ResetAuthorityResult = "expired"
	ResetAuthorityNotYetValid   ResetAuthorityResult = "not_yet_valid"
	ResetAuthorityWrongKind     ResetAuthorityResult = "wrong_kind"
	ResetAuthorityWrongTarget   ResetAuthorityResult = "wrong_target"
	ResetAuthorityWrongInstance ResetAuthorityResult = "wrong_instance"
	ResetAuthorityWrongEpoch    ResetAuthorityResult = "wrong_epoch"
	ResetAuthorityReplayed      ResetAuthorityResult = "replayed"
	ResetAuthorityRemoveFailed  ResetAuthorityResult = "remove_failed"
	ResetAuthorityPathChanged   ResetAuthorityResult = "path_changed"
)

// ResetAuthorityDecision returns untrusted diagnostics for audit; only
// Result==accepted may change live reset state.
type ResetAuthorityDecision struct {
	Result     ResetAuthorityResult
	Delegation ResetDelegation
}

// ResetAuthority keeps the live target and in-process consumed-nonce ledger.
// InstanceID is random at proxy start, so pre-restart delegations never regain
// authority after restart without a same-UID durable replay ledger.
type ResetAuthority struct {
	publicKey  ed25519.PublicKey
	target     string
	instanceID string
	now        func() time.Time
	mu         sync.Mutex
	consumed   map[string]struct{}
}

// NewResetAuthority makes a verifier for one proxy process.
func NewResetAuthority(publicKey ed25519.PublicKey, target string) (*ResetAuthority, error) {
	instanceID, err := randomResetHex(resetInstanceBytes)
	if err != nil {
		return nil, fmt.Errorf("generate reset authority instance ID: %w", err)
	}
	return newResetAuthority(publicKey, target, instanceID, time.Now)
}

func newResetAuthority(publicKey ed25519.PublicKey, target, instanceID string, now func() time.Time) (*ResetAuthority, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("reset authority public key length %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	if err := validateResetTarget(target); err != nil {
		return nil, err
	}
	if err := validateResetHex("instance_id", instanceID, resetInstanceBytes); err != nil {
		return nil, err
	}
	if now == nil {
		return nil, errors.New("reset authority clock is nil")
	}
	return &ResetAuthority{
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
		target:     target,
		instanceID: instanceID,
		now:        now,
		consumed:   make(map[string]struct{}),
	}, nil
}

func (a *ResetAuthority) Target() string {
	if a == nil {
		return ""
	}
	return a.target
}

func (a *ResetAuthority) InstanceID() string {
	if a == nil {
		return ""
	}
	return a.instanceID
}

// NewResetNonce creates the random one-shot nonce carried in a delegation.
func NewResetNonce() (string, error) { return randomResetHex(resetNonceBytes) }

// MintResetDelegation signs a short-lived canonical delegation. The caller
// retains the private key, which never enters the MCP proxy.
func MintResetDelegation(privateKey ed25519.PrivateKey, issuer string, kind ResetKind, target, instanceID string, epoch uint64, issuedAt, expiresAt time.Time, nonce string) (ResetDelegation, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ResetDelegation{}, fmt.Errorf("reset authority private key length %d, want %d", len(privateKey), ed25519.PrivateKeySize)
	}
	if err := signing.ValidatePrivateKeyConsistency(privateKey); err != nil {
		return ResetDelegation{}, fmt.Errorf("validate reset authority private key: %w", err)
	}
	if !kind.valid() {
		return ResetDelegation{}, fmt.Errorf("invalid reset delegation kind %q", kind)
	}
	if err := validateResetTarget(target); err != nil {
		return ResetDelegation{}, err
	}
	if err := validateResetHex("instance_id", instanceID, resetInstanceBytes); err != nil {
		return ResetDelegation{}, err
	}
	if err := validateResetHex("nonce", nonce, resetNonceBytes); err != nil {
		return ResetDelegation{}, err
	}
	if err := validateResetIssuer(issuer); err != nil {
		return ResetDelegation{}, err
	}
	issuedAt, expiresAt = issuedAt.UTC().Truncate(time.Second), expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > resetDelegationMaxTTL {
		return ResetDelegation{}, fmt.Errorf("reset delegation expiry must be after issue time and no more than %s later", resetDelegationMaxTTL)
	}
	pub, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return ResetDelegation{}, errors.New("derive reset authority public key")
	}
	fingerprint, err := signing.Fingerprint(pub)
	if err != nil {
		return ResetDelegation{}, fmt.Errorf("fingerprint reset authority key: %w", err)
	}
	d := ResetDelegation{
		SchemaVersion: resetDelegationSchemaVersion, Purpose: signing.PurposeMCPResetAuthority.String(),
		Kind: kind, Target: target, InstanceID: instanceID, Epoch: epoch,
		IssuedUnix: issuedAt.Unix(), ExpiresUnix: expiresAt.Unix(), Nonce: nonce,
		Issuer: issuer, IssuerFingerprint: fingerprint,
	}
	input, err := d.signingInput()
	if err != nil {
		return ResetDelegation{}, err
	}
	d.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input))
	return d, nil
}

// MarshalResetDelegation emits the canonical control-file envelope.
func MarshalResetDelegation(d ResetDelegation) ([]byte, error) {
	if _, err := d.signingInput(); err != nil {
		return nil, err
	}
	if _, err := decodeResetSignature(d.Signature); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("marshal reset delegation: %w", err)
	}
	return append(raw, '\n'), nil
}

// ConsumeFile verifies and unlinks one delegation. Ownership and mode do not
// confer authority: only the signature and live binding fields can authorize.
func (a *ResetAuthority) ConsumeFile(path string, kind ResetKind, epoch uint64) ResetAuthorityDecision {
	if a == nil || strings.TrimSpace(path) == "" {
		return ResetAuthorityDecision{Result: ResetAuthorityAbsent}
	}
	raw, opened, err := readResetDelegationFile(path)
	if err != nil {
		return ResetAuthorityDecision{Result: resetReadResult(err)}
	}
	var d ResetDelegation
	if err := contract.DecodeStrictJSON(raw, &d); err != nil {
		_ = removeResetDelegationFile(path, opened)
		return ResetAuthorityDecision{Result: ResetAuthorityMalformed}
	}
	decision := ResetAuthorityDecision{Delegation: d}
	if result := a.verify(d, kind, epoch); result != ResetAuthorityAccepted {
		decision.Result = result
		_ = removeResetDelegationFile(path, opened)
		return decision
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, used := a.consumed[d.Nonce]; used {
		decision.Result = ResetAuthorityReplayed
		_ = removeResetDelegationFile(path, opened)
		return decision
	}
	if err := removeResetDelegationFile(path, opened); err != nil {
		decision.Result = removeResetResult(err)
		return decision
	}
	a.consumed[d.Nonce] = struct{}{}
	decision.Result = ResetAuthorityAccepted
	return decision
}

func (a *ResetAuthority) verify(d ResetDelegation, kind ResetKind, epoch uint64) ResetAuthorityResult {
	if _, err := d.signingInput(); err != nil {
		if d.Purpose != signing.PurposeMCPResetAuthority.String() {
			return ResetAuthorityWrongPurpose
		}
		return ResetAuthorityMalformed
	}
	if d.Signature == "" {
		return ResetAuthorityUnsigned
	}
	sig, err := decodeResetSignature(d.Signature)
	if err != nil {
		return ResetAuthorityMalformed
	}
	input, _ := d.signingInput()
	if !ed25519.Verify(a.publicKey, input, sig) {
		return ResetAuthorityWrongKey
	}
	if err := signing.VerifyFingerprint(a.publicKey, d.IssuerFingerprint); err != nil {
		return ResetAuthorityWrongKey
	}
	now := a.now().UTC().Truncate(time.Second)
	issued, expires := time.Unix(d.IssuedUnix, 0).UTC(), time.Unix(d.ExpiresUnix, 0).UTC()
	if issued.After(now.Add(resetDelegationClockSkew)) {
		return ResetAuthorityNotYetValid
	}
	if !expires.After(now) {
		return ResetAuthorityExpired
	}
	if !expires.After(issued) || expires.Sub(issued) > resetDelegationMaxTTL {
		return ResetAuthorityMalformed
	}
	if d.Kind != kind {
		return ResetAuthorityWrongKind
	}
	if d.Target != a.target {
		return ResetAuthorityWrongTarget
	}
	if d.InstanceID != a.instanceID {
		return ResetAuthorityWrongInstance
	}
	if d.Epoch != epoch {
		return ResetAuthorityWrongEpoch
	}
	return ResetAuthorityAccepted
}

func (d ResetDelegation) signingInput() ([]byte, error) {
	if d.SchemaVersion != resetDelegationSchemaVersion {
		return nil, fmt.Errorf("unsupported reset delegation schema_version %d", d.SchemaVersion)
	}
	if d.Purpose != signing.PurposeMCPResetAuthority.String() {
		return nil, fmt.Errorf("reset delegation purpose %q is not %q", d.Purpose, signing.PurposeMCPResetAuthority)
	}
	if !d.Kind.valid() {
		return nil, fmt.Errorf("invalid reset delegation kind %q", d.Kind)
	}
	if err := validateResetTarget(d.Target); err != nil {
		return nil, err
	}
	if err := validateResetHex("instance_id", d.InstanceID, resetInstanceBytes); err != nil {
		return nil, err
	}
	if err := validateResetHex("nonce", d.Nonce, resetNonceBytes); err != nil {
		return nil, err
	}
	if err := validateResetIssuer(d.Issuer); err != nil {
		return nil, err
	}
	if _, _, err := signing.ParseFingerprint(d.IssuerFingerprint); err != nil {
		return nil, fmt.Errorf("invalid reset delegation issuer fingerprint: %w", err)
	}
	raw, err := json.Marshal(resetPayload{
		SchemaVersion: d.SchemaVersion, Purpose: d.Purpose, Kind: d.Kind, Target: d.Target,
		InstanceID: d.InstanceID, Epoch: d.Epoch, IssuedUnix: d.IssuedUnix, ExpiresUnix: d.ExpiresUnix,
		Nonce: d.Nonce, Issuer: d.Issuer, IssuerFingerprint: d.IssuerFingerprint,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal reset delegation signing input: %w", err)
	}
	return append([]byte(resetDelegationPrefix), raw...), nil
}

func readResetDelegationFile(path string) ([]byte, os.FileInfo, error) {
	clean := filepath.Clean(path)
	listed, err := os.Lstat(clean)
	if err != nil {
		return nil, nil, err
	}
	if listed.Mode()&os.ModeSymlink != 0 || !listed.Mode().IsRegular() {
		return nil, nil, errors.New("reset delegation is not a regular file")
	}
	f, err := os.Open(clean) //nolint:gosec // configured operator control path, fd checked and bounded below
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(listed, opened) {
		return nil, nil, errors.New("reset delegation changed before read")
	}
	if opened.Size() > resetDelegationMaxBytes {
		return nil, nil, errors.New("reset delegation exceeds size limit")
	}
	raw, err := io.ReadAll(io.LimitReader(f, resetDelegationMaxBytes+1))
	if err != nil || len(raw) > resetDelegationMaxBytes {
		return nil, nil, errors.New("reset delegation exceeds size limit")
	}
	return raw, opened, nil
}

func removeResetDelegationFile(path string, opened os.FileInfo) error {
	current, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("reset delegation path changed before removal")
	}
	return os.Remove(filepath.Clean(path))
}

func resetReadResult(err error) ResetAuthorityResult {
	if errors.Is(err, os.ErrNotExist) {
		return ResetAuthorityAbsent
	}
	return ResetAuthorityUnreadable
}

func removeResetResult(err error) ResetAuthorityResult {
	if strings.Contains(err.Error(), "path changed") {
		return ResetAuthorityPathChanged
	}
	return ResetAuthorityRemoveFailed
}

func decodeResetSignature(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, errors.New("reset delegation is unsigned")
	}
	sig, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid reset delegation signature")
	}
	return sig, nil
}

func validateResetTarget(target string) error {
	if strings.TrimSpace(target) == "" || len(target) > 512 || strings.ContainsAny(target, "\r\n\x00") {
		return errors.New("invalid reset delegation target")
	}
	return nil
}

func validateResetIssuer(issuer string) error {
	if strings.TrimSpace(issuer) == "" || len(issuer) > 128 || strings.ContainsAny(issuer, "\r\n\x00") {
		return errors.New("invalid reset delegation issuer")
	}
	return nil
}

func validateResetHex(label, value string, wantBytes int) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != wantBytes || strings.ToLower(value) != value {
		return fmt.Errorf("invalid reset delegation %s", label)
	}
	return nil
}

func randomResetHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// CanonicalResetDelegationInput returns the exact Ed25519 preimage.
func CanonicalResetDelegationInput(d ResetDelegation) ([]byte, error) {
	return d.signingInput()
}
