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
	"sync/atomic"
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
	// maxResetConsumedNonces bounds one authority's replay ledger. When every
	// entry is live, accepting another protection-lowering reset would require
	// forgetting replay state, so the authority denies the reset instead.
	maxResetConsumedNonces = 1024
	// resetHexBytes is the byte length of BOTH the nonce and the instance ID.
	// One constant, deliberately: they are generated and validated by the same
	// helper, and two equal constants with nothing holding them equal would let
	// generation and validation drift into refusing our own instance ID.
	resetHexBytes = 16
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
	ResetAuthorityCapacity      ResetAuthorityResult = "capacity_exceeded"
	ResetAuthorityRemoveFailed  ResetAuthorityResult = "remove_failed"
	ResetAuthorityPathChanged   ResetAuthorityResult = "path_changed"
)

// ResetAuthorityDecision returns untrusted diagnostics for audit; only
// Result==accepted may change live reset state.
type ResetAuthorityDecision struct {
	Result     ResetAuthorityResult
	Delegation ResetDelegation
	// ExpectedEpoch is the epoch the proxy required. It is reported on a
	// mismatch because the delegation only carries the epoch the operator
	// supplied, and echoing a wrong value back gives them nothing to correct
	// with. The epoch advances on every accepted reset, so an operator who
	// mints a second delegation from a stale number otherwise has no way to
	// learn the current one short of restarting the proxy.
	ExpectedTarget     string
	ExpectedInstanceID string
	ExpectedEpoch      uint64
}

// ResetEpoch is the live reset generation that a delegation consumes. The
// authority reads and advances it while holding its own nonce ledger lock, and
// AdvanceEpoch must atomically advance only the expected generation.
//
// A caller must pass the one live epoch holder for its reset state. Supplying
// an already-read integer would let distinct valid delegations race past the
// same generation check.
type ResetEpoch interface {
	CurrentEpoch() uint64
	AdvanceEpoch(expected uint64) bool
}

type resetAtomicEpoch struct {
	epoch *atomic.Uint64
}

func newResetAtomicEpoch(epoch *atomic.Uint64) ResetEpoch {
	if epoch == nil {
		return nil
	}
	return resetAtomicEpoch{epoch: epoch}
}

func (e resetAtomicEpoch) CurrentEpoch() uint64 {
	return e.epoch.Load()
}

func (e resetAtomicEpoch) AdvanceEpoch(expected uint64) bool {
	return e.epoch.CompareAndSwap(expected, expected+1)
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
	consumed   map[string]time.Time
}

// NewResetAuthority makes a verifier for one proxy process.
func NewResetAuthority(publicKey ed25519.PublicKey, target string) (*ResetAuthority, error) {
	instanceID, err := randomResetHex(resetHexBytes)
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
	if err := validateResetHex("instance_id", instanceID); err != nil {
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
		consumed:   make(map[string]time.Time),
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
func NewResetNonce() (string, error) { return randomResetHex(resetHexBytes) }

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
	if err := validateResetHex("instance_id", instanceID); err != nil {
		return ResetDelegation{}, err
	}
	if err := validateResetHex("nonce", nonce); err != nil {
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
// The nonce check and the epoch compare-and-advance are one operation under
// the authority lock, so a delegation epoch is spendable exactly once.
func (a *ResetAuthority) ConsumeFile(path string, kind ResetKind, epoch ResetEpoch) ResetAuthorityDecision {
	if a == nil || strings.TrimSpace(path) == "" {
		return ResetAuthorityDecision{Result: ResetAuthorityAbsent}
	}
	if epoch == nil {
		return ResetAuthorityDecision{Result: ResetAuthorityUnreadable}
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
	a.mu.Lock()
	defer a.mu.Unlock()
	expectedEpoch := epoch.CurrentEpoch()
	decision := ResetAuthorityDecision{
		Delegation:         d,
		ExpectedTarget:     a.target,
		ExpectedInstanceID: a.instanceID,
		ExpectedEpoch:      expectedEpoch,
	}
	now := a.now().UTC().Truncate(time.Second)
	a.purgeExpiredConsumedLocked(now)
	if result := a.verifyAt(d, kind, expectedEpoch, now); result != ResetAuthorityAccepted {
		decision.Result = result
		_ = removeResetDelegationFile(path, opened)
		return decision
	}
	if _, used := a.consumed[d.Nonce]; used {
		decision.Result = ResetAuthorityReplayed
		_ = removeResetDelegationFile(path, opened)
		return decision
	}
	if len(a.consumed) >= maxResetConsumedNonces {
		decision.Result = ResetAuthorityCapacity
		_ = removeResetDelegationFile(path, opened)
		return decision
	}
	if err := removeResetDelegationFile(path, opened); err != nil {
		decision.Result = removeResetResult(err)
		return decision
	}
	if !epoch.AdvanceEpoch(expectedEpoch) {
		decision.Result = ResetAuthorityWrongEpoch
		decision.ExpectedEpoch = epoch.CurrentEpoch()
		return decision
	}
	a.consumed[d.Nonce] = time.Unix(d.ExpiresUnix, 0).UTC()
	decision.Result = ResetAuthorityAccepted
	return decision
}

func (a *ResetAuthority) verify(d ResetDelegation, kind ResetKind, epoch uint64) ResetAuthorityResult {
	return a.verifyAt(d, kind, epoch, a.now().UTC().Truncate(time.Second))
}

func (a *ResetAuthority) verifyAt(d ResetDelegation, kind ResetKind, epoch uint64, now time.Time) ResetAuthorityResult {
	if _, err := d.signingInput(); err != nil {
		if d.Purpose != signing.PurposeMCPResetAuthority.String() {
			return ResetAuthorityWrongPurpose
		}
		return ResetAuthorityMalformed
	}
	if d.Signature == "" {
		return ResetAuthorityUnsigned
	}
	if err := VerifyResetDelegationSignature(a.publicKey, d); err != nil {
		return ResetAuthorityWrongKey
	}
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

// purgeExpiredConsumedLocked removes only nonces whose delegations have
// already expired. A replay carrying one of those nonces still fails the
// delegation expiry check before it can change reset state.
func (a *ResetAuthority) purgeExpiredConsumedLocked(now time.Time) {
	for nonce, expires := range a.consumed {
		if !expires.After(now) {
			delete(a.consumed, nonce)
		}
	}
}

// ParseResetDelegation strictly decodes one control-file envelope and validates
// its signed fields. It does not treat the result as authorized until the
// caller verifies it against the configured public key and live state.
func ParseResetDelegation(raw []byte) (ResetDelegation, error) {
	var d ResetDelegation
	if err := contract.DecodeStrictJSON(raw, &d); err != nil {
		return ResetDelegation{}, fmt.Errorf("decode reset delegation: %w", err)
	}
	if _, err := d.signingInput(); err != nil {
		return ResetDelegation{}, err
	}
	return d, nil
}

// VerifyResetDelegationSignature proves a parsed delegation came from the
// configured reset-authority key. It does not consume the nonce or evaluate
// target, epoch, or expiry.
func VerifyResetDelegationSignature(publicKey ed25519.PublicKey, d ResetDelegation) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("reset authority public key length %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	input, err := d.signingInput()
	if err != nil {
		return err
	}
	sig, err := decodeResetSignature(d.Signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, input, sig) {
		return errors.New("reset delegation signature does not match configured authority key")
	}
	if err := signing.VerifyFingerprint(publicKey, d.IssuerFingerprint); err != nil {
		return fmt.Errorf("reset delegation issuer fingerprint: %w", err)
	}
	return nil
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
	if err := validateResetHex("instance_id", d.InstanceID); err != nil {
		return nil, err
	}
	if err := validateResetHex("nonce", d.Nonce); err != nil {
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
	f, err := os.Open(clean) // #nosec G304 -- configured operator control path, fd checked and bounded below
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

// validateResetHex checks one lowercase hex field against the exact byte length
// its generator produced.
//
// The length is a parameter rather than a single shared constant because the
// instance ID and the nonce are generated from separate constants. Validating
// both against one of them happens to work only while the two are equal, and
// the failure if they ever diverge is silent and total: the proxy generates an
// instance ID it then refuses as malformed, every reset fails, and the error
// names a field the operator never typed.
func validateResetHex(label, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != resetHexBytes || strings.ToLower(value) != value {
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
