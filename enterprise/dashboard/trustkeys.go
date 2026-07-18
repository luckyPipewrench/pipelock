//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/anchor"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	AnchorNotExpected  = "not expected"
	AnchorMissing      = "missing"
	AnchorCurrent      = "current"
	AnchorStale        = "stale"
	AnchorFailure      = "failure"
	AnchorUnconfigured = "not configured - cannot verify"

	RevocationNotConfigured = "CRL not configured"
	RevocationFailure       = "FAILURE: CRL could not be verified"
	RevocationUnbound       = "FAILURE: receipt key has no verified CRL serial binding"

	localAnchorLogPathRequired = "local anchor log path is required to verify local anchor"

	maxAnchorMarkerBytes = 64 * 1024
	maxAnchorBundleBytes = 1024 * 1024
)

var errLocalAnchorLogPathRequired = errors.New(localAnchorLogPathRequired)

// ChainAuditInput contains the evidence and explicit trust material needed for
// one read-only consistency audit. AnchorExpected is an operator policy input;
// absence is a failure only when that policy says an anchor should exist.
type ChainAuditInput struct {
	SessionID      string
	Receipts       []receipt.Receipt
	TrustedKeys    []string
	AnchorExpected bool
	AnchorBundle   *anchor.Bundle
	AnchorBackend  anchor.Backend
}

// AnchorResolver returns verified-backend inputs for one session. expected is
// policy, not evidence: it controls whether absence is a failure.
type AnchorResolver func(sessionID string) (bundle *anchor.Bundle, backend anchor.Backend, expected bool, err error)

// NewFileAnchorResolver builds the dashboard's read-only adapter over the
// anchor-state marker emitted by `pipelock anchor receipts`. Rekor verification
// requires pinned log keys; local verification requires the actual local log.
func NewFileAnchorResolver(
	receiptDir string,
	localLogPath string,
	rekorLogKeyInputs []string,
	expected bool,
) (AnchorResolver, error) {
	return newFileAnchorResolver(receiptDir, localLogPath, rekorLogKeyInputs, expected, anchor.LoadBundleBytes)
}

func newFileAnchorResolver(
	receiptDir string,
	localLogPath string,
	rekorLogKeyInputs []string,
	expected bool,
	loadBundle func([]byte) (anchor.Bundle, error),
) (AnchorResolver, error) {
	rekorKeys, err := anchor.LoadRekorPublicKeys(rekorLogKeyInputs)
	if err != nil {
		return nil, fmt.Errorf("load Rekor log keys: %w", err)
	}
	baseDir, err := filepath.Abs(filepath.Clean(receiptDir))
	if err != nil {
		return nil, fmt.Errorf("resolve receipt directory: %w", err)
	}
	baseDir, err = filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("resolve receipt directory: %w", err)
	}
	baseInfo, err := os.Stat(baseDir)
	if err != nil {
		return nil, fmt.Errorf("inspect receipt directory: %w", err)
	}
	if !baseInfo.IsDir() {
		return nil, errors.New("receipt directory is not a directory")
	}
	return func(sessionID string) (*anchor.Bundle, anchor.Backend, bool, error) {
		markers, loadErr := loadAnchorMarkers(baseDir)
		if loadErr != nil {
			return nil, nil, true, loadErr
		}
		if len(markers) == 0 {
			return nil, nil, expected, nil
		}
		var marker anchorStateMarker
		found := false
		for _, candidate := range markers {
			if candidate.SessionID != sessionID {
				continue
			}
			if found {
				return nil, nil, true, fmt.Errorf("ambiguous anchor-state markers for session %q", sessionID)
			}
			marker = candidate
			found = true
		}
		if !found {
			// A marker proves anchoring is in use in this receipt directory. Treat
			// sessions without their own marker as expected-but-missing instead of
			// downgrading them to "not expected" when the global policy flag is
			// false.
			return nil, nil, true, nil
		}
		bundleBytes, readErr := readConfinedRegularFile(
			baseDir, marker.BundlePath, maxAnchorBundleBytes, "anchor bundle",
		)
		if readErr != nil {
			return nil, nil, true, readErr
		}
		sum := sha256.Sum256(bundleBytes)
		if hex.EncodeToString(sum[:]) != marker.BundleSHA256 {
			return nil, nil, true, errors.New("anchor bundle hash does not match anchor-state marker")
		}
		bundle, loadErr := loadBundle(bundleBytes)
		if loadErr != nil {
			return nil, nil, true, loadErr
		}
		if bundle.Checkpoint.SessionID != marker.SessionID || bundle.Checkpoint.FinalSeq != marker.FinalSeq ||
			bundle.Checkpoint.RootHash != marker.RootHash || bundle.Backend != marker.Backend ||
			bundle.Proof.LogIndex != marker.LogIndex {
			return nil, nil, true, errors.New("anchor bundle does not match anchor-state marker")
		}
		backend, backendErr := anchorBackend(bundle, localLogPath, rekorKeys)
		if backendErr != nil {
			return nil, nil, true, backendErr
		}
		return &bundle, backend, true, nil
	}, nil
}

type anchorStateMarker = anchor.StateMarker

func loadAnchorMarker(baseDir string) (anchorStateMarker, bool, error) {
	markers, err := loadAnchorMarkers(baseDir)
	if err != nil {
		return anchorStateMarker{}, false, err
	}
	if len(markers) == 0 {
		return anchorStateMarker{}, false, nil
	}
	if len(markers) > 1 {
		return anchorStateMarker{}, false, errors.New("anchor-state index has multiple markers")
	}
	return markers[0], true, nil
}

func loadAnchorMarkers(baseDir string) ([]anchorStateMarker, error) {
	markers, err := anchor.LoadStateMarkers(baseDir)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for _, marker := range markers {
		if marker.AnchoredAt.IsZero() || marker.AnchoredAt.After(now) {
			return nil, errors.New("anchor-state marker has invalid required fields")
		}
	}
	return markers, nil
}

func readConfinedRegularFile(baseDir, relativePath string, maxBytes int64, label string) ([]byte, error) {
	if filepath.IsAbs(relativePath) {
		return nil, fmt.Errorf("read %s: path must be relative to receipt directory", label)
	}
	candidate := filepath.Join(baseDir, filepath.Clean(relativePath))
	rel, err := filepath.Rel(baseDir, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("read %s: path escapes receipt directory", label)
	}
	pathInfo, err := os.Lstat(candidate)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("read %s: symlink is not allowed", label)
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, fmt.Errorf("read %s: resolve path: %w", label, err)
	}
	resolvedRel, err := filepath.Rel(baseDir, resolved)
	if err != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("read %s: resolved path escapes receipt directory", label)
	}
	if resolved != candidate {
		return nil, fmt.Errorf("read %s: symlink is not allowed", label)
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file", label)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("read %s: inspect opened file: %w", label, err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, fmt.Errorf("read %s: file changed during validation", label)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("read %s: exceeds size limit of %d bytes", label, maxBytes)
	}
	return data, nil
}

func anchorBackend(bundle anchor.Bundle, localLogPath string, rekorKeys []crypto.PublicKey) (anchor.Backend, error) {
	switch bundle.Backend {
	case anchor.LocalBackend:
		if strings.TrimSpace(localLogPath) == "" {
			return nil, errLocalAnchorLogPathRequired
		}
		return anchor.LocalLog{Path: localLogPath, LogID: bundle.Proof.LogID}, nil
	case anchor.RekorBackend:
		if len(rekorKeys) == 0 {
			return nil, errors.New("pinned Rekor log key is required to verify Rekor anchor")
		}
		return anchor.RekorLog{TrustedLogKeys: rekorKeys}, nil
	default:
		return nil, fmt.Errorf("unsupported anchor backend %q", bundle.Backend)
	}
}

// ChainAudit describes tamper evidence without claiming operator truthfulness.
type ChainAudit struct {
	SessionID    string
	Consistent   bool
	Failures     int
	Gaps         int
	Forks        int
	AnchorStatus string
	LocalHead    string
	AnchoredHead string
	Detail       string
}

// AuditReceiptChain verifies signatures and chain continuity with the receipt
// package, then verifies any external anchor with the anchor package. It never
// treats receipt labels, key names, or bundle metadata as proof by themselves.
func AuditReceiptChain(in ChainAuditInput) ChainAudit {
	out := ChainAudit{SessionID: in.SessionID, AnchorStatus: AnchorNotExpected}
	if len(in.Receipts) == 0 {
		out.Failures = 1
		out.Detail = "chain inconsistent: no receipts"
		if in.AnchorExpected {
			out.AnchorStatus = AnchorMissing
			out.Detail += "; missing anchor"
		}
		return out
	}
	if len(in.TrustedKeys) == 0 {
		out.Failures = 1
		out.Detail = "chain inconsistent: unknown signer key; no trusted receipt keys configured"
		return auditAnchor(in, out)
	}

	problem, gaps, forks := classifyContinuity(in.Receipts)
	out.Gaps = gaps
	out.Forks = forks
	chainResult := receipt.VerifyChainTrusted(in.Receipts, in.TrustedKeys)
	if !chainResult.Valid {
		out.Failures++
		if problem == "" {
			problem = chainResult.Error
		}
		out.Detail = "chain inconsistent: " + problem
		return auditAnchor(in, out)
	}
	out.LocalHead = chainResult.RootHash
	out.Detail = "chain consistent / 0 gaps detected"
	return auditAnchor(in, out)
}

func classifyContinuity(receipts []receipt.Receipt) (string, int, int) {
	for i := 1; i < len(receipts); i++ {
		prev := receipts[i-1]
		current := receipts[i]
		if current.ActionRecord.ChainSeq == prev.ActionRecord.ChainSeq {
			return fmt.Sprintf("fork detected at chain_seq %d", current.ActionRecord.ChainSeq), 0, 1
		}
		if current.ActionRecord.ChainSeq > prev.ActionRecord.ChainSeq+1 {
			return fmt.Sprintf("gap detected before chain_seq %d", current.ActionRecord.ChainSeq), 1, 0
		}
		if current.ActionRecord.ChainSeq < prev.ActionRecord.ChainSeq {
			return fmt.Sprintf("fork or out-of-order chain_seq %d", current.ActionRecord.ChainSeq), 0, 0
		}
		prevHash, err := receipt.ReceiptHash(prev)
		if err != nil {
			return fmt.Sprintf("could not hash receipt before chain_seq %d: %v", current.ActionRecord.ChainSeq, err), 0, 0
		}
		if current.ActionRecord.ChainPrevHash != prevHash {
			return fmt.Sprintf("prev_hash mismatch at chain_seq %d", current.ActionRecord.ChainSeq), 0, 0
		}
	}
	return "", 0, 0
}

func auditAnchor(in ChainAuditInput, out ChainAudit) ChainAudit {
	if in.AnchorBundle == nil {
		if in.AnchorExpected {
			out.Failures++
			out.AnchorStatus = AnchorMissing
			out.Detail += "; missing anchor"
		}
		out.Consistent = out.Failures == 0
		return out
	}
	out.AnchoredHead = in.AnchorBundle.Checkpoint.RootHash
	if in.AnchorBackend == nil {
		out.Failures++
		out.AnchorStatus = AnchorFailure
		out.Detail += "; anchor verification backend missing"
		return out
	}
	count := in.AnchorBundle.Checkpoint.ReceiptCount
	if count == 0 || count > uint64(len(in.Receipts)) {
		out.Failures++
		out.AnchorStatus = AnchorFailure
		out.Detail += "; anchor receipt range is invalid"
		return out
	}
	report := anchor.VerifyBundle(*in.AnchorBundle, in.Receipts[:count], in.TrustedKeys, in.AnchorBackend)
	if !report.Valid {
		out.Failures++
		out.AnchorStatus = AnchorFailure
		out.Detail += "; anchor verification failed: " + report.Error
		return out
	}
	if count < uint64(len(in.Receipts)) {
		out.Failures++
		out.AnchorStatus = AnchorStale
		out.Detail += fmt.Sprintf("; stale anchor covers %d of %d receipts", count, len(in.Receipts))
		return out
	}
	out.AnchorStatus = AnchorCurrent
	out.Consistent = out.Failures == 0
	return out
}

// TrustKeyRow is one operator-imported key plus facts derived from verified
// receipt signatures and a verified CRL. Static receipt keys carry no signed
// validity certificate, so ValidityWindow deliberately does not invent one.
type TrustKeyRow struct {
	PublicKey        string
	Purpose          string
	Fingerprint      string
	Provenance       string
	ValidityWindow   string
	RevocationStatus string
	RevocationReason string
	BlastRadius      []string
	VerifiedReceipts int
	RejectedReceipts int
}

// TrustKeysPage is the complete read-only trust registry and chain-audit view.
type TrustKeysPage struct {
	Nav       NavContext
	Keys      []TrustKeyRow
	Audits    []ChainAudit
	CRLStatus string
	CRLDetail string
}

// TrustKeys reconstructs usage from receipt evidence on each request. No
// second database or disposable index becomes a source of truth.
func (m *ReadModel) TrustKeys() (TrustKeysPage, error) {
	ids, err := recorder.ListSessions(m.receiptDir)
	if err != nil {
		return TrustKeysPage{}, fmt.Errorf("list sessions: %w", err)
	}
	sessions := make(map[string][]receipt.Receipt, len(ids))
	audits := make([]ChainAudit, 0, len(ids))
	trustedKeys := make([]string, 0, len(m.trustedKeys))
	for key := range m.trustedKeys {
		trustedKeys = append(trustedKeys, key)
	}
	sort.Strings(trustedKeys)
	for _, id := range ids {
		receipts, limited, readErr := receipt.ExtractReceiptsFromSessionDirBounded(m.receiptDir, id, m.receiptReadLimit)
		if readErr != nil {
			return TrustKeysPage{}, fmt.Errorf("read session %s receipts: %w", id, readErr)
		}
		sessions[id] = receipts
		input := ChainAuditInput{SessionID: id, Receipts: receipts, TrustedKeys: trustedKeys}
		if m.anchorResolver != nil {
			input.AnchorBundle, input.AnchorBackend, input.AnchorExpected, readErr = m.anchorResolver(id)
			if readErr != nil {
				audit := AuditReceiptChain(ChainAuditInput{SessionID: id, Receipts: receipts, TrustedKeys: trustedKeys})
				if isAnchorBackendUnconfigured(readErr) {
					audit.AnchorStatus = AnchorUnconfigured
					audit.Detail += "; anchor audit not configured: cannot verify local anchor"
				} else {
					audit.Consistent = false
					audit.Failures++
					audit.AnchorStatus = AnchorFailure
					audit.Detail += "; anchor audit FAILURE: " + readErr.Error()
				}
				audits = append(audits, audit)
				continue
			}
		}
		audit := AuditReceiptChain(input)
		if limited {
			audit.Consistent = false
			audit.Failures++
			audit.Detail += fmt.Sprintf("; audit input truncated at %d recorder entries", m.receiptReadLimit)
		}
		audits = append(audits, audit)
	}
	var crl *license.CRL
	var crlErr error
	if m.trustCRLSource != nil {
		crl, crlErr = m.trustCRLSource()
	}
	page := TrustKeysPage{Keys: BuildTrustKeyRows(m.trustedKeys, sessions, crl, crlErr), Audits: audits}
	switch {
	case crlErr != nil:
		page.CRLStatus = RevocationFailure
		page.CRLDetail = crlErr.Error()
	case crl == nil:
		page.CRLStatus = RevocationNotConfigured
	default:
		page.CRLStatus = "verified signed CRL"
		page.CRLDetail = fmt.Sprintf("generation %d; payload SHA-256 %s", crl.Payload.Generation, crl.SHA256)
	}
	return page, nil
}

func isAnchorBackendUnconfigured(err error) bool {
	return errors.Is(err, errLocalAnchorLogPathRequired) || (err != nil && err.Error() == localAnchorLogPathRequired)
}

// TrustKeyFingerprint returns the SHA-256 fingerprint of the actual Ed25519
// public-key bytes. Human labels never participate in identity or revocation.
func TrustKeyFingerprint(keyHex string) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(keyHex))
	if err != nil {
		return "", fmt.Errorf("decode trusted key: %w", err)
	}
	if len(key) != 32 {
		return "", fmt.Errorf("trusted key length = %d, want 32", len(key))
	}
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:]), nil
}

// BuildTrustKeyRows derives each key's blast radius from receipts whose
// signatures verify against that key. crl must already have passed the license
// package's signature and expiry checks; crlErr makes every row fail closed.
// The license CRL keys intermediate revocations by certificate serial, while a
// static receipt key has no root-verified certificate/serial binding. The view
// therefore refuses to infer revocation identity from a coincidentally equal
// key fingerprint.
func BuildTrustKeyRows(
	trusted map[string]TrustedKey,
	sessions map[string][]receipt.Receipt,
	crl *license.CRL,
	crlErr error,
) []TrustKeyRow {
	keys := make([]string, 0, len(trusted))
	for key := range trusted {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := make([]TrustKeyRow, 0, len(keys))
	for _, key := range keys {
		fingerprint, fingerprintErr := TrustKeyFingerprint(key)
		row := TrustKeyRow{
			PublicKey: key, Purpose: "receipt signing", Fingerprint: fingerprint,
			Provenance: formatKeyProvenance(trusted[key]), ValidityWindow: "not declared for static key",
		}
		if fingerprintErr != nil {
			row.RevocationStatus = RevocationFailure
			row.RevocationReason = fingerprintErr.Error()
		} else {
			applyRevocation(&row, crl, crlErr)
		}
		seenTypes := make(map[string]struct{})
		for _, receipts := range sessions {
			for _, candidate := range receipts {
				if candidate.SignerKey != key {
					continue
				}
				if err := receipt.VerifyWithKey(candidate, key); err != nil {
					row.RejectedReceipts++
					continue
				}
				row.VerifiedReceipts++
				seenTypes[string(candidate.ActionRecord.ActionType)] = struct{}{}
			}
		}
		for actionType := range seenTypes {
			row.BlastRadius = append(row.BlastRadius, actionType)
		}
		sort.Strings(row.BlastRadius)
		rows = append(rows, row)
	}
	return rows
}

func formatKeyProvenance(key TrustedKey) string {
	parts := make([]string, 0, 3)
	if key.ProvenanceKind != "" {
		parts = append(parts, key.ProvenanceKind)
	}
	if key.Location != "" {
		parts = append(parts, key.Location)
	}
	if key.Source != "" {
		parts = append(parts, key.Source)
	}
	if len(parts) == 0 {
		return "static registry entry; source not declared"
	}
	return strings.Join(parts, " — ")
}

func applyRevocation(row *TrustKeyRow, crl *license.CRL, crlErr error) {
	switch {
	case crlErr != nil:
		row.RevocationStatus = RevocationFailure
		row.RevocationReason = crlErr.Error()
	case crl == nil:
		row.RevocationStatus = RevocationNotConfigured
	default:
		row.RevocationStatus = RevocationUnbound
		row.RevocationReason = "verified license CRL uses certificate serials; this static receipt key has no root-verified serial binding"
	}
}
