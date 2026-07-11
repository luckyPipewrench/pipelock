// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package anchor records and verifies external receipt-chain checkpoints.
package anchor

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	BundleVersion     = 1
	LocalBackend      = "local"
	RekorBackend      = "rekor"
	DefaultLocalLogID = "local-fake-log"
	DefaultRekorURL   = "https://rekor.sigstore.dev"
	GenesisHash       = "genesis"

	dirPermissions  = 0o750
	filePermissions = 0o600

	stateMarkerSchema   = "pipelock.anchorstate.v1"
	stateMarkerIndexDir = "anchor-state.d"
	legacyStateMarker   = "anchor-state.json"
	maxStateMarkerBytes = 64 * 1024
)

var DefaultLimits = []string{
	"Anchor bundles bind a verified receipt-chain checkpoint to backend proof material.",
	"The local backend is a deterministic test backend, not an operator-independent witness.",
	"Anchoring does not prove real-time truth by whoever held the receipt signing key.",
}

var rekorLimits = []string{
	"Rekor verification proves the checkpoint entry has a valid SET and inclusion proof under a pinned Rekor log key.",
	"Rekor anchoring does not prove the checkpoint was witnessed before every later action unless the anchored checkpoint covers the whole receipt chain being verified.",
	"Rekor anchoring does not prove the log remained globally consistent after the recorded checkpoint without a later consistency audit.",
	"Anchoring does not prove real-time truth by whoever held the receipt signing key.",
}

type Backend interface {
	Submit(Checkpoint) (Proof, error)
	Verify(Proof, Checkpoint) error
}

type Checkpoint struct {
	SessionID    string    `json:"session_id"`
	FinalSeq     uint64    `json:"final_seq"`
	RootHash     string    `json:"root_hash"`
	ReceiptCount uint64    `json:"receipt_count"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	SignerKeys   []string  `json:"signer_keys"`
}

type Proof struct {
	Backend     string      `json:"backend"`
	LogID       string      `json:"log_id"`
	LogIndex    uint64      `json:"log_index"`
	EntryHash   string      `json:"entry_hash"`
	LogRootHash string      `json:"log_root_hash"`
	Rekor       *RekorProof `json:"rekor,omitempty"`
}

type RekorProof struct {
	URL                  string               `json:"url,omitempty"`
	UUID                 string               `json:"uuid,omitempty"`
	Body                 string               `json:"body,omitempty"`
	PublicKey            string               `json:"public_key,omitempty"`
	Signature            string               `json:"signature,omitempty"`
	IntegratedTime       int64                `json:"integrated_time,omitempty"`
	SignedEntryTimestamp string               `json:"signed_entry_timestamp,omitempty"`
	InclusionProof       *RekorInclusionProof `json:"inclusion_proof,omitempty"`
}

type RekorInclusionProof struct {
	RootHash   string   `json:"root_hash"`
	LogIndex   uint64   `json:"log_index"`
	TreeSize   uint64   `json:"tree_size"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

type Bundle struct {
	Version    int        `json:"version"`
	Backend    string     `json:"backend"`
	CreatedAt  time.Time  `json:"created_at"`
	Checkpoint Checkpoint `json:"checkpoint"`
	Proof      Proof      `json:"proof"`
	Limits     []string   `json:"limits"`
}

type StateMarker struct {
	Schema       string    `json:"schema"`
	SessionID    string    `json:"session_id"`
	FinalSeq     uint64    `json:"final_seq"`
	RootHash     string    `json:"root_hash"`
	Backend      string    `json:"backend"`
	LogIndex     uint64    `json:"log_index"`
	AnchoredAt   time.Time `json:"anchored_at"`
	BundleSHA256 string    `json:"bundle_sha256"`
	BundlePath   string    `json:"bundle_path"`
}

type VerifyReport struct {
	Valid        bool       `json:"valid"`
	Backend      string     `json:"backend,omitempty"`
	SessionID    string     `json:"session_id,omitempty"`
	ReceiptCount uint64     `json:"receipt_count,omitempty"`
	FinalSeq     uint64     `json:"final_seq,omitempty"`
	RootHash     string     `json:"root_hash,omitempty"`
	Proof        Proof      `json:"proof,omitempty"`
	Limits       []string   `json:"limits,omitempty"`
	Error        string     `json:"error,omitempty"`
	Checkpoint   Checkpoint `json:"checkpoint,omitempty"`
}

func BuildCheckpoint(sessionID string, receipts []receipt.Receipt, trustedKeys []string) (Checkpoint, error) {
	if len(receipts) == 0 {
		return Checkpoint{}, errors.New("empty receipt chain")
	}
	result := receipt.VerifyChainTrusted(receipts, trustedKeys)
	if !result.Valid {
		return Checkpoint{}, fmt.Errorf("invalid receipt chain: %s", result.Error)
	}
	if len(trustedKeys) == 0 {
		return Checkpoint{}, errors.New("trust anchor required: pass at least one trusted signer key")
	}
	root, err := receipt.ComputeTranscriptRootTrusted(sessionID, receipts, trustedKeys)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("compute transcript root: %w", err)
	}
	return Checkpoint{
		SessionID:    root.SessionID,
		FinalSeq:     root.FinalSeq,
		RootHash:     root.RootHash,
		ReceiptCount: root.ReceiptCount,
		StartTime:    root.StartTime,
		EndTime:      root.EndTime,
		SignerKeys:   append([]string(nil), result.SignerKeys...),
	}, nil
}

func NewBundle(checkpoint Checkpoint, proof Proof) Bundle {
	return Bundle{
		Version:    BundleVersion,
		Backend:    proof.Backend,
		CreatedAt:  time.Now().UTC(),
		Checkpoint: checkpoint,
		Proof:      proof,
		Limits:     limitsForBackend(proof.Backend),
	}
}

func VerifyBundle(b Bundle, receipts []receipt.Receipt, trustedKeys []string, backend Backend) VerifyReport {
	report := VerifyReport{
		Valid:      false,
		Proof:      b.Proof,
		Limits:     limitsForBackend(b.Proof.Backend),
		Checkpoint: b.Checkpoint,
	}
	if b.Version != BundleVersion {
		report.Error = fmt.Sprintf("unsupported anchor bundle version %d", b.Version)
		return report
	}
	if b.Backend != b.Proof.Backend {
		report.Error = fmt.Sprintf("anchor bundle backend %q does not match proof backend %q", b.Backend, b.Proof.Backend)
		return report
	}
	if backend == nil {
		report.Error = "anchor backend required"
		return report
	}
	computed, err := BuildCheckpoint(b.Checkpoint.SessionID, receipts, trustedKeys)
	if err != nil {
		report.Error = err.Error()
		return report
	}
	if !checkpointsEqual(computed, b.Checkpoint) {
		report.Error = "receipt chain checkpoint does not match anchor bundle"
		return report
	}
	if err := backend.Verify(b.Proof, b.Checkpoint); err != nil {
		report.Error = err.Error()
		return report
	}
	report.Valid = true
	report.Backend = b.Proof.Backend
	report.SessionID = computed.SessionID
	report.ReceiptCount = computed.ReceiptCount
	report.FinalSeq = computed.FinalSeq
	report.RootHash = computed.RootHash
	return report
}

func limitsForBackend(backend string) []string {
	switch backend {
	case RekorBackend:
		return append([]string(nil), rekorLimits...)
	default:
		return append([]string(nil), DefaultLimits...)
	}
}

func LoadBundle(path string) (Bundle, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return Bundle{}, fmt.Errorf("read anchor bundle: %w", err)
	}
	return LoadBundleBytes(data)
}

// LoadBundleBytes strictly parses an anchor bundle from caller-supplied bytes.
// Callers that authenticate or hash a bounded read can use this entry point to
// ensure verification and parsing operate on the exact same evidence.
func LoadBundleBytes(data []byte) (Bundle, error) {
	var b Bundle
	if err := decodeStrict(data, &b); err != nil {
		return Bundle{}, fmt.Errorf("parse anchor bundle: %w", err)
	}
	return b, nil
}

func WriteBundle(path string, b Bundle) error {
	data, err := bundleBytes(b)
	if err != nil {
		return err
	}
	return writeBundleFile(filepath.Clean(path), data)
}

// WriteBundleUnderDir writes an anchor bundle under root without trusting
// pathnames after the caller has resolved policy. On Unix-like platforms it uses
// descriptor-relative no-follow operations for every component.
func WriteBundleUnderDir(root, rel string, b Bundle) ([]byte, error) {
	cleanRel := filepath.Clean(filepath.FromSlash(rel))
	if filepath.IsAbs(cleanRel) || cleanRel == "." || cleanRel == ".." || strings.HasPrefix(cleanRel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("anchor bundle path must stay under receipt directory")
	}
	data, err := bundleBytes(b)
	if err != nil {
		return nil, err
	}
	if err := writeBundleFileUnderDir(filepath.Clean(root), cleanRel, data); err != nil {
		return nil, err
	}
	return data, nil
}

func bundleBytes(b Bundle) ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal anchor bundle: %w", err)
	}
	return append(data, '\n'), nil
}

func WriteStateMarker(dir string, marker StateMarker) error {
	marker.Schema = stateMarkerSchema
	if err := validateStateMarker(marker); err != nil {
		return err
	}
	data, err := json.Marshal(marker)
	if err != nil {
		return fmt.Errorf("marshal anchor-state marker: %w", err)
	}
	cleanDir := filepath.Clean(dir)
	return writeStateMarkerFile(cleanDir, marker, append(data, '\n'))
}

func StateMarkerPath(dir string, marker StateMarker) (string, error) {
	name, err := stateMarkerFileName(marker)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Clean(dir), stateMarkerIndexDir, name), nil
}

func validateStateMarkerIndexDir(indexDir string) error {
	info, err := os.Lstat(indexDir)
	if err != nil {
		return fmt.Errorf("inspect anchor-state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("anchor-state directory is not a regular directory")
	}
	return nil
}

func LoadStateMarkers(dir string) ([]StateMarker, error) {
	cleanDir := filepath.Clean(dir)
	var markers []StateMarker
	if marker, found, err := LoadStateMarkerFile(filepath.Join(cleanDir, legacyStateMarker)); err != nil {
		return nil, err
	} else if found {
		markers = append(markers, marker)
	}

	indexDir := filepath.Join(cleanDir, stateMarkerIndexDir)
	_, err := os.Lstat(indexDir)
	if errors.Is(err, os.ErrNotExist) {
		return markers, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect anchor-state index: %w", err)
	}
	if err := validateStateMarkerIndexDir(indexDir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(indexDir)
	if err != nil {
		return nil, fmt.Errorf("read anchor-state index: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	seen := make(map[string]string, len(markers)+len(entries))
	for _, marker := range markers {
		key := stateMarkerIdentity(marker)
		seen[key] = legacyStateMarker
	}
	for _, entry := range entries {
		if IsStateMarkerTempName(entry.Name()) {
			continue
		}
		if entry.IsDir() {
			return nil, fmt.Errorf("read anchor-state index: %s is not a regular marker", entry.Name())
		}
		if filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("read anchor-state index: unexpected marker name %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect anchor-state marker %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("read anchor-state index: %s is not a regular marker", entry.Name())
		}
		path := filepath.Join(indexDir, entry.Name())
		marker, found, err := LoadStateMarkerFile(path)
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		want, err := stateMarkerFileName(marker)
		if err != nil {
			return nil, err
		}
		if entry.Name() != want {
			return nil, fmt.Errorf("anchor-state marker %q does not match marker identity", entry.Name())
		}
		key := stateMarkerIdentity(marker)
		if previous, ok := seen[key]; ok {
			return nil, fmt.Errorf("anchor-state marker %q duplicates %q", entry.Name(), previous)
		}
		seen[key] = entry.Name()
		markers = append(markers, marker)
	}
	return markers, nil
}

// IsStateMarkerTempName reports whether name matches the private temp-file
// pattern produced by WriteStateMarker before the final atomic rename.
func IsStateMarkerTempName(name string) bool {
	const (
		prefix = ".anchor-state-"
		suffix = ".tmp"
	)
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	random := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	if len(random) == 0 {
		return false
	}
	if len(random) <= 10 {
		for _, r := range random {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}
	if len(random) != 32 {
		return false
	}
	for _, r := range random {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func stateMarkerTempName() (string, error) {
	var raw [16]byte
	if _, err := crand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate anchor-state temp name: %w", err)
	}
	return ".anchor-state-" + hex.EncodeToString(raw[:]) + ".tmp", nil
}

// LoadStateMarkerFile strictly reads and validates one anchor-state marker file.
// It rejects symlinks, non-regular files, oversized files, duplicate JSON keys,
// unknown fields, trailing JSON, and local replacement races.
func LoadStateMarkerFile(path string) (StateMarker, bool, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if errors.Is(err, os.ErrNotExist) {
		return StateMarker{}, false, nil
	}
	if err != nil {
		return StateMarker{}, false, fmt.Errorf("inspect anchor-state marker: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return StateMarker{}, false, errors.New("anchor-state marker is not a regular file")
	}
	if info.Size() > maxStateMarkerBytes {
		return StateMarker{}, false, fmt.Errorf("anchor-state marker exceeds size limit of %d bytes", maxStateMarkerBytes)
	}
	file, err := os.Open(clean) // #nosec G304 -- caller supplies an anchor-state path; Lstat and fstat below fail closed on races.
	if err != nil {
		return StateMarker{}, false, fmt.Errorf("read anchor-state marker: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return StateMarker{}, false, fmt.Errorf("inspect opened anchor-state marker: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return StateMarker{}, false, errors.New("anchor-state marker changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateMarkerBytes+1))
	if err != nil {
		return StateMarker{}, false, fmt.Errorf("read anchor-state marker: %w", err)
	}
	if len(data) > maxStateMarkerBytes {
		return StateMarker{}, false, fmt.Errorf("anchor-state marker exceeds size limit of %d bytes", maxStateMarkerBytes)
	}
	var marker StateMarker
	if err := decodeStrict(data, &marker); err != nil {
		return StateMarker{}, false, fmt.Errorf("parse anchor-state marker: %w", err)
	}
	if err := validateStateMarker(marker); err != nil {
		return StateMarker{}, false, err
	}
	return marker, true, nil
}

func validateStateMarker(marker StateMarker) error {
	if marker.Schema != stateMarkerSchema {
		return fmt.Errorf("anchor-state marker schema %q is invalid", marker.Schema)
	}
	if strings.TrimSpace(marker.SessionID) == "" {
		return errors.New("anchor-state marker session_id is empty")
	}
	if !isLowerHexBytes(marker.RootHash, sha256.Size) {
		return errors.New("anchor-state marker root_hash is invalid")
	}
	if !isLowerHexBytes(marker.BundleSHA256, sha256.Size) {
		return errors.New("anchor-state marker bundle_sha256 is invalid")
	}
	if strings.TrimSpace(marker.BundlePath) == "" {
		return errors.New("anchor-state marker bundle_path is empty")
	}
	return nil
}

func stateMarkerFileName(marker StateMarker) (string, error) {
	if marker.SessionID == "" {
		return "", errors.New("anchor-state marker session_id is empty")
	}
	if marker.RootHash == "" {
		return "", errors.New("anchor-state marker root_hash is empty")
	}
	sum := sha256.Sum256([]byte(stateMarkerIdentity(marker)))
	return hex.EncodeToString(sum[:]) + ".json", nil
}

func stateMarkerIdentity(marker StateMarker) string {
	return marker.SessionID + "\x00" + strconv.FormatUint(marker.FinalSeq, 10) + "\x00" + marker.RootHash
}

func isLowerHexBytes(value string, bytesLen int) bool {
	if len(value) != bytesLen*2 {
		return false
	}
	for _, ch := range value {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return false
	}
	return true
}

func checkpointsEqual(a, b Checkpoint) bool {
	if a.SessionID != b.SessionID ||
		a.FinalSeq != b.FinalSeq ||
		a.RootHash != b.RootHash ||
		a.ReceiptCount != b.ReceiptCount ||
		!a.StartTime.Equal(b.StartTime) ||
		!a.EndTime.Equal(b.EndTime) ||
		len(a.SignerKeys) != len(b.SignerKeys) {
		return false
	}
	for i := range a.SignerKeys {
		if a.SignerKeys[i] != b.SignerKeys[i] {
			return false
		}
	}
	return true
}

func decodeStrict(data []byte, dst any) error {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
