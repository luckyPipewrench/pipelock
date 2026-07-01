// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	rekorHashedRekordKind       = "hashedrekord"
	rekorHashedRekordAPIVersion = "0.0.1"
	rekorSHA256Algorithm        = "sha256"
)

// RekorLog submits receipt-chain checkpoints to Rekor and stores the returned
// submission metadata. Verify requires a pinned Rekor log public key and checks
// the SET, signed checkpoint, and inclusion proof offline.
type RekorLog struct {
	URL            string
	HTTPClient     *http.Client
	Signer         ed25519.PrivateKey
	TrustedLogKeys []crypto.PublicKey
}

type rekorSubmitRequest struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       rekorSubmitSpec `json:"spec"`
}

type rekorSubmitSpec struct {
	Data      rekorData      `json:"data"`
	Signature rekorSignature `json:"signature"`
}

type rekorData struct {
	Hash rekorHash `json:"hash"`
}

type rekorHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type rekorSignature struct {
	Content   string         `json:"content"`
	PublicKey rekorPublicKey `json:"publicKey"`
}

type rekorPublicKey struct {
	Content string `json:"content"`
}

type rekorEntry struct {
	LogID          string            `json:"logID"`
	LogIndex       uint64            `json:"logIndex"`
	IntegratedTime int64             `json:"integratedTime"`
	Body           string            `json:"body"`
	Verification   rekorVerification `json:"verification"`
}

type rekorVerification struct {
	SignedEntryTimestamp string              `json:"signedEntryTimestamp"`
	InclusionProof       rekorInclusionProof `json:"inclusionProof"`
}

type rekorInclusionProof struct {
	RootHash   string   `json:"rootHash"`
	LogIndex   uint64   `json:"logIndex"`
	TreeSize   uint64   `json:"treeSize"`
	Hashes     []string `json:"hashes"`
	Checkpoint string   `json:"checkpoint"`
}

func (r RekorLog) Submit(checkpoint Checkpoint) (Proof, error) {
	if len(r.Signer) == 0 {
		return Proof{}, errors.New("rekor signing key required")
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		return Proof{}, err
	}
	publicKey, signature, err := signRekorCheckpoint(checkpointBytes, r.Signer)
	if err != nil {
		return Proof{}, err
	}
	body := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: rekorSHA256Algorithm,
				Value:     sha256Hex(checkpointBytes),
			}},
			Signature: rekorSignature{
				Content:   signature,
				PublicKey: rekorPublicKey{Content: publicKey},
			},
		},
	}
	requestBody, err := json.Marshal(body)
	if err != nil {
		return Proof{}, fmt.Errorf("marshal rekor entry: %w", err)
	}
	baseURL, err := normalizeRekorBaseURL(r.URL)
	if err != nil {
		return Proof{}, fmt.Errorf("normalize rekor URL: %w", err)
	}
	endpoint, err := rekorEntriesURL(baseURL)
	if err != nil {
		return Proof{}, fmt.Errorf("build rekor entries URL: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return Proof{}, fmt.Errorf("build rekor request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Proof{}, fmt.Errorf("submit rekor entry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return Proof{}, fmt.Errorf("read rekor response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Proof{}, fmt.Errorf("rekor submit status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	entry, uuid, err := decodeRekorEntry(respBody)
	if err != nil {
		return Proof{}, err
	}
	if uuid == "" {
		return Proof{}, errors.New("rekor response UUID required")
	}
	if entry.LogID == "" {
		return Proof{}, errors.New("rekor response logID required")
	}
	if entry.Body == "" {
		return Proof{}, errors.New("rekor response body required")
	}
	proof := Proof{
		Backend:     RekorBackend,
		LogID:       entry.LogID,
		LogIndex:    entry.LogIndex,
		EntryHash:   sha256Hex([]byte(entry.Body)),
		LogRootHash: entry.Verification.InclusionProof.RootHash,
		Rekor: &RekorProof{
			URL:                  baseURL,
			UUID:                 uuid,
			Body:                 entry.Body,
			PublicKey:            publicKey,
			Signature:            signature,
			IntegratedTime:       entry.IntegratedTime,
			SignedEntryTimestamp: entry.Verification.SignedEntryTimestamp,
			InclusionProof: &RekorInclusionProof{
				RootHash:   entry.Verification.InclusionProof.RootHash,
				LogIndex:   entry.Verification.InclusionProof.LogIndex,
				TreeSize:   entry.Verification.InclusionProof.TreeSize,
				Hashes:     append([]string(nil), entry.Verification.InclusionProof.Hashes...),
				Checkpoint: entry.Verification.InclusionProof.Checkpoint,
			},
		},
	}
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		return Proof{}, fmt.Errorf("validate submitted rekor proof: %w", err)
	}
	return proof, nil
}

func (r RekorLog) Verify(proof Proof, checkpoint Checkpoint) error {
	if err := validateRekorSubmissionRecord(proof, checkpoint); err != nil {
		return err
	}
	if len(r.TrustedLogKeys) == 0 {
		return errors.New("trusted Rekor log public key required")
	}
	if err := verifyRekorSET(proof, r.TrustedLogKeys); err != nil {
		return err
	}
	if err := verifyRekorCheckpoint(proof, r.TrustedLogKeys); err != nil {
		return err
	}
	if err := verifyRekorInclusion(proof); err != nil {
		return err
	}
	return nil
}

func validateRekorSubmissionRecord(proof Proof, checkpoint Checkpoint) error {
	if proof.Backend != RekorBackend {
		return fmt.Errorf("anchor proof backend %q is not %q", proof.Backend, RekorBackend)
	}
	if proof.Rekor == nil {
		return errors.New("rekor proof required")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "URL", value: proof.Rekor.URL},
		{name: "UUID", value: proof.Rekor.UUID},
		{name: "log_id", value: proof.LogID},
		{name: "body", value: proof.Rekor.Body},
		{name: "entry_hash", value: proof.EntryHash},
		{name: "log_root_hash", value: proof.LogRootHash},
		{name: "signed_entry_timestamp", value: proof.Rekor.SignedEntryTimestamp},
	} {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("rekor proof %s required", field.name)
		}
	}
	if proof.Rekor.IntegratedTime <= 0 {
		return errors.New("rekor proof integrated_time required")
	}
	if proof.Rekor.InclusionProof == nil {
		return errors.New("rekor proof inclusion_proof required")
	}
	if err := validateRekorInclusionProof(proof); err != nil {
		return err
	}
	normalizedURL, err := normalizeRekorBaseURL(proof.Rekor.URL)
	if err != nil {
		return fmt.Errorf("rekor proof URL invalid: %w", err)
	}
	if proof.Rekor.URL != normalizedURL {
		return errors.New("rekor proof URL is not canonical")
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		return err
	}
	if err := verifyRekorSignature(checkpointBytes, proof.Rekor.PublicKey, proof.Rekor.Signature); err != nil {
		return err
	}
	bodyBytes, err := base64.StdEncoding.DecodeString(proof.Rekor.Body)
	if err != nil {
		return fmt.Errorf("decode rekor body: %w", err)
	}
	if proof.EntryHash != sha256Hex([]byte(proof.Rekor.Body)) {
		return errors.New("rekor proof entry_hash does not match encoded body")
	}
	var body rekorSubmitRequest
	if err := decodeStrict(bodyBytes, &body); err != nil {
		return fmt.Errorf("parse rekor body: %w", err)
	}
	if body.APIVersion != rekorHashedRekordAPIVersion || body.Kind != rekorHashedRekordKind {
		return fmt.Errorf("unsupported rekor body %s/%s", body.Kind, body.APIVersion)
	}
	if body.Spec.Data.Hash.Algorithm != rekorSHA256Algorithm {
		return fmt.Errorf("unsupported rekor hash algorithm %q", body.Spec.Data.Hash.Algorithm)
	}
	if body.Spec.Data.Hash.Value != sha256Hex(checkpointBytes) {
		return errors.New("rekor body checkpoint digest does not match bundle checkpoint")
	}
	if body.Spec.Signature.Content != proof.Rekor.Signature {
		return errors.New("rekor body signature does not match proof signature")
	}
	if body.Spec.Signature.PublicKey.Content != proof.Rekor.PublicKey {
		return errors.New("rekor body public key does not match proof public key")
	}
	return nil
}

func validateRekorInclusionProof(proof Proof) error {
	inc := proof.Rekor.InclusionProof
	if strings.TrimSpace(inc.RootHash) == "" {
		return errors.New("rekor proof inclusion_proof.root_hash required")
	}
	if inc.RootHash != proof.LogRootHash {
		return errors.New("rekor proof inclusion_proof.root_hash does not match log_root_hash")
	}
	if inc.TreeSize == 0 {
		return errors.New("rekor proof inclusion_proof.tree_size required")
	}
	if inc.LogIndex != proof.LogIndex {
		return fmt.Errorf("rekor proof inclusion_proof.log_index %d does not match log_index %d", inc.LogIndex, proof.LogIndex)
	}
	if inc.LogIndex >= inc.TreeSize {
		return fmt.Errorf("rekor proof inclusion_proof.log_index %d outside tree_size %d", inc.LogIndex, inc.TreeSize)
	}
	if strings.TrimSpace(inc.Checkpoint) == "" {
		return errors.New("rekor proof inclusion_proof.checkpoint required")
	}
	root, err := hex.DecodeString(inc.RootHash)
	if err != nil {
		return fmt.Errorf("decode rekor inclusion root_hash: %w", err)
	}
	if len(root) != sha256.Size {
		return fmt.Errorf("rekor proof inclusion_proof.root_hash length = %d, want %d", len(root), sha256.Size)
	}
	for i, hash := range inc.Hashes {
		decoded, err := hex.DecodeString(hash)
		if err != nil {
			return fmt.Errorf("decode rekor inclusion proof hash %d: %w", i, err)
		}
		if len(decoded) != sha256.Size {
			return fmt.Errorf("rekor inclusion proof hash %d length = %d, want %d", i, len(decoded), sha256.Size)
		}
	}
	return nil
}

// LoadRekorPrivateKey loads the Ed25519 key used to sign Rekor submission
// bodies before they are posted.
func LoadRekorPrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := domsigning.LoadPrivateKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("load rekor signing key: %w", err)
	}
	return key, nil
}

func LoadRekorPublicKeys(inputs []string) ([]crypto.PublicKey, error) {
	keys := make([]crypto.PublicKey, 0, len(inputs))
	for _, input := range inputs {
		key, err := LoadRekorPublicKey(input)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func LoadRekorPublicKey(pathOrValue string) (crypto.PublicKey, error) {
	input := strings.TrimSpace(pathOrValue)
	if input == "" {
		return nil, errors.New("rekor log public key is empty")
	}
	if strings.Contains(input, "\n") || strings.HasPrefix(input, "-----BEGIN ") {
		return ParseRekorPublicKey(input)
	}
	cleanPath := filepath.Clean(input)
	if _, err := os.Stat(cleanPath); err == nil {
		data, readErr := os.ReadFile(cleanPath)
		if readErr != nil {
			return nil, fmt.Errorf("read rekor log public key: %w", readErr)
		}
		key, parseErr := ParseRekorPublicKey(string(data))
		if parseErr != nil {
			return nil, fmt.Errorf("parse rekor log public key file: %w", parseErr)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read rekor log public key: %w", err)
	}
	if strings.ContainsAny(input, "/\\") || strings.HasPrefix(input, ".") || filepath.Ext(input) != "" {
		return nil, fmt.Errorf("read rekor log public key file %s: %w", cleanPath, os.ErrNotExist)
	}
	return ParseRekorPublicKey(input)
}

func ParseRekorPublicKey(encoded string) (crypto.PublicKey, error) {
	trimmed := strings.TrimSpace(encoded)
	if trimmed == "" {
		return nil, errors.New("rekor log public key is empty")
	}
	if block, _ := pem.Decode([]byte(trimmed)); block != nil {
		switch block.Type {
		case "PUBLIC KEY":
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PEM public key: %w", err)
			}
			return key, nil
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PEM certificate: %w", err)
			}
			return cert.PublicKey, nil
		default:
			return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
		}
	}
	key, err := domsigning.ParsePublicKey(trimmed)
	if err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("parse rekor log public key: %w", err)
}

func checkpointBytes(checkpoint Checkpoint) ([]byte, error) {
	data, err := json.Marshal(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("marshal checkpoint: %w", err)
	}
	return data, nil
}

func signRekorCheckpoint(data []byte, priv ed25519.PrivateKey) (publicKey string, signature string, err error) {
	if err := domsigning.ValidatePrivateKeyConsistency(priv); err != nil {
		return "", "", fmt.Errorf("validate rekor signing key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", errors.New("rekor signing key public key is not ed25519")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("marshal rekor public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if len(pemBytes) == 0 {
		return "", "", errors.New("encode rekor public key")
	}
	return base64.StdEncoding.EncodeToString(pemBytes), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data)), nil
}

func verifyRekorSignature(data []byte, publicKey, signature string) error {
	if publicKey == "" || signature == "" {
		return errors.New("rekor proof public key and signature required")
	}
	pemBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return fmt.Errorf("decode rekor public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return errors.New("parse rekor public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse rekor public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return errors.New("rekor public key is not ed25519")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode rekor signature: %w", err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("rekor checkpoint signature invalid")
	}
	return nil
}

func verifyRekorSET(proof Proof, keys []crypto.PublicKey) error {
	if proof.LogIndex > math.MaxInt64 {
		return fmt.Errorf("rekor proof log_index %d overflows SET payload", proof.LogIndex)
	}
	sig, err := base64.StdEncoding.DecodeString(proof.Rekor.SignedEntryTimestamp)
	if err != nil {
		return fmt.Errorf("decode rekor signed_entry_timestamp: %w", err)
	}
	payload, err := canonicalRekorSETPayload(proof)
	if err != nil {
		return err
	}
	if verifyWithAnyKey(keys, payload, sig) {
		return nil
	}
	return errors.New("rekor signed_entry_timestamp verification failed")
}

func canonicalRekorSETPayload(proof Proof) ([]byte, error) {
	// Rekor signs the JCS form of exactly these four fields. For this shape,
	// JCS is normal JSON string escaping plus lexicographic field order:
	// body, integratedTime, logID, logIndex.
	body, err := json.Marshal(proof.Rekor.Body)
	if err != nil {
		return nil, fmt.Errorf("marshal rekor SET body: %w", err)
	}
	logID, err := json.Marshal(proof.LogID)
	if err != nil {
		return nil, fmt.Errorf("marshal rekor SET logID: %w", err)
	}
	var out bytes.Buffer
	out.WriteString(`{"body":`)
	out.Write(body)
	out.WriteString(`,"integratedTime":`)
	_, _ = fmt.Fprintf(&out, "%d", proof.Rekor.IntegratedTime)
	out.WriteString(`,"logID":`)
	out.Write(logID)
	out.WriteString(`,"logIndex":`)
	_, _ = fmt.Fprintf(&out, "%d", proof.LogIndex)
	out.WriteByte('}')
	return out.Bytes(), nil
}

func verifyRekorCheckpoint(proof Proof, keys []crypto.PublicKey) error {
	checkpoint, err := parseSignedRekorCheckpoint(proof.Rekor.InclusionProof.Checkpoint)
	if err != nil {
		return err
	}
	root, err := hex.DecodeString(proof.Rekor.InclusionProof.RootHash)
	if err != nil {
		return fmt.Errorf("decode rekor inclusion root_hash: %w", err)
	}
	if !bytes.Equal(root, checkpoint.RootHash) {
		return errors.New("rekor checkpoint root hash does not match inclusion proof")
	}
	if checkpoint.TreeSize != proof.Rekor.InclusionProof.TreeSize {
		return errors.New("rekor checkpoint tree size does not match inclusion proof")
	}
	for _, key := range keys {
		for _, sig := range checkpoint.Signatures {
			if sig.KeyHash == publicKeyHash(key) && verifySignature(key, checkpoint.Note, sig.Signature) {
				return nil
			}
		}
	}
	return errors.New("rekor checkpoint signature verification failed")
}

type signedRekorCheckpoint struct {
	Note       []byte
	TreeSize   uint64
	RootHash   []byte
	Signatures []rekorNoteSignature
}

type rekorNoteSignature struct {
	Name      string
	KeyHash   uint32
	Signature []byte
}

func parseSignedRekorCheckpoint(raw string) (signedRekorCheckpoint, error) {
	data := []byte(raw)
	split := bytes.LastIndex(data, []byte("\n\n"))
	if split < 0 {
		return signedRekorCheckpoint{}, errors.New("rekor checkpoint malformed signed note")
	}
	note := data[:split+1]
	signatureBlock := data[split+2:]
	if len(signatureBlock) == 0 || signatureBlock[len(signatureBlock)-1] != '\n' {
		return signedRekorCheckpoint{}, errors.New("rekor checkpoint malformed signature block")
	}
	lines := bytes.Split(note, []byte("\n"))
	if len(lines) < 4 {
		return signedRekorCheckpoint{}, errors.New("rekor checkpoint has too few lines")
	}
	if len(lines[0]) == 0 {
		return signedRekorCheckpoint{}, errors.New("rekor checkpoint origin is empty")
	}
	treeSize, err := parseUintLine(lines[1], "tree size")
	if err != nil {
		return signedRekorCheckpoint{}, err
	}
	root, err := base64.StdEncoding.DecodeString(string(lines[2]))
	if err != nil {
		return signedRekorCheckpoint{}, fmt.Errorf("decode rekor checkpoint root hash: %w", err)
	}
	signatures, err := parseRekorNoteSignatures(signatureBlock)
	if err != nil {
		return signedRekorCheckpoint{}, err
	}
	return signedRekorCheckpoint{Note: note, TreeSize: treeSize, RootHash: root, Signatures: signatures}, nil
}

func parseUintLine(line []byte, name string) (uint64, error) {
	var value uint64
	if len(line) == 0 {
		return 0, fmt.Errorf("rekor checkpoint %s is empty", name)
	}
	for _, b := range line {
		if b < '0' || b > '9' {
			return 0, fmt.Errorf("rekor checkpoint %s is not numeric", name)
		}
		if value > (math.MaxUint64-uint64(b-'0'))/10 {
			return 0, fmt.Errorf("rekor checkpoint %s overflows uint64", name)
		}
		value = value*10 + uint64(b-'0')
	}
	return value, nil
}

func parseRekorNoteSignatures(data []byte) ([]rekorNoteSignature, error) {
	lines := bytes.Split(data, []byte("\n"))
	var signatures []rekorNoteSignature
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		rest, ok := strings.CutPrefix(string(line), "\u2014 ")
		if !ok {
			return nil, errors.New("rekor checkpoint signature line malformed")
		}
		name, encoded, ok := strings.Cut(rest, " ")
		if !ok || name == "" || encoded == "" {
			return nil, errors.New("rekor checkpoint signature line malformed")
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode rekor checkpoint signature: %w", err)
		}
		if len(raw) < 5 {
			return nil, errors.New("rekor checkpoint signature too small")
		}
		signatures = append(signatures, rekorNoteSignature{
			Name:      name,
			KeyHash:   binary.BigEndian.Uint32(raw[:4]),
			Signature: raw[4:],
		})
	}
	if len(signatures) == 0 {
		return nil, errors.New("rekor checkpoint has no signatures")
	}
	return signatures, nil
}

func verifyRekorInclusion(proof Proof) error {
	bodyBytes, err := base64.StdEncoding.DecodeString(proof.Rekor.Body)
	if err != nil {
		return fmt.Errorf("decode rekor body: %w", err)
	}
	root, err := hex.DecodeString(proof.Rekor.InclusionProof.RootHash)
	if err != nil {
		return fmt.Errorf("decode rekor inclusion root_hash: %w", err)
	}
	hashes := make([][]byte, 0, len(proof.Rekor.InclusionProof.Hashes))
	for i, hash := range proof.Rekor.InclusionProof.Hashes {
		decoded, err := hex.DecodeString(hash)
		if err != nil {
			return fmt.Errorf("decode rekor inclusion proof hash %d: %w", i, err)
		}
		hashes = append(hashes, decoded)
	}
	leaf := rfc6962LeafHash(bodyBytes)
	if err := verifyRFC6962Inclusion(proof.Rekor.InclusionProof.LogIndex, proof.Rekor.InclusionProof.TreeSize, leaf, hashes, root); err != nil {
		return fmt.Errorf("verify rekor inclusion proof: %w", err)
	}
	return nil
}

func verifyRFC6962Inclusion(index, size uint64, leafHash []byte, hashes [][]byte, root []byte) error {
	if size == 0 {
		return errors.New("tree size is zero")
	}
	if index >= size {
		return fmt.Errorf("index %d outside tree size %d", index, size)
	}
	fn := index
	sn := size - 1
	computed := append([]byte(nil), leafHash...)
	for _, hash := range hashes {
		if sn == 0 {
			return errors.New("too many proof hashes")
		}
		if fn%2 == 1 || fn == sn {
			computed = rfc6962NodeHash(hash, computed)
			for fn%2 == 0 && fn != 0 {
				fn /= 2
				sn /= 2
			}
		} else {
			computed = rfc6962NodeHash(computed, hash)
		}
		fn /= 2
		sn /= 2
	}
	if sn != 0 {
		return errors.New("proof too short")
	}
	if !bytes.Equal(computed, root) {
		return errors.New("computed root does not match proof root")
	}
	return nil
}

func rfc6962LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func rfc6962NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func verifyWithAnyKey(keys []crypto.PublicKey, message, signature []byte) bool {
	for _, key := range keys {
		if verifySignature(key, message, signature) {
			return true
		}
	}
	return false
}

func verifySignature(key crypto.PublicKey, message, signature []byte) bool {
	switch pub := key.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(pub, message, signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(pub, digest[:], signature)
	case *rsa.PublicKey:
		digest := sha256.Sum256(message)
		if rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, nil) == nil {
			return true
		}
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature) == nil
	default:
		return false
	}
}

func publicKeyHash(key crypto.PublicKey) uint32 {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0
	}
	sum := sha256.Sum256(der)
	return binary.BigEndian.Uint32(sum[:4])
}

func rekorBaseURL(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return DefaultRekorURL
	}
	return strings.TrimSpace(raw)
}

func normalizeRekorBaseURL(raw string) (string, error) {
	base, err := url.Parse(rekorBaseURL(raw))
	if err != nil {
		return "", fmt.Errorf("parse rekor URL: %w", err)
	}
	if base.Scheme == "" {
		return "", errors.New("rekor URL scheme required")
	}
	base.Scheme = strings.ToLower(base.Scheme)
	if base.Host == "" {
		return "", errors.New("rekor URL host required")
	}
	if base.User != nil {
		return "", errors.New("rekor URL userinfo is not allowed")
	}
	if base.RawQuery != "" {
		return "", errors.New("rekor URL query is not allowed")
	}
	if base.Fragment != "" {
		return "", errors.New("rekor URL fragment is not allowed")
	}
	if base.Scheme != "https" {
		if base.Scheme != "http" || !isLocalRekorHost(base.Hostname()) {
			return "", errors.New("rekor URL must use https unless host is a local test endpoint")
		}
	}
	base.Host = strings.ToLower(base.Host)
	base.Path = strings.TrimRight(base.Path, "/")
	base.RawPath = ""
	return base.String(), nil
}

func isLocalRekorHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func rekorEntriesURL(raw string) (string, error) {
	baseURL, err := normalizeRekorBaseURL(raw)
	if err != nil {
		return "", err
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse rekor URL: %w", err)
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/log/entries"
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func decodeRekorEntry(data []byte) (rekorEntry, string, error) {
	if err := jsonscan.RejectDuplicateKeys(data); err != nil {
		return rekorEntry{}, "", err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err == nil && len(raw) > 0 {
		if isDirectRekorEntryObject(raw) {
			var entry rekorEntry
			if err := json.Unmarshal(data, &entry); err != nil {
				return rekorEntry{}, "", fmt.Errorf("parse rekor response: %w", err)
			}
			return entry, "", nil
		}
		if len(raw) != 1 {
			return rekorEntry{}, "", fmt.Errorf("rekor response contained %d entries, want exactly 1", len(raw))
		}
		for uuid, entryData := range raw {
			var entry rekorEntry
			if err := json.Unmarshal(entryData, &entry); err != nil {
				return rekorEntry{}, "", fmt.Errorf("parse rekor entry %q: %w", uuid, err)
			}
			return entry, uuid, nil
		}
	}
	var entry rekorEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return rekorEntry{}, "", fmt.Errorf("parse rekor response: %w", err)
	}
	return entry, "", nil
}

func isDirectRekorEntryObject(raw map[string]json.RawMessage) bool {
	for _, key := range []string{"logID", "logIndex", "integratedTime", "body", "verification"} {
		if _, ok := raw[key]; ok {
			return true
		}
	}
	return false
}
