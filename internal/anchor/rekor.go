// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
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
	"math/big"
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
	rekorSHA512Algorithm        = "sha512"
	// rekorDefaultSubmitHashAlgorithm is used when RekorLog.HashAlgorithm is
	// unset. Pipelock Rekor submissions use Ed25519 keys; Rekor v1 validates
	// those hashedrekord signatures as Ed25519ph over a SHA-512 digest.
	rekorDefaultSubmitHashAlgorithm = rekorSHA512Algorithm
	rekorMaxResponseBytes           = 10 << 20

	// DefaultRekorHashAlgorithm is the hashedrekord data.hash.algorithm used
	// when RekorLog.HashAlgorithm is unset. It is exported so CLI defaults stay
	// tied to the anchor package behavior.
	DefaultRekorHashAlgorithm = rekorDefaultSubmitHashAlgorithm
)

// RekorLog submits receipt-chain checkpoints to Rekor and stores the returned
// submission metadata. Verify requires a pinned Rekor log public key and checks
// the SET, signed checkpoint, and inclusion proof offline.
type RekorLog struct {
	URL            string
	HTTPClient     *http.Client
	Signer         ed25519.PrivateKey
	TrustedLogKeys []crypto.PublicKey
	// HashAlgorithm selects the hashedrekord data.hash.algorithm for Ed25519
	// submissions. Rekor v1 accepts SHA-512 for this key type. Empty means the
	// default (rekorDefaultSubmitHashAlgorithm).
	HashAlgorithm string
}

// submitHashAlgorithm resolves the configured submission hash algorithm,
// falling back to the default when unset and rejecting anything the verifier
// cannot recompute. Fail closed: an unsupported algorithm never submits.
func (r RekorLog) submitHashAlgorithm() (string, error) {
	algo := strings.TrimSpace(r.HashAlgorithm)
	if algo == "" {
		return rekorDefaultSubmitHashAlgorithm, nil
	}
	switch algo {
	case rekorSHA512Algorithm:
		return algo, nil
	case rekorSHA256Algorithm:
		return "", fmt.Errorf("unsupported rekor hash algorithm %q for ed25519 hashedrekord submissions (want %q)", algo, rekorSHA512Algorithm)
	default:
		return "", fmt.Errorf("unsupported rekor hash algorithm %q (want %q)", algo, rekorSHA512Algorithm)
	}
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
	// Fail closed on an empty submission URL. Defaulting to the public
	// A public-log fallback would silently publish receipt-chain checkpoint hash
	// metadata outside the operator's trust
	// boundary — the opposite of "your evidence stays where you put it". The
	// caller must name the target log explicitly; there is no public default
	// for submission. (Verification of an already-recorded proof is separate:
	// it reads the URL embedded in the proof, not this field.)
	if strings.TrimSpace(r.URL) == "" {
		return Proof{}, errors.New("rekor anchor URL is required for submission; " +
			"set an explicit transparency-log URL (no public default — receipt metadata must stay in your trust boundary)")
	}
	checkpointBytes, err := checkpointBytes(checkpoint)
	if err != nil {
		return Proof{}, err
	}
	hashAlgorithm, err := r.submitHashAlgorithm()
	if err != nil {
		return Proof{}, err
	}
	publicKey, signature, err := signRekorArtifact(checkpointBytes, hashAlgorithm, r.Signer)
	if err != nil {
		return Proof{}, err
	}
	body := rekorSubmitRequest{
		APIVersion: rekorHashedRekordAPIVersion,
		Kind:       rekorHashedRekordKind,
		Spec: rekorSubmitSpec{
			Data: rekorData{Hash: rekorHash{
				Algorithm: hashAlgorithm,
				Value:     rekorDigestHex(hashAlgorithm, checkpointBytes),
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
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, rekorMaxResponseBytes+1))
	if err != nil {
		return Proof{}, fmt.Errorf("read rekor response: %w", err)
	}
	if len(respBody) > rekorMaxResponseBytes {
		return Proof{}, fmt.Errorf("read rekor response: exceeds %d bytes", rekorMaxResponseBytes)
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
	// Resolve the pinned trust set through the shared acceptance policy BEFORE any
	// signature work, so an unsupported key surfaces as itself instead of as a
	// generic verification failure, and so no malformed key reaches the stdlib
	// verifiers. Downstream helpers receive already-normalized keys.
	trustedKeys, err := supportedRekorLogPublicKeys(r.TrustedLogKeys)
	if err != nil {
		return err
	}
	if err := verifyRekorSET(proof, trustedKeys); err != nil {
		return err
	}
	if err := verifyRekorCheckpoint(proof, trustedKeys); err != nil {
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
	expectedDigest, err := rekorDigestHexForAlgorithm(body.Spec.Data.Hash.Algorithm, checkpointBytes)
	if err != nil {
		return err
	}
	if body.Spec.Data.Hash.Value != expectedDigest {
		return errors.New("rekor body checkpoint digest does not match bundle checkpoint")
	}
	if body.Spec.Signature.Content != proof.Rekor.Signature {
		return errors.New("rekor body signature does not match proof signature")
	}
	if body.Spec.Signature.PublicKey.Content != proof.Rekor.PublicKey {
		return errors.New("rekor body public key does not match proof public key")
	}
	if err := verifyRekorSignature(checkpointBytes, body.Spec.Data.Hash.Algorithm, proof.Rekor.PublicKey, proof.Rekor.Signature); err != nil {
		return err
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
	for i, input := range inputs {
		key, err := LoadRekorPublicKey(input)
		if err != nil {
			return nil, fmt.Errorf("rekor log public key %d: %w", i, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// LoadRekorPublicKey resolves a pinned Rekor log public key from an inline PEM
// value, a file path, or a bare encoded key, and REFUSES a key this verifier cannot
// use. Applying the acceptance policy at load is what makes the failure actionable:
// `pipelock-verifier independent --rekor-log-key` and dashboard startup are being
// configured to render a trust verdict, so an unsupported key must stop them before
// any bundle is judged rather than turning every later verification into an opaque
// signature failure. Parsing stays separate from policy in ParseRekorPublicKey so
// "parsed but unsupported" remains distinguishable from "unparseable".
func LoadRekorPublicKey(pathOrValue string) (crypto.PublicKey, error) {
	key, err := loadRekorPublicKeyRaw(pathOrValue)
	if err != nil {
		return nil, err
	}
	return supportedRekorLogPublicKey(key)
}

func loadRekorPublicKeyRaw(pathOrValue string) (crypto.PublicKey, error) {
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

func rekorDigestHexForAlgorithm(algorithm string, data []byte) (string, error) {
	switch algorithm {
	case rekorSHA256Algorithm, rekorSHA512Algorithm:
		return rekorDigestHex(algorithm, data), nil
	default:
		return "", fmt.Errorf("unsupported rekor hash algorithm %q", algorithm)
	}
}

func rekorDigestHex(algorithm string, data []byte) string {
	switch algorithm {
	case rekorSHA512Algorithm:
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:])
	default:
		return sha256Hex(data)
	}
}

func signRekorArtifact(data []byte, algorithm string, priv ed25519.PrivateKey) (publicKey string, signature string, err error) {
	if err := domsigning.ValidatePrivateKeyConsistency(priv); err != nil {
		return "", "", fmt.Errorf("validate rekor signing key: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", "", errors.New("rekor signing key public key is not ed25519")
	}
	publicKey, err = encodeRekorPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	digest, signerOpts, err := rekorSignatureDigest(algorithm, data)
	if err != nil {
		return "", "", err
	}
	sig, err := priv.Sign(nil, digest, signerOpts)
	if err != nil {
		return "", "", fmt.Errorf("sign rekor artifact digest: %w", err)
	}
	return publicKey, base64.StdEncoding.EncodeToString(sig), nil
}

func encodeRekorPublicKey(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal rekor public key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if len(pemBytes) == 0 {
		return "", errors.New("encode rekor public key")
	}
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

func rekorSignatureDigest(algorithm string, data []byte) ([]byte, crypto.SignerOpts, error) {
	switch algorithm {
	case rekorSHA512Algorithm:
		sum := sha512.Sum512(data)
		return sum[:], crypto.SHA512, nil
	default:
		return nil, nil, fmt.Errorf("unsupported rekor hash algorithm %q", algorithm)
	}
}

func verifyRekorSignature(data []byte, algorithm, publicKey, signature string) error {
	if publicKey == "" || signature == "" {
		return errors.New("rekor proof public key and signature required")
	}
	pub, err := parseRekorEd25519PublicKey(publicKey)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode rekor signature: %w", err)
	}
	switch algorithm {
	case rekorSHA512Algorithm:
		digest, _, err := rekorSignatureDigest(algorithm, data)
		if err != nil {
			return err
		}
		if err := ed25519.VerifyWithOptions(pub, digest, sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
			return errors.New("rekor hashedrekord signature invalid")
		}
	case rekorSHA256Algorithm:
		if !ed25519.Verify(pub, data, sig) {
			return errors.New("rekor legacy checkpoint signature invalid")
		}
	default:
		return fmt.Errorf("unsupported rekor hash algorithm %q", algorithm)
	}
	return nil
}

func parseRekorEd25519PublicKey(publicKey string) (ed25519.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, fmt.Errorf("decode rekor public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("parse rekor public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rekor public key: %w", err)
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("rekor public key is not ed25519")
	}
	return pub, nil
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

// verifyWithAnyKey returns true if ANY key verifies the signature, skipping keys the
// acceptance policy refuses rather than failing on them.
//
// That leniency is only safe because of a LAYERING CONTRACT: RekorLog.Verify resolves
// the whole pinned trust set through supportedRekorLogPublicKeys and fails closed
// BEFORE reaching here, so by this point every key is already known-supported and the
// skip is unreachable in practice. A future caller that reaches verifyRekorSET or
// verifyRekorCheckpoint directly, bypassing RekorLog.Verify, would instead verify
// against a SILENTLY NARROWED trust set: an unsupported key would be skipped rather
// than reported, and the operator would never learn their pinned key does nothing.
// If such a caller is ever added, resolve the keys there too, or make this function
// return an error on an unsupported key instead of skipping it.
func verifyWithAnyKey(keys []crypto.PublicKey, message, signature []byte) bool {
	for _, key := range keys {
		if verifySignature(key, message, signature) {
			return true
		}
	}
	return false
}

// ErrUnsupportedRekorLogKey marks a pinned Rekor log key that parsed correctly but
// is not one this verifier accepts. It is distinguishable on purpose: an operator
// who supplies an RSA or P-384 log key needs to be told the key is unsupported, not
// handed a generic "signature verification failed" that reads like a tampered log.
var ErrUnsupportedRekorLogKey = errors.New("unsupported rekor log public key")

// supportedRekorLogPublicKey is the SINGLE acceptance policy for a pinned Rekor log
// public key, shared by key LOAD (so the verifier CLI and the dashboard refuse a bad
// key before rendering any verdict) and by VERIFICATION (so a caller that constructs
// RekorLog directly still fails closed rather than silently never matching).
//
// Accepted: Ed25519, and ECDSA on NIST P-256. RSA in both padding modes and every
// other curve are refused. The wire artifacts here carry NO hash-algorithm field --
// a SET payload is canonicalized entry metadata and a checkpoint signature carries
// only name, a 32-bit key hash, and the signature bytes -- so the digest is fixed at
// SHA-256. Accepting another curve would mean inventing a local curve-to-hash policy
// and calling it interoperability. Broadening this belongs to a named compatibility
// target with fixtures from that deployment, not to a hardening change.
//
// Both branches also close a PANIC reachable from a caller-supplied key:
// ed25519.Verify panics on a wrong-length key, and ECDSA verification panics on a
// nil curve or nil coordinates. Returning a typed error here means a malformed key
// can never reach the stdlib verifier.
func supportedRekorLogPublicKey(key crypto.PublicKey) (crypto.PublicKey, error) {
	switch pub := key.(type) {
	case ed25519.PublicKey:
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: ed25519 key is %d bytes, want %d",
				ErrUnsupportedRekorLogKey, len(pub), ed25519.PublicKeySize)
		}
		return pub, nil
	case *ecdsa.PublicKey:
		p256Pub, ok := normalizeECDSAP256PublicKey(pub)
		if !ok {
			// Name the curve the operator actually supplied. "not a valid P-256 point"
			// alone leaves someone who pinned a P-384 key with no idea what was wrong.
			return nil, fmt.Errorf("%w: ecdsa key on curve %s is not a valid NIST P-256 point",
				ErrUnsupportedRekorLogKey, ecdsaCurveName(pub))
		}
		return p256Pub, nil
	default:
		return nil, fmt.Errorf("%w: %T; supported Rekor log keys are Ed25519 and ECDSA P-256",
			ErrUnsupportedRekorLogKey, key)
	}
}

// ecdsaCurveName describes an ECDSA key's curve for an operator-facing error, without
// assuming the key is well formed: a nil key, a nil curve, or a curve with nil params
// all have to produce a string rather than panic on the error path.
func ecdsaCurveName(pub *ecdsa.PublicKey) string {
	if pub == nil || pub.Curve == nil {
		return "unknown"
	}
	params := pub.Params()
	if params == nil || params.Name == "" {
		return "unnamed"
	}
	return params.Name
}

// supportedRekorLogPublicKeys resolves every pinned key through the policy above,
// failing on the FIRST unsupported key rather than silently dropping it: a keyring
// that quietly loses an entry would verify against fewer keys than the operator
// configured, which is a trust-set change they never asked for.
func supportedRekorLogPublicKeys(keys []crypto.PublicKey) ([]crypto.PublicKey, error) {
	out := make([]crypto.PublicKey, 0, len(keys))
	for i, key := range keys {
		resolved, err := supportedRekorLogPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("trusted rekor log key %d: %w", i, err)
		}
		out = append(out, resolved)
	}
	return out, nil
}

func verifySignature(key crypto.PublicKey, message, signature []byte) bool {
	resolved, err := supportedRekorLogPublicKey(key)
	if err != nil {
		return false
	}
	switch pub := resolved.(type) {
	case ed25519.PublicKey:
		return ed25519.Verify(pub, message, signature)
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(message)
		return ecdsa.VerifyASN1(pub, digest[:], signature)
	default:
		return false
	}
}

func normalizeECDSAP256PublicKey(pub *ecdsa.PublicKey) (*ecdsa.PublicKey, bool) {
	if pub == nil || pub.X == nil || pub.Y == nil || !isECDSAP256Curve(pub.Curve) {
		return nil, false
	}
	p256 := elliptic.P256()
	if !validECDHP256Point(pub) {
		return nil, false
	}
	return &ecdsa.PublicKey{Curve: p256, X: pub.X, Y: pub.Y}, true
}

func validECDHP256Point(pub *ecdsa.PublicKey) bool {
	byteLen := (elliptic.P256().Params().BitSize + 7) / 8
	if pub.X.Sign() < 0 || pub.Y.Sign() < 0 || pub.X.BitLen() > byteLen*8 || pub.Y.BitLen() > byteLen*8 {
		return false
	}
	encoded := make([]byte, 1+2*byteLen)
	encoded[0] = 4
	pub.X.FillBytes(encoded[1 : 1+byteLen])
	pub.Y.FillBytes(encoded[1+byteLen:])
	_, err := ecdh.P256().NewPublicKey(encoded)
	return err == nil
}

func isECDSAP256Curve(curve elliptic.Curve) bool {
	if curve == nil {
		return false
	}
	params := curve.Params()
	want := elliptic.P256().Params()
	return params != nil &&
		params.Name == want.Name &&
		params.BitSize == want.BitSize &&
		sameBigInt(params.P, want.P) &&
		sameBigInt(params.N, want.N) &&
		sameBigInt(params.B, want.B) &&
		sameBigInt(params.Gx, want.Gx) &&
		sameBigInt(params.Gy, want.Gy)
}

func sameBigInt(a, b *big.Int) bool {
	return a != nil && b != nil && a.Cmp(b) == 0
}

func publicKeyHash(key crypto.PublicKey) uint32 {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return 0
	}
	sum := sha256.Sum256(der)
	return binary.BigEndian.Uint32(sum[:4])
}

func normalizeRekorBaseURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("rekor URL is required")
	}
	base, err := url.Parse(strings.TrimSpace(raw))
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
