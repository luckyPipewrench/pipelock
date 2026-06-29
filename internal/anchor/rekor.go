// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
// submission metadata. Verify fails closed until trusted Rekor SET and
// inclusion-proof verification is implemented.
type RekorLog struct {
	URL        string
	HTTPClient *http.Client
	Signer     ed25519.PrivateKey
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
	return errors.New("rekor independent verification unavailable: trusted Rekor SET and inclusion-proof verification is required")
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

// LoadRekorPrivateKey loads the Ed25519 key used to sign Rekor submission
// bodies before they are posted.
func LoadRekorPrivateKey(path string) (ed25519.PrivateKey, error) {
	key, err := domsigning.LoadPrivateKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("load rekor signing key: %w", err)
	}
	return key, nil
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
