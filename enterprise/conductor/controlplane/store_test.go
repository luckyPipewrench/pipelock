//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var testNow = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

func TestFileBundleStorePublishesIdempotentlyAndReloads(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})

	record, created, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if !created {
		t.Fatal("Publish() created = false, want true")
	}
	again, created, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow.Add(time.Second)})
	if err != nil {
		t.Fatalf("Publish(idempotent) error = %v", err)
	}
	if created || again.BundleHash != record.BundleHash {
		t.Fatalf("Publish(idempotent) created=%v hash=%q, want existing %q", created, again.BundleHash, record.BundleHash)
	}

	reopened, err := OpenFileBundleStore(store.dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore(reopen) error = %v", err)
	}
	latest, err := reopened.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
	}, testNow)
	if err != nil {
		t.Fatalf("Latest() error = %v", err)
	}
	if latest.BundleHash != record.BundleHash || latest.Bundle.BundleID != "bundle-1" {
		t.Fatalf("Latest() = hash=%q id=%q, want %q bundle-1", latest.BundleHash, latest.Bundle.BundleID, record.BundleHash)
	}
	info, err := os.Stat(filepath.Join(store.bundlesDir, record.BundleHash+".json"))
	if err != nil {
		t.Fatalf("stat bundle record: %v", err)
	}
	if got := info.Mode().Perm(); got != bundleRecordFileMode {
		t.Fatalf("bundle record mode = %v, want %v", got, bundleRecordFileMode)
	}
}

func TestFileBundleStoreRejectsStreamConflicts(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	first := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	firstRecord, _, err := store.Publish(t.Context(), first, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(first) error = %v", err)
	}

	wrongPrev := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: stringsOf("a", 64),
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), wrongPrev, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(wrong prev) error = %v, want ErrBundleConflict", err)
	}

	second := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: firstRecord.BundleHash,
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), second, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(second) error = %v", err)
	}

	sameVersionSwap := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2b",
		version:      2,
		previousHash: firstRecord.BundleHash,
		audience:     conductor.Audience{Labels: map[string]string{"ring": "stable"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api3.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), sameVersionSwap, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(same version swap) error = %v, want ErrBundleConflict", err)
	}

	downgrade := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-old",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), downgrade, PublishOptions{Now: testNow, Rollback: true}); !errors.Is(err, ErrUnsupportedRollback) {
		t.Fatalf("Publish(rollback) error = %v, want ErrUnsupportedRollback", err)
	}
}

func TestFileBundleStoreLatestSelectsMatchingValidBundle(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	stable := signedControlBundle(t, signer, bundleSpec{
		id:       "stable-1",
		version:  1,
		audience: conductor.Audience{Labels: map[string]string{"ring": "stable"}},
	})
	if _, _, err := store.Publish(t.Context(), stable, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(stable) error = %v", err)
	}
	canary := signedControlBundle(t, signer, bundleSpec{
		id:       "canary-3",
		version:  3,
		audience: conductor.Audience{Labels: map[string]string{"ring": "canary"}},
	})
	if _, _, err := store.Publish(t.Context(), canary, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(canary) error = %v", err)
	}
	wildcard := signedControlBundle(t, signer, bundleSpec{
		id:       "wildcard-9",
		version:  9,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), wildcard, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(wildcard) error = %v", err)
	}

	latest, err := store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		Labels:      map[string]string{"ring": "canary"},
	}, testNow)
	if err != nil {
		t.Fatalf("Latest(canary) error = %v", err)
	}
	if latest.Bundle.BundleID != "canary-3" {
		t.Fatalf("Latest(canary) = %q, want canary-3", latest.Bundle.BundleID)
	}
	latest, err = store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-2",
		Environment: "prod",
		Labels:      map[string]string{"ring": "missing"},
	}, testNow)
	if err != nil {
		t.Fatalf("Latest(wildcard fallback) error = %v", err)
	}
	if latest.Bundle.BundleID != "wildcard-9" {
		t.Fatalf("Latest(wildcard fallback) = %q, want wildcard-9", latest.Bundle.BundleID)
	}
	if _, err := store.Latest(t.Context(), FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
		Labels:      map[string]string{"ring": "canary"},
	}, testNow.Add(3*time.Hour)); !errors.Is(err, ErrBundleNotFound) {
		t.Fatalf("Latest(expired) error = %v, want ErrBundleNotFound", err)
	}
}

func TestFileBundleStoreRejectsTamperedRecordOnOpen(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	path := filepath.Join(store.bundlesDir, record.BundleHash+".json")
	data, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // test path is under the temp store dir.
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	data = []byte(stringsReplaceOnce(string(data), `"version": 1`, `"version": 2`))
	if err := os.WriteFile(path, data, bundleRecordFileMode); err != nil {
		t.Fatalf("tamper record: %v", err)
	}
	if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(tampered) error = %v, want ErrInvalidStoreRecord", err)
	}
}

func TestStoredRecordValidationGuards(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*PublishedBundle)
	}{
		{name: "missing_hash", mutate: func(r *PublishedBundle) { r.BundleHash = "" }},
		{name: "non_hex_hash", mutate: func(r *PublishedBundle) { r.BundleHash = stringsOf("z", 64) }},
		{name: "hash_mismatch", mutate: func(r *PublishedBundle) { r.Bundle.BundleID = "changed" }},
		{name: "stream_key_mismatch", mutate: func(r *PublishedBundle) { r.StreamKey = "wrong" }},
		{name: "missing_published_at", mutate: func(r *PublishedBundle) { r.PublishedAt = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tampered := record
			tc.mutate(&tampered)
			if err := validateStoredRecord(tampered); !errors.Is(err, ErrInvalidStoreRecord) {
				t.Fatalf("validateStoredRecord() error = %v, want ErrInvalidStoreRecord", err)
			}
		})
	}
}

func TestReadBundleRecordRejectsTrailingDocument(t *testing.T) {
	store := mustStore(t)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	record, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	path := filepath.Join(store.bundlesDir, "trailing.json")
	if err := os.WriteFile(path, append(data, []byte(`{}`)...), bundleRecordFileMode); err != nil {
		t.Fatalf("write trailing record: %v", err)
	}
	if _, err := readBundleRecord(path); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("readBundleRecord(trailing) error = %v, want ErrInvalidStoreRecord", err)
	}
}

func TestNewerRecordTieBreakers(t *testing.T) {
	a := PublishedBundle{Bundle: conductor.PolicyBundle{Version: 2}, BundleHash: "b", PublishedAt: testNow}
	b := PublishedBundle{Bundle: conductor.PolicyBundle{Version: 1}, BundleHash: "c", PublishedAt: testNow.Add(time.Hour)}
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(version) = false, want true")
	}
	a.Bundle.Version = 1
	a.PublishedAt = testNow.Add(2 * time.Hour)
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(published_at) = false, want true")
	}
	a.PublishedAt = b.PublishedAt
	a.BundleHash = "d"
	if !newerRecord(a, b) {
		t.Fatal("newerRecord(hash tie-breaker) = false, want true")
	}
	a.BundleHash = "a"
	if newerRecord(a, b) {
		t.Fatal("newerRecord(older hash tie-breaker) = true, want false")
	}
}

type testSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

type bundleSpec struct {
	id           string
	version      uint64
	previousHash string
	audience     conductor.Audience
	configYAML   string
}

func newTestSigner(t *testing.T) testSigner {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	return testSigner{keyID: "policy-key-1", priv: priv}
}

func signedControlBundle(t *testing.T, signer testSigner, spec bundleSpec) conductor.PolicyBundle {
	t.Helper()
	if spec.configYAML == "" {
		spec.configYAML = "mode: strict\napi_allowlist:\n  - api.example.com\n"
	}
	payload := conductor.PolicyBundlePayload{ConfigYAML: spec.configYAML}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		t.Fatalf("PayloadHash() error = %v", err)
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		t.Fatalf("PolicyHash() error = %v", err)
	}
	bundle := conductor.PolicyBundle{
		SchemaVersion:      conductor.SchemaVersion,
		BundleID:           spec.id,
		OrgID:              "org-main",
		FleetID:            "prod",
		Environment:        "prod",
		Audience:           spec.audience,
		Version:            spec.version,
		PreviousBundleHash: spec.previousHash,
		CreatedAt:          testNow.Add(-time.Minute),
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(2 * time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	signature := ed25519.Sign(signer.priv, preimage)
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: signer.keyID,
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(signature),
	}}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("test bundle Validate() error = %v", err)
	}
	return bundle
}

func stringsOf(value string, count int) string {
	var b strings.Builder
	for range count {
		b.WriteString(value)
	}
	return b.String()
}

func stringsReplaceOnce(s, old, replacement string) string {
	idx := strings.Index(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + replacement + s[idx+len(old):]
}
