// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestStore_PutTombstone_RoundTrip(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	raw := mustJSON(t, env)

	got, err := st.PutTombstone(raw, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}
	if got != cHash {
		t.Fatalf("PutTombstone hash = %q, want %q", got, cHash)
	}

	loaded, found, err := st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("LoadTombstone: %v", err)
	}
	if !found {
		t.Fatal("LoadTombstone found = false, want true")
	}
	if loaded.Body.PriorContractHash != cHash {
		t.Fatalf("loaded prior_contract_hash = %q, want %q", loaded.Body.PriorContractHash, cHash)
	}
	if loaded.Body.SignerKeyID != signer.keyID {
		t.Fatalf("loaded signer_key_id = %q, want %q", loaded.Body.SignerKeyID, signer.keyID)
	}
}

func TestStore_LoadTombstone_MissingReturnsFalseNoError(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")
	missing := mustComputeContractHash(t, []byte("nonexistent"))

	env, found, err := st.LoadTombstone(missing, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("LoadTombstone missing: %v", err)
	}
	if found {
		t.Fatal("LoadTombstone found = true on missing file")
	}
	if env.Body.PriorContractHash != "" {
		t.Fatalf("missing tombstone returned non-zero body: %+v", env.Body)
	}
}

func TestStore_PutTombstone_RejectsBadSignature(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	body := newTombstoneBody(cHash, signer)
	env := contract.TombstoneEnvelope{
		Body:      body,
		Signature: "ed25519:" + strings.Repeat("00", 64),
	}

	_, err := st.PutTombstone(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("PutTombstone err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_PutTombstone_RejectsWrongKeyPurpose(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	body := newTombstoneBody(cHash, signer)
	body.KeyPurpose = signing.PurposeContractCompileSigning.String()
	env := signTombstoneEnvelope(t, body, signer)

	_, err := st.PutTombstone(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, contract.ErrTombstoneWrongKeyPurpose) {
		t.Fatalf("PutTombstone err = %v, want ErrTombstoneWrongKeyPurpose", err)
	}
	if !errors.Is(err, ErrStructural) {
		t.Fatalf("PutTombstone err = %v, want wrapped by ErrStructural", err)
	}
}

func TestStore_PutTombstone_RejectsUnknownSigner(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	rosterSigner := newTestSigner(t, "act-1", "alice")
	rogueSigner := newTestSigner(t, "rogue", "mallory")
	env := signTestTombstone(t, newTombstoneBody(cHash, rogueSigner), rogueSigner)

	_, err := st.PutTombstone(mustJSON(t, env), testOptions(testRoster(rosterSigner), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("PutTombstone err = %v, want ErrTombstoneSignature for unknown signer", err)
	}
}

func TestStore_PutTombstone_WriteOnceConflict(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	first := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	firstRaw := mustJSON(t, first)
	if _, err := st.PutTombstone(firstRaw, testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone first: %v", err)
	}

	if _, err := st.PutTombstone(firstRaw, testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone idempotent: %v", err)
	}

	conflict := signTestTombstone(t, func() contract.Tombstone {
		body := newTombstoneBody(cHash, signer)
		body.RedactedAt = "2026-05-13T18:00:00Z"
		return body
	}(), signer)
	_, err := st.PutTombstone(mustJSON(t, conflict), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrWriteOnceConflict) {
		t.Fatalf("PutTombstone conflict err = %v, want ErrWriteOnceConflict", err)
	}
}

func TestStore_PutTombstone_RejectsMalformedHash(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")
	body := newTombstoneBody("not-a-hash", signer)
	env := signTombstoneEnvelope(t, body, signer)

	_, err := st.PutTombstone(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractHistory) {
		t.Fatalf("PutTombstone err = %v, want ErrContractHistory for malformed hash", err)
	}
}

func TestStore_LoadTombstone_FilenameHashMismatch_FailsClosed(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	otherHash := mustComputeContractHash(t, []byte("other-payload"))
	signer := newTestSigner(t, "act-1", "alice")

	body := newTombstoneBody(otherHash, signer)
	env := signTombstoneEnvelope(t, body, signer)
	raw := mustJSON(t, env)
	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir tombstones: %v", err)
	}
	pathForOther, err := st.tombstonePath(cHash)
	if err != nil {
		t.Fatalf("tombstonePath: %v", err)
	}
	if err := os.WriteFile(pathForOther, raw, filePerm); err != nil {
		t.Fatalf("write tombstone with mismatched hash: %v", err)
	}

	_, _, err = st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("LoadTombstone filename mismatch err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_LoadTombstone_CorruptFile_FailsClosed(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir tombstones: %v", err)
	}
	path, err := st.tombstonePath(cHash)
	if err != nil {
		t.Fatalf("tombstonePath: %v", err)
	}
	if err := os.WriteFile(path, []byte("not a tombstone"), filePerm); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	_, _, err = st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneDecode) {
		t.Fatalf("LoadTombstone garbage err = %v, want ErrTombstoneDecode", err)
	}
}

func TestStore_ValidateEnvelope_TombstonedContract_Rejected(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}

	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	_, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractTombstoned) {
		t.Fatalf("ValidateEnvelope err = %v, want ErrContractTombstoned", err)
	}
	if !strings.Contains(err.Error(), cHash) {
		t.Errorf("error message does not name tombstoned hash %s: %v", cHash, err)
	}
	if !strings.Contains(err.Error(), "alice-auth-id") {
		t.Errorf("error message does not include authorization id: %v", err)
	}
}

func TestStore_ValidateEnvelope_NoTombstone_StillAccepts(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)

	if _, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("ValidateEnvelope without tombstone: %v", err)
	}
}

func TestStore_Reload_TombstonedContract_RecordsJournalRejection(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	raw := mustJSON(t, env)
	if _, err := st.WriteActive(raw, testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}

	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); !errors.Is(err, ErrContractTombstoned) {
		t.Fatalf("Reload err = %v, want ErrContractTombstoned", err)
	}

	journal, err := os.ReadFile(st.journalPath())
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if !strings.Contains(string(journal), "rejected") {
		t.Errorf("journal does not record rejected outcome: %s", journal)
	}
	if !strings.Contains(string(journal), "tombstoned") {
		t.Errorf("journal does not name tombstoned reason: %s", journal)
	}
}

func TestStore_ValidateEnvelope_TombstoneFor_DifferentContract_StillAccepts(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	otherHash := mustComputeContractHash(t, []byte("other-contract-payload"))
	tomb := signTestTombstone(t, newTombstoneBody(otherHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone for other hash: %v", err)
	}

	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	if _, err := st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("ValidateEnvelope with unrelated tombstone: %v", err)
	}
}

func TestStore_ValidateEnvelope_LegacyYAMLTombstone_Rejected(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir tombstones: %v", err)
	}
	path, err := st.legacyTombstonePath(cHash)
	if err != nil {
		t.Fatalf("legacyTombstonePath: %v", err)
	}
	if err := os.WriteFile(path, mustYAMLWithJSONTags(t, tomb), filePerm); err != nil {
		t.Fatalf("write legacy tombstone: %v", err)
	}

	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	_, err = st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractTombstoned) {
		t.Fatalf("ValidateEnvelope legacy YAML tombstone err = %v, want ErrContractTombstoned", err)
	}
}

func TestStore_Accepted_TombstonedContract_Rejected(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	manifestHash, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}

	_, err = st.Accepted(manifestHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractTombstoned) {
		t.Fatalf("Accepted err = %v, want ErrContractTombstoned (rollback bypass)", err)
	}
	history, err := st.AcceptedHistory(manifestHash, testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("AcceptedHistory should still load tombstoned historical manifest for chain checks: %v", err)
	}
	if history.ManifestHash != manifestHash {
		t.Fatalf("AcceptedHistory hash = %s, want %s", history.ManifestHash, manifestHash)
	}
}

func TestStore_LatestAccepted_TombstonedContract_Rejected(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	if _, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("WriteActive: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}

	_, err := st.LatestAccepted(testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractTombstoned) {
		t.Fatalf("LatestAccepted err = %v, want ErrContractTombstoned (recovery bypass)", err)
	}
	history, err := st.LatestAcceptedHistory(testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("LatestAcceptedHistory should still load tombstoned historical manifest for baselines: %v", err)
	}
	if history.Envelope.Body.Generation != 1 {
		t.Fatalf("LatestAcceptedHistory generation = %d, want 1", history.Envelope.Body.Generation)
	}
}

func TestStore_WriteActive_CanAdvancePastTombstonedCurrent(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	replacementHash := putAlternateTestContract(t, st, "agent-b")
	signer := newTestSigner(t, "act-1", "alice")
	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	manifestHash, err := st.WriteActive(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if err != nil {
		t.Fatalf("WriteActive gen1: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("Reload gen1: %v", err)
	}

	tomb := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)
	if _, err := st.PutTombstone(mustJSON(t, tomb), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("PutTombstone: %v", err)
	}

	replacement := signedManifest(t, replacementHash, 2, manifestHash, testEnv(), signer)
	if _, err := st.WriteActive(mustJSON(t, replacement), testOptions(testRoster(signer), "", 0, 1)); err != nil {
		t.Fatalf("WriteActive replacement after tombstoned current: %v", err)
	}
	if _, err := st.Reload(testOptions(testRoster(signer), manifestHash, 1, 1)); err != nil {
		t.Fatalf("Reload replacement after tombstoned current: %v", err)
	}
}

func TestStore_PutTombstone_RejectsGarbageJSON(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")

	_, err := st.PutTombstone([]byte("not-json"), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneDecode) {
		t.Fatalf("PutTombstone garbage err = %v, want ErrTombstoneDecode", err)
	}
}

func TestStore_PutTombstone_RejectsNilRoster(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	env := signTestTombstone(t, newTombstoneBody(cHash, signer), signer)

	opts := testOptions(nil, "", 0, 1)
	_, err := st.PutTombstone(mustJSON(t, env), opts)
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("PutTombstone nil roster err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_PutTombstone_RejectsMalformedSignaturePrefix(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")
	body := newTombstoneBody(cHash, signer)
	env := contract.TombstoneEnvelope{
		Body:      body,
		Signature: "no-prefix-here",
	}

	_, err := st.PutTombstone(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("PutTombstone bad signature prefix err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_LoadTombstone_MalformedHashRequest(t *testing.T) {
	st := New(t.TempDir())
	signer := newTestSigner(t, "act-1", "alice")

	_, _, err := st.LoadTombstone("not-a-valid-hash", testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrContractHistory) {
		t.Fatalf("LoadTombstone malformed hash err = %v, want ErrContractHistory", err)
	}
}

func TestStore_LoadTombstone_BadBodyValidate_FailsClosed(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	body := newTombstoneBody(cHash, signer)
	body.SchemaVersion = 99
	env := signTombstoneEnvelope(t, body, signer)
	raw := mustJSON(t, env)
	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path, err := st.tombstonePath(cHash)
	if err != nil {
		t.Fatalf("tombstonePath: %v", err)
	}
	if err := os.WriteFile(path, raw, filePerm); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err = st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrStructural) {
		t.Fatalf("LoadTombstone bad schema err = %v, want ErrStructural", err)
	}
}

func TestStore_LoadTombstone_BadSignature_FailsClosed(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	body := newTombstoneBody(cHash, signer)
	env := contract.TombstoneEnvelope{
		Body:      body,
		Signature: "ed25519:" + strings.Repeat("00", 64),
	}
	raw := mustJSON(t, env)
	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path, err := st.tombstonePath(cHash)
	if err != nil {
		t.Fatalf("tombstonePath: %v", err)
	}
	if err := os.WriteFile(path, raw, filePerm); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, _, err = st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("LoadTombstone bad signature err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_VerifyTombstoneSignature_RejectsWrongBodyKeyPurpose(t *testing.T) {
	signer := newTestSigner(t, "act-1", "alice")
	body := newTombstoneBody("sha256:"+strings.Repeat("ab", 32), signer)
	body.KeyPurpose = "wrong-purpose"
	env := contract.TombstoneEnvelope{
		Body:      body,
		Signature: "ed25519:" + strings.Repeat("00", 64),
	}

	err := verifyTombstoneSignature(env, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("verifyTombstoneSignature wrong body purpose err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_LoadTombstone_PropagatesReadError(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	restore := replaceReadFile(func(string) ([]byte, error) {
		return nil, errors.New("forced read failure")
	})
	defer restore()

	_, _, err := st.LoadTombstone(cHash, testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneDecode) {
		t.Fatalf("LoadTombstone read err = %v, want ErrTombstoneDecode", err)
	}
}

func TestStore_VerifyTombstoneSignature_RejectsCorruptRosterHex(t *testing.T) {
	signer := newTestSigner(t, "act-1", "alice")
	env := signTestTombstone(t, contract.NewTombstone(
		"sha256:"+strings.Repeat("ab", 32),
		"2026-05-13T16:30:00Z",
		"alice-auth-id",
		signer.keyID,
	), signer)

	roster := &signing.LoadedRoster{Body: contract.KeyRoster{Keys: []contract.KeyInfo{
		{
			KeyID:        signer.keyID,
			KeyPurpose:   signing.PurposeContractActivationSigning.String(),
			PublicKeyHex: "not-hex-XX",
			ValidFrom:    testNow.Add(-time.Hour).Format(time.RFC3339),
			Status:       contract.KeyStatusActive,
			Principal:    signer.principal,
		},
	}}}
	opts := Options{Roster: roster, Now: func() time.Time { return testNow }}
	err := verifyTombstoneSignature(env, opts)
	if !errors.Is(err, ErrTombstoneSignature) {
		t.Fatalf("verifyTombstoneSignature corrupt hex err = %v, want ErrTombstoneSignature", err)
	}
}

func TestStore_ValidateEnvelope_TombstoneCheck_PropagatesCorruptStoreError(t *testing.T) {
	st := New(t.TempDir())
	cHash := putTestContract(t, st)
	signer := newTestSigner(t, "act-1", "alice")

	if err := os.MkdirAll(st.tombstoneDir(), dirPerm); err != nil {
		t.Fatalf("mkdir tombstones: %v", err)
	}
	path, err := st.tombstonePath(cHash)
	if err != nil {
		t.Fatalf("tombstonePath: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage"), filePerm); err != nil {
		t.Fatalf("write garbage tombstone: %v", err)
	}

	env := signedManifest(t, cHash, 1, "sha256:genesis", testEnv(), signer)
	_, err = st.ValidateEnvelope(mustJSON(t, env), testOptions(testRoster(signer), "", 0, 1))
	if !errors.Is(err, ErrTombstoneDecode) {
		t.Fatalf("ValidateEnvelope with corrupt tombstone err = %v, want ErrTombstoneDecode", err)
	}
}

// newTombstoneBody returns a Tombstone with all required fields populated
// for the given signer. RedactedAt is fixed so test cases that compare
// distinct bytes can vary it deliberately.
func newTombstoneBody(priorContractHash string, signer testSigner) contract.Tombstone {
	return contract.NewTombstone(
		priorContractHash,
		"2026-05-13T16:30:00Z",
		signer.principal+"-auth-id",
		signer.keyID,
	)
}

func signTestTombstone(t *testing.T, body contract.Tombstone, signer testSigner) contract.TombstoneEnvelope {
	t.Helper()
	return signTombstoneEnvelope(t, body, signer)
}

func signTombstoneEnvelope(t *testing.T, body contract.Tombstone, signer testSigner) contract.TombstoneEnvelope {
	t.Helper()
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("Tombstone.SignablePreimage: %v", err)
	}
	sig := ed25519.Sign(signer.priv, preimage)
	return contract.TombstoneEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(sig),
	}
}

func putAlternateTestContract(t *testing.T, st Store, agent string) string {
	t.Helper()
	compileSigner := testCompileSigner()
	c := testContractBody(compileSigner)
	c.Selector.Agent = agent
	hash, err := ContractHash(c)
	if err != nil {
		t.Fatalf("ContractHash alternate: %v", err)
	}
	c.ContractHash = hash
	raw := mustJSON(t, signTestContract(t, c, compileSigner))
	got, err := st.PutHistoryContract(raw, testOptions(testRoster(), "", 0, 1))
	if err != nil {
		t.Fatalf("PutHistoryContract alternate: %v", err)
	}
	if got != hash {
		t.Fatalf("PutHistoryContract alternate hash = %q, want %q", got, hash)
	}
	return hash
}

func mustYAMLWithJSONTags(t *testing.T, v any) []byte {
	t.Helper()
	raw := mustJSON(t, v)
	var tree any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		t.Fatalf("yaml tree unmarshal: %v", err)
	}
	out, err := yaml.Marshal(tree)
	if err != nil {
		t.Fatalf("yaml marshal: %v", err)
	}
	return out
}

// mustComputeContractHash returns a deterministic synthetic sha256 hash
// suitable for "no tombstone exists" / "tombstone for unrelated hash"
// tests. Not derived from a real contract; only used where the test
// does not need the hash to round-trip through the store.
func mustComputeContractHash(t *testing.T, seed []byte) string {
	t.Helper()
	out := make([]byte, 32)
	for i := range out {
		if i < len(seed) {
			out[i] = seed[i]
		} else {
			out[i] = byte(i)
		}
	}
	return hashPrefix + hex.EncodeToString(out)
}
