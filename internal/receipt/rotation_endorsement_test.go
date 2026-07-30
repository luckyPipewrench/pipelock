// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func buildSessionBoundRotatedChain(t *testing.T, keys ...ed25519.PrivateKey) ([]Receipt, []int) {
	t.Helper()
	dir := t.TempDir()
	boundaries := make([]int, 0, len(keys)-1)
	for keyIndex, key := range keys {
		rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir, CheckpointInterval: 1000}, nil, key)
		if err != nil {
			t.Fatalf("recorder.New: %v", err)
		}
		emitter := NewEmitter(EmitterConfig{Recorder: rec, PrivKey: key, Principal: "test", Actor: "test"})
		if err := emitter.InitError(); err != nil {
			t.Fatalf("emitter InitError: %v", err)
		}
		if err := emitter.EmitSessionOpen(); err != nil {
			t.Fatalf("EmitSessionOpen: %v", err)
		}
		if err := emitter.Emit(EmitOpts{
			ActionID: fmt.Sprintf("action-%d", keyIndex), Verdict: "allow", Transport: "fetch",
			Method: http.MethodGet, Target: "https://api.vendor.example/data", SessionID: "agent-session",
		}); err != nil {
			t.Fatalf("Emit: %v", err)
		}
		if err := rec.Close(); err != nil {
			t.Fatalf("recorder.Close: %v", err)
		}
	}
	receipts, err := ExtractReceiptsFromSessionDir(dir, "proxy")
	if err != nil {
		t.Fatalf("ExtractReceiptsFromSessionDir: %v", err)
	}
	for i := 1; i < len(receipts); i++ {
		if receipts[i].ActionRecord.KeyTransition != nil {
			boundaries = append(boundaries, i)
		}
	}
	if len(boundaries) != len(keys)-1 {
		t.Fatalf("rotation boundaries = %v, want %d", boundaries, len(keys)-1)
	}
	return receipts, boundaries
}

func endorsementForBoundary(t *testing.T, chain []Receipt, boundary int, priorKey ed25519.PrivateKey) RotationEndorsement {
	t.Helper()
	prior := chain[boundary-1]
	priorHash := mustHash(t, prior)
	endorsement, err := SignRotationEndorsement(RotationEndorsement{
		SessionID:     "proxy",
		PriorFinalSeq: prior.ActionRecord.ChainSeq,
		PriorTailHash: priorHash,
		NewSignerKey:  chain[boundary].SignerKey,
		RotatedAt:     time.Date(2026, 4, 1, 1, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}, priorKey)
	if err != nil {
		t.Fatalf("SignRotationEndorsement: %v", err)
	}
	return endorsement
}

func TestVerifyChainWithEndorsements_AuthorizesSuccessor(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)

	result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement}, []string{hex.EncodeToString(pubA)})
	if !result.Valid {
		t.Fatalf("endorsed rotation rejected: %s", result.Error)
	}
	if got := strings.Join(result.TrustBasis, ","); got != "root,endorsed" {
		t.Fatalf("TrustBasis = %q, want root,endorsed", got)
	}
	if len(result.EndorsementGaps) != 0 {
		t.Fatalf("EndorsementGaps = %v, want none", result.EndorsementGaps)
	}
}

func TestVerifyChainWithEndorsements_MultiHopDelegation(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	_, privC := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB, privC)
	endorsementAB := endorsementForBoundary(t, chain, boundaries[0], privA)
	endorsementBC := endorsementForBoundary(t, chain, boundaries[1], privB)

	result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsementBC, endorsementAB}, []string{hex.EncodeToString(pubA)})
	if !result.Valid || strings.Join(result.TrustBasis, ",") != "root,endorsed,endorsed" {
		t.Fatalf("multi-hop endorsement chain rejected: %+v", result)
	}
}

func TestFindRotationPriorTailFailsClosedWhenLaterSegmentIsMissing(t *testing.T) {
	t.Parallel()
	receipts := []Receipt{{SignerKey: "key-a"}, {SignerKey: "key-b"}}
	if index, found := findRotationPriorTail(receipts, 1, "key-b"); !found || index != 0 {
		t.Fatalf("first boundary = (%d, %t), want (0, true)", index, found)
	}
	if _, found := findRotationPriorTail(receipts, 2, "key-c"); found {
		t.Fatal("missing later segment retained a previous boundary")
	}
}

func TestVerifyChainWithEndorsements_RepeatedKeysRequireEveryEndorsement(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB, privA, privB)
	endorsements := []RotationEndorsement{
		endorsementForBoundary(t, chain, boundaries[2], privA),
		endorsementForBoundary(t, chain, boundaries[0], privA),
		endorsementForBoundary(t, chain, boundaries[1], privB),
	}

	result := VerifyChainWithEndorsements("proxy", chain, endorsements, []string{hex.EncodeToString(pubA)})
	if !result.Valid || strings.Join(result.TrustBasis, ",") != "root,endorsed,endorsed,endorsed" {
		t.Fatalf("repeated-key endorsement chain rejected: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_FailsClosedWithoutEndorsement(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	chain, _ := buildSessionBoundRotatedChain(t, privA, privB)

	result := VerifyChainWithEndorsements("proxy", chain, nil, []string{hex.EncodeToString(pubA)})
	if result.Valid {
		t.Fatal("unendorsed successor outside the root set must fail")
	}
	if result.UntrustedSignerKey != hex.EncodeToString(pubB) || len(result.EndorsementGaps) != 1 {
		t.Fatalf("failure did not identify successor: %+v", result)
	}

	// In endorsement mode, extra roots do not silently replace a boundary
	// endorsement. The root set authenticates genesis only.
	result = VerifyChainWithEndorsements("proxy", chain, nil, []string{hex.EncodeToString(pubA), hex.EncodeToString(pubB)})
	if result.Valid || result.UntrustedSignerKey != hex.EncodeToString(pubB) || len(result.EndorsementGaps) != 1 {
		t.Fatalf("pre-pinned successor bypassed its endorsement: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_RejectsUntrustedGenesis(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	pubB, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)

	// Trusting only the successor must not let its presence bootstrap trust in
	// the unpinned genesis key. Delegation flows old -> new, never backward.
	result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement}, []string{hex.EncodeToString(pubB)})
	if result.Valid || !strings.Contains(result.Error, "genesis signer key") {
		t.Fatalf("untrusted genesis was accepted: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_RequiresPinnedRoot(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)

	result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement}, nil)
	if result.Valid || !strings.Contains(result.Error, "requires at least one trusted root key") {
		t.Fatalf("unpinned endorsement chain was accepted: %+v", result)
	}

	single, _ := buildSessionBoundRotatedChain(t, privA)
	result = VerifyChainWithEndorsements("proxy", single, nil, nil)
	if result.Valid || !strings.Contains(result.Error, "requires at least one trusted root key") {
		t.Fatalf("unpinned single-segment chain was accepted by endorsement verifier: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_RequiresSignedRecorderOpen(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	legacy := buildRotatedChain(t, privA, privB, 2, 1)
	endorsement := endorsementForBoundary(t, legacy, 2, privA)

	// ActionRecord.SessionID is an agent/logical session, not the recorder
	// namespace. It cannot substitute for a signed session_open binding.
	result := VerifyChainWithEndorsements("proxy", legacy, []RotationEndorsement{endorsement}, []string{hex.EncodeToString(pubA)})
	if result.Valid || !strings.Contains(result.Error, "no signed session_open") {
		t.Fatalf("legacy chain without signed recorder open was accepted: %+v", result)
	}

	// A successor-signed open cannot retroactively bind a legacy root segment
	// to the endorsement's recorder session.
	root, tail := buildSegment(t, privA, 2, GenesisHash, time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), nil)
	prior := root[len(root)-1]
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(pubA),
		PriorChainSeq:  prior.ActionRecord.ChainSeq,
		PriorChainHash: tail,
	}
	rotatedOpen := signRestartOpen(t, privB, 0, tail, prior.ActionRecord.ChainSeq, sessionOpenTestRunB, time.Date(2026, 4, 1, 1, 0, 0, 0, time.UTC), marker)
	successorBound := append(root, rotatedOpen)
	endorsement = endorsementForBoundary(t, successorBound, len(root), privA)
	result = VerifyChainWithEndorsements("proxy", successorBound, []RotationEndorsement{endorsement}, []string{hex.EncodeToString(pubA)})
	if result.Valid || !strings.Contains(result.Error, "root receipt segment") {
		t.Fatalf("successor-only recorder binding accepted: %+v", result)
	}
}

func TestVerifySignedRecorderSession_RequiresRootSegmentBinding(t *testing.T) {
	t.Parallel()
	receipts := []Receipt{
		{},
		{
			ActionRecord: ActionRecord{
				KeyTransition: &KeyTransition{},
				SessionControl: &SessionControl{
					Kind: SessionControlOpen,
					Open: &SessionOpen{RecorderSession: "proxy"},
				},
			},
		},
	}
	if err := verifySignedRecorderSession("proxy", receipts); err == nil || !strings.Contains(err.Error(), "root receipt segment") {
		t.Fatalf("successor-only recorder binding accepted: %v", err)
	}
}

func TestVerifyChainWithEndorsements_FailClosedInputBoundaries(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)
	root := []string{hex.EncodeToString(pubA)}

	t.Run("blank session", func(t *testing.T) {
		result := VerifyChainWithEndorsements(" ", chain, []RotationEndorsement{endorsement}, root)
		if result.Valid || !strings.Contains(result.Error, "requires a recorder session ID") {
			t.Fatalf("blank session accepted: %+v", result)
		}
	})
	t.Run("endorsement on empty chain", func(t *testing.T) {
		result := VerifyChainWithEndorsements("proxy", nil, []RotationEndorsement{endorsement}, root)
		if result.Valid || !strings.Contains(result.Error, "empty receipt chain") {
			t.Fatalf("endorsement on empty chain accepted: %+v", result)
		}
	})
	t.Run("empty chain without endorsement", func(t *testing.T) {
		result := VerifyChainWithEndorsements("proxy", nil, nil, root)
		if !result.Valid || !result.IntegrityVerified {
			t.Fatalf("empty chain result = %+v", result)
		}
	})
	t.Run("invalid trusted root", func(t *testing.T) {
		result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement}, []string{" "})
		if result.Valid || !strings.Contains(result.Error, "trusted key set") {
			t.Fatalf("invalid root accepted: %+v", result)
		}
	})
	t.Run("broken base chain", func(t *testing.T) {
		broken := append([]Receipt(nil), chain...)
		broken[0].Signature = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2)
		result := VerifyChainWithEndorsements("proxy", broken, []RotationEndorsement{endorsement}, root)
		if result.Valid || result.FailureKind != ChainFailureIntegrity {
			t.Fatalf("broken base chain accepted: %+v", result)
		}
	})
	t.Run("duplicate matching endorsement", func(t *testing.T) {
		result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement, endorsement}, root)
		if result.Valid || !strings.Contains(result.Error, "multiple rotation endorsements") {
			t.Fatalf("duplicate endorsement accepted: %+v", result)
		}
	})
}

func TestVerifyChainWithEndorsements_RejectsTruncationLaundering(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	original, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	boundary := boundaries[0]
	endorsement := endorsementForBoundary(t, original, boundary, privA)

	// A write-only attacker removes A's real tail, then opens a structurally
	// valid B segment on the shorter prefix. Replaying the real endorsement
	// cannot authorize the shortened tail because seq and hash are bound.
	short := append([]Receipt(nil), original[:boundary-1]...)
	shortTail := mustHash(t, short[len(short)-1])
	marker := &KeyTransition{
		PriorSignerKey: hex.EncodeToString(pubA),
		PriorChainSeq:  short[len(short)-1].ActionRecord.ChainSeq,
		PriorChainHash: shortTail,
	}
	forgedB, _ := buildSegment(t, privB, 2, shortTail, time.Date(2026, 4, 1, 2, 0, 0, 0, time.UTC), marker)
	forged := append(short, forgedB...)

	result := VerifyChainWithEndorsements("proxy", forged, []RotationEndorsement{endorsement}, []string{hex.EncodeToString(pubA)})
	if result.Valid || !strings.Contains(result.Error, "does not match receipt boundary") {
		t.Fatalf("truncation laundering was not rejected: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_RejectsAttackerSignedAuthorization(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	_, attacker := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	forged := endorsementForBoundary(t, chain, boundaries[0], attacker)
	// Claim the trusted retiring key after signing with the attacker's key.
	forged.PriorSignerKey = hex.EncodeToString(pubA)

	result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{forged}, []string{hex.EncodeToString(pubA)})
	if result.Valid || !strings.Contains(result.Error, "signature verification failed") {
		t.Fatalf("attacker-signed authorization was not rejected: %+v", result)
	}
}

func TestVerifyChainWithEndorsements_RejectsCrossSessionAndUnused(t *testing.T) {
	t.Parallel()
	pubA, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)

	crossSession := endorsement
	crossSession.SessionID = "other"
	resigned, err := SignRotationEndorsement(crossSession, privA)
	if err != nil {
		t.Fatalf("SignRotationEndorsement: %v", err)
	}
	if result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{resigned}, []string{hex.EncodeToString(pubA)}); result.Valid {
		t.Fatal("cross-session endorsement replay must fail")
	}
	if result := VerifyChainWithEndorsements("other", chain, []RotationEndorsement{resigned}, []string{hex.EncodeToString(pubA)}); result.Valid || !strings.Contains(result.Error, "signed recorder session") {
		t.Fatalf("caller-relabelled chain session was accepted: %+v", result)
	}

	_, unusedPriv := generateTestKey(t)
	unused := endorsement
	unused.NewSignerKey = hex.EncodeToString(unusedPriv.Public().(ed25519.PublicKey))
	unused, err = SignRotationEndorsement(unused, privA)
	if err != nil {
		t.Fatalf("SignRotationEndorsement unused: %v", err)
	}
	if result := VerifyChainWithEndorsements("proxy", chain, []RotationEndorsement{endorsement, unused}, []string{hex.EncodeToString(pubA)}); result.Valid {
		t.Fatal("unused endorsement must fail closed")
	}
}

func TestRotationEndorsementStrictDecodeAndDomainSeparation(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	_, privB := generateTestKey(t)
	chain, boundaries := buildSessionBoundRotatedChain(t, privA, privB)
	endorsement := endorsementForBoundary(t, chain, boundaries[0], privA)
	data, err := json.Marshal(endorsement)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := UnmarshalRotationEndorsement(data); err != nil {
		t.Fatalf("valid endorsement decode: %v", err)
	}

	cases := map[string][]byte{
		"unknown":   []byte(strings.Replace(string(data), `"endorsement":`, `"unknown":1,"endorsement":`, 1)),
		"duplicate": []byte(strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1)),
		"trailing":  append(append([]byte(nil), data...), []byte(` {}`)...),
	}
	for name, malformed := range cases {
		malformed := malformed
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := UnmarshalRotationEndorsement(malformed); err == nil {
				t.Fatal("malformed endorsement accepted")
			}
		})
	}

	// A receipt signature cannot be repurposed as a rotation authorization:
	// the endorsement digest carries a distinct domain separator.
	endorsement.Endorsement = chain[0].Signature
	if err := VerifyRotationEndorsement(endorsement); err == nil {
		t.Fatal("receipt signature accepted as rotation endorsement")
	}
}

func TestRotationEndorsementRejectsMalformedFields(t *testing.T) {
	t.Parallel()
	_, privA := generateTestKey(t)
	pubB, _ := generateTestKey(t)
	valid, err := SignRotationEndorsement(RotationEndorsement{
		SessionID:     "proxy",
		PriorFinalSeq: 7,
		PriorTailHash: strings.Repeat("a", sha256.Size*2),
		NewSignerKey:  hex.EncodeToString(pubB),
		RotatedAt:     time.Date(2026, 4, 1, 1, 0, 0, 0, time.UTC).Format(time.RFC3339Nano),
	}, privA)
	if err != nil {
		t.Fatalf("SignRotationEndorsement: %v", err)
	}

	cases := map[string]struct {
		mutate  func(*RotationEndorsement)
		wantErr string
	}{
		"version":          {func(e *RotationEndorsement) { e.Version++ }, "unsupported"},
		"session":          {func(e *RotationEndorsement) { e.SessionID = " " }, "session_id"},
		"prior key":        {func(e *RotationEndorsement) { e.PriorSignerKey = "00" }, "prior_signer_key"},
		"successor key":    {func(e *RotationEndorsement) { e.NewSignerKey = "00" }, "new_signer_key"},
		"same key":         {func(e *RotationEndorsement) { e.NewSignerKey = e.PriorSignerKey }, "must differ"},
		"tail hash":        {func(e *RotationEndorsement) { e.PriorTailHash = "00" }, "prior_tail_hash"},
		"rotation time":    {func(e *RotationEndorsement) { e.RotatedAt = "2026-04-01T02:00:00+01:00" }, "canonical UTC"},
		"empty signature":  {func(e *RotationEndorsement) { e.Endorsement = "" }, "signature is empty"},
		"signature prefix": {func(e *RotationEndorsement) { e.Endorsement = strings.TrimPrefix(e.Endorsement, signaturePrefix) }, "signature format"},
		"signature hex":    {func(e *RotationEndorsement) { e.Endorsement = signaturePrefix + "zz" }, "invalid endorsement signature"},
		"signature value": {func(e *RotationEndorsement) {
			e.Endorsement = signaturePrefix + strings.Repeat("0", ed25519.SignatureSize*2)
		}, "verification failed"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := valid
			tc.mutate(&candidate)
			if err := VerifyRotationEndorsement(candidate); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	if _, err := SignRotationEndorsement(valid, ed25519.PrivateKey("short")); err == nil || !strings.Contains(err.Error(), "private key size") {
		t.Fatalf("invalid private key error = %v", err)
	}
	unsigned := valid
	unsigned.SessionID = ""
	if _, err := SignRotationEndorsement(unsigned, privA); err == nil || !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("invalid field signing error = %v", err)
	}
}

func TestLoadRotationEndorsementFileBoundaries(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadRotationEndorsementFile(missing); err == nil || !strings.Contains(err.Error(), "read rotation endorsement") {
		t.Fatalf("missing file error = %v", err)
	}
	over := filepath.Join(t.TempDir(), "oversized.json")
	if err := os.WriteFile(over, []byte(strings.Repeat("x", maxRotationEndorsementBytes+1)), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadRotationEndorsementFile(over); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized file error = %v", err)
	}
}
