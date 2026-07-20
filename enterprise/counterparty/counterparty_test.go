//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestVerifyCounterpartyValidBoundPair(t *testing.T) {
	fx := newFixture(t)
	res := VerifyCounterparty(fx.request())
	if !res.Passed {
		t.Fatalf("VerifyCounterparty() failed: code=%s err=%s", res.FailureCode, res.Error)
	}
	wantNonce := NonceKey{
		SideRecordKeyID:  "receiver-counterparty-key",
		SenderIdentity:   "agent-a",
		ReceiverIdentity: "agent-b",
		Nonce:            "nonce-001",
	}
	if res.Nonce == nil || *res.Nonce != wantNonce {
		t.Fatalf("nonce = %+v, want %+v", res.Nonce, wantNonce)
	}
	if res.SignerKeyID != "receiver-counterparty-key" {
		t.Fatalf("signer key id = %q", res.SignerKeyID)
	}
}

func TestVerifyCounterpartyRejectsUnilateralFabricationWithSelfSignedSender(t *testing.T) {
	fx := newFixture(t)
	_, fakeSenderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(fake sender): %v", err)
	}
	fakeSenderReceipt := signReceipt(t, fakeSenderPriv, fx.sender.Receipt.ActionRecord.ActionID, "agent-a")

	req := fx.request()
	req.Sender = &BoundReceipt{Receipt: fakeSenderReceipt, Capture: fx.sender.Capture}
	req.Record = fx.resign(func(b *Binding) {
		b.SenderReceiptHash = mustReceiptHashLabel(t, fakeSenderReceipt)
	})

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a self-signed fake sender receipt, want fail closed")
	}
	if res.FailureCode != FailureTrust {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureTrust)
	}
}

// TestVerifyCounterpartyRejectsRogueSideRecordKey proves the receiver-scoped key
// fix: a record signed by any other enrolled counterparty key cannot attest a
// transfer to a receiver whose enrolled key is different. Before the fix, any
// key in a flat trusted-key map could attest any identity.
func TestVerifyCounterpartyRejectsRogueSideRecordKey(t *testing.T) {
	fx := newFixture(t)
	roguePub, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(rogue): %v", err)
	}
	req := fx.request()
	// A different, otherwise-valid counterparty key signs the real receiver's
	// binding. The receiver's enrolled key id/pub stays the honest one.
	req.Record = fx.signWith(func(_ *Binding) {}, "rogue-counterparty-key", roguePriv)

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a rogue side-record key, want fail closed")
	}
	if res.FailureCode != FailureTrust {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureTrust)
	}
	if !strings.Contains(res.Error, "enrolled") {
		t.Fatalf("error %q does not describe an enrolled-key mismatch", res.Error)
	}
	_ = roguePub
}

// TestVerifyCounterpartyRejectsRogueKeyForgingEnrolledKeyID proves the second
// layer: even if the attacker labels the record with the receiver's enrolled
// key id, the signature is verified against the receiver's real public key.
func TestVerifyCounterpartyRejectsRogueKeyForgingEnrolledKeyID(t *testing.T) {
	fx := newFixture(t)
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(rogue): %v", err)
	}
	req := fx.request()
	// Attacker forges the enrolled key id but signs with a rogue key.
	req.Record = fx.signWith(func(_ *Binding) {}, "receiver-counterparty-key", roguePriv)

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a forged-key-id rogue signature, want fail closed")
	}
	if res.FailureCode != FailureSignature {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureSignature)
	}
}

// TestVerifyCounterpartyRequiresSenderPayloadAttestation proves the payload is
// attested by BOTH parties: a receiver cannot bind a payload the sender never
// signed. The receiver signs a capture + binding for a forged payload; the
// sender's honest capture still attests the real payload, so verification fails.
func TestVerifyCounterpartyRequiresSenderPayloadAttestation(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	forged := PayloadHash([]byte("payload the sender never sent"))
	rcv := *req.Receiver
	rcv.Capture = signCapture(t, fx.recvPriv, rcv.Receipt, captureTestSpec{keyID: "receiver-receipt-key", payloadHash: forged, direction: DirectionIngress, party: "agent-b", counterparty: "agent-a"})
	req.Receiver = &rcv
	req.Record = fx.resign(func(b *Binding) { b.PayloadHash = forged })

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a payload the sender never attested, want fail closed")
	}
	if res.FailureCode != FailurePayloadHashMismatch {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailurePayloadHashMismatch)
	}
}

func TestVerifyCounterpartyRejectsForgedSenderCapture(t *testing.T) {
	fx := newFixture(t)
	_, roguePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(rogue): %v", err)
	}
	req := fx.request()
	snd := *req.Sender
	snd.Capture = signCapture(t, roguePriv, snd.Receipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: fx.payloadHash, direction: DirectionEgress, party: "agent-a", counterparty: "agent-b"})
	req.Sender = &snd
	res := VerifyCounterparty(req)
	if res.Passed || res.FailureCode != FailurePayloadCapture {
		t.Fatalf("passed=%v code=%s err=%s, want fail %s", res.Passed, res.FailureCode, res.Error, FailurePayloadCapture)
	}
}

func TestVerifyCounterpartyRejectsCaptureDirectionAndActionMismatch(t *testing.T) {
	for _, tc := range []struct {
		name    string
		capture func(fx *fixture) PayloadCapture
	}{
		{
			name: "wrong direction",
			capture: func(fx *fixture) PayloadCapture {
				return signCapture(t, fx.senderPriv, fx.sender.Receipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: fx.payloadHash, direction: DirectionIngress, party: "agent-a", counterparty: "agent-b"})
			},
		},
		{
			name: "wrong action id",
			capture: func(fx *fixture) PayloadCapture {
				actionHash, err := signedActionHash(fx.sender.Receipt)
				if err != nil {
					t.Fatalf("signedActionHash: %v", err)
				}
				return signCaptureForAction(t, fx.senderPriv, captureTestSpec{keyID: "sender-receipt-key", actionID: "different-action", actionHash: actionHash, payloadHash: fx.payloadHash, direction: DirectionEgress, party: "agent-a", counterparty: "agent-b"})
			},
		},
		{
			name: "wrong party identity",
			capture: func(fx *fixture) PayloadCapture {
				return signCapture(t, fx.senderPriv, fx.sender.Receipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: fx.payloadHash, direction: DirectionEgress, party: "agent-x", counterparty: "agent-b"})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			req := fx.request()
			snd := *req.Sender
			snd.Capture = tc.capture(fx)
			req.Sender = &snd
			res := VerifyCounterparty(req)
			if res.Passed || res.FailureCode != FailurePayloadCapture {
				t.Fatalf("passed=%v code=%s err=%s, want fail %s", res.Passed, res.FailureCode, res.Error, FailurePayloadCapture)
			}
		})
	}
}

func TestVerifyCounterpartyRejectsCaptureReusedForSameActionIDDifferentSignedAction(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()

	ar := req.Sender.Receipt.ActionRecord
	ar.Target = "https://api.vendor.example/v1/different-target"
	ar.Intent = "different signed action with reused action id"
	wrongReceipt, err := receipt.Sign(ar, fx.senderPriv)
	if err != nil {
		t.Fatalf("receipt.Sign(wrong action): %v", err)
	}
	req.Sender.Receipt = wrongReceipt
	req.Record = fx.resign(func(b *Binding) {
		b.SenderReceiptHash = mustReceiptHashLabel(t, wrongReceipt)
	})

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a capture reused against a different signed action with the same action_id")
	}
	if res.FailureCode != FailurePayloadCapture {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailurePayloadCapture)
	}
}

func TestVerifyCounterpartyRejectsSenderCaptureReusedForDifferentCounterparty(t *testing.T) {
	fx := newFixture(t)
	recvCPub, recvCPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(receiver-c): %v", err)
	}
	sideCPub, sideCPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(receiver-c side): %v", err)
	}
	receiverCReceipt := signReceipt(t, recvCPriv, "receiver-c-action", "agent-c")
	receiverCCapture := signCapture(t, recvCPriv, receiverCReceipt, captureTestSpec{keyID: "receiver-c-receipt-key", payloadHash: fx.payloadHash, direction: DirectionIngress, party: "agent-c", counterparty: "agent-a"})
	record, err := SignRecord(fleetLicense(), Record{Binding: Binding{
		PayloadHash:         fx.payloadHash,
		SenderIdentity:      "agent-a",
		ReceiverIdentity:    "agent-c",
		Nonce:               "nonce-001",
		SenderReceiptID:     fx.sender.Receipt.ActionRecord.ActionID,
		SenderReceiptHash:   mustReceiptHashLabel(t, fx.sender.Receipt),
		ReceiverReceiptID:   receiverCReceipt.ActionRecord.ActionID,
		ReceiverReceiptHash: mustReceiptHashLabel(t, receiverCReceipt),
		Timestamp:           fx.record.Binding.Timestamp,
		Version:             Version,
	}}, "receiver-c-counterparty-key", sideCPriv)
	if err != nil {
		t.Fatalf("SignRecord(receiver-c): %v", err)
	}

	req := fx.request()
	req.Receiver = &BoundReceipt{Receipt: receiverCReceipt, Capture: receiverCCapture}
	req.Record = &record
	req.ReceiverReceiptKey = recvCPub
	req.ReceiverSideRecordKey = sideCPub
	req.ReceiverSideRecordKeyID = "receiver-c-counterparty-key"

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted an agent-a->agent-b sender capture inside an agent-a->agent-c transfer")
	}
	if res.FailureCode != FailurePayloadCapture {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailurePayloadCapture)
	}
}

// TestBindingRejectsNonASCIIToken closes the Unicode-normalization replay
// bypass: the signed hash NFC-normalizes strings, but the replay key uses the
// raw string. Restricting identity/nonce/id fields to ASCII makes NFC a no-op,
// so the two forms that collided can no longer both be built or accepted.
func TestBindingRejectsNonASCIIToken(t *testing.T) {
	fx := newFixture(t)

	// SignRecord refuses to even create a record with a non-ASCII nonce.
	rec := fx.record
	rec.Binding.Nonce = "é" // "e" + combining acute; NFC-equals "é"
	if _, err := SignRecord(fleetLicense(), Record{Binding: rec.Binding}, "receiver-counterparty-key", fx.cpPriv); !errors.Is(err, ErrMalformedBinding) {
		t.Fatalf("SignRecord(non-ascii nonce) error = %v, want ErrMalformedBinding", err)
	}

	// A hand-crafted record (bypassing SignRecord) is rejected before signature.
	req := fx.request()
	req.Record.Binding.Nonce = "é"
	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted a non-ASCII nonce, want fail closed")
	}
	if res.FailureCode != FailureMalformedBinding {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureMalformedBinding)
	}
}

func TestVerifyCounterpartyFreshness(t *testing.T) {
	base := time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)
	testCases := []struct {
		name string
		mut  func(*VerifyRequest)
		want FailureCode
	}{
		{
			name: "stale beyond max age",
			mut: func(req *VerifyRequest) {
				req.Now = base.Add(48 * time.Hour) // ts is base; MaxAge is 24h
			},
			want: FailureStale,
		},
		{
			name: "too far in the future",
			mut: func(req *VerifyRequest) {
				req.Now = base.Add(-time.Hour) // ts is base, 1h ahead; skew is 5m
			},
			want: FailureFuture,
		},
		{
			name: "missing verify time",
			mut: func(req *VerifyRequest) {
				req.Now = time.Time{}
			},
			want: FailureMissingInput,
		},
		{
			name: "non-positive max age",
			mut: func(req *VerifyRequest) {
				req.MaxAge = 0
			},
			want: FailureMissingInput,
		},
		{
			name: "non-positive future skew",
			mut: func(req *VerifyRequest) {
				req.MaxFutureSkew = 0
			},
			want: FailureMissingInput,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			req := fx.request()
			tc.mut(&req)
			res := VerifyCounterparty(req)
			if res.Passed {
				t.Fatal("VerifyCounterparty() passed, want fail closed")
			}
			if res.FailureCode != tc.want {
				t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, tc.want)
			}
		})
	}
}

func TestVerifyCounterpartyExactAgeBoundaryPasses(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	// ts is exactly MaxAge old and exactly MaxFutureSkew is unused here.
	req.Now = fx.record.Binding.Timestamp.Add(req.MaxAge)
	res := VerifyCounterparty(req)
	if !res.Passed {
		t.Fatalf("VerifyCounterparty() at exact max-age boundary failed: code=%s err=%s", res.FailureCode, res.Error)
	}
}

func TestVerifyCounterpartyRequiresReplayStore(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	req.ReplayStore = nil
	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() passed without a replay store, want fail closed")
	}
	if res.FailureCode != FailureMissingInput {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureMissingInput)
	}
}

func TestVerifyCounterpartyRejectsReplayedRecord(t *testing.T) {
	fx := newFixture(t)
	store := NewMemReplayStore()
	req := fx.request()
	req.ReplayStore = store
	if res := VerifyCounterparty(req); !res.Passed {
		t.Fatalf("first VerifyCounterparty() failed: %s", res.Error)
	}

	replay := fx.request()
	replay.ReplayStore = store
	res := VerifyCounterparty(replay)
	if res.Passed {
		t.Fatal("VerifyCounterparty() re-accepted the identical record, want fail closed")
	}
	if res.FailureCode != FailureReplay {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureReplay)
	}
}

// TestVerifyCounterpartyRejectsReSignedTransfer proves the TransferKey dedup:
// the same two receipts + payload re-signed under a fresh nonce cannot inflate a
// coverage count.
func TestVerifyCounterpartyRejectsReSignedTransfer(t *testing.T) {
	fx := newFixture(t)
	store := NewMemReplayStore()
	req := fx.request()
	req.ReplayStore = store
	if res := VerifyCounterparty(req); !res.Passed {
		t.Fatalf("first VerifyCounterparty() failed: %s", res.Error)
	}

	replay := fx.request()
	replay.ReplayStore = store
	replay.Record = fx.resign(func(b *Binding) { b.Nonce = "nonce-002" })
	res := VerifyCounterparty(replay)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted the same transfer under a new nonce, want fail closed")
	}
	if res.FailureCode != FailureReplay {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureReplay)
	}
}

// TestVerifyCounterpartyRejectsReSignedTransferWithMutableReceiptEnvelope proves
// TransferKey is based on signed receipt content rather than mutable envelope
// bytes. The receipt signature hex string can be re-cased without changing the
// Ed25519 signature bytes; that must not let the same real transfer pass again
// under a fresh side-record nonce.
func TestVerifyCounterpartyRejectsReSignedTransferWithMutableReceiptEnvelope(t *testing.T) {
	fx := newFixture(t)
	store := NewMemReplayStore()
	req := fx.request()
	req.ReplayStore = store
	if res := VerifyCounterparty(req); !res.Passed {
		t.Fatalf("first VerifyCounterparty() failed: %s", res.Error)
	}

	replay := fx.request()
	replay.ReplayStore = store
	mutatedSender := fx.sender
	replay.Sender = &mutatedSender
	replay.Sender.Receipt.Signature = "ed25519:" + strings.ToUpper(strings.TrimPrefix(replay.Sender.Receipt.Signature, "ed25519:"))
	if replay.Sender.Receipt.Signature == fx.sender.Receipt.Signature {
		t.Skip("fixture signature had no lowercase hex letters to mutate")
	}
	replay.Record = fx.resign(func(b *Binding) {
		b.Nonce = "nonce-002"
		b.SenderReceiptHash = mustReceiptHashLabel(t, replay.Sender.Receipt)
	})

	res := VerifyCounterparty(replay)
	if res.Passed {
		t.Fatal("VerifyCounterparty() accepted the same transfer with a mutable receipt envelope, want fail closed")
	}
	if res.FailureCode != FailureReplay {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureReplay)
	}
}

// TestVerifyCounterpartyRejectedRecordDoesNotConsumeReplayState proves a record
// that fails a non-mutating check (staleness) never inserts its nonce, so a
// later honest record with the same nonce still passes.
func TestVerifyCounterpartyRejectedRecordDoesNotConsumeReplayState(t *testing.T) {
	fx := newFixture(t)
	store := NewMemReplayStore()

	stale := fx.request()
	stale.ReplayStore = store
	stale.Now = fx.record.Binding.Timestamp.Add(48 * time.Hour)
	if res := VerifyCounterparty(stale); res.FailureCode != FailureStale {
		t.Fatalf("stale record: code=%s err=%s, want %s", res.FailureCode, res.Error, FailureStale)
	}

	honest := fx.request()
	honest.ReplayStore = store
	if res := VerifyCounterparty(honest); !res.Passed {
		t.Fatalf("honest record after a rejected one failed: code=%s err=%s (rejected record consumed replay state)", res.FailureCode, res.Error)
	}
}

func TestVerifyCounterpartyBytesStrictParsing(t *testing.T) {
	fx := newFixture(t)

	honest, err := json.Marshal(fx.record)
	if err != nil {
		t.Fatalf("Marshal record: %v", err)
	}
	req := fx.request()
	req.Record = nil
	if res := VerifyCounterpartyBytes(req, honest); !res.Passed {
		t.Fatalf("VerifyCounterpartyBytes(honest) failed: code=%s err=%s", res.FailureCode, res.Error)
	}

	dup := []byte(`{"record_type":"counterparty_receipt_v1","record_type":"x"}`)
	if res := VerifyCounterpartyBytes(fx.request(), dup); res.Passed || res.FailureCode != FailureMalformedBinding {
		t.Fatalf("VerifyCounterpartyBytes(dup keys): passed=%v code=%s, want fail %s", res.Passed, res.FailureCode, FailureMalformedBinding)
	}

	unknown := append(honest[:len(honest)-1:len(honest)-1], []byte(`,"extra":true}`)...)
	if res := VerifyCounterpartyBytes(fx.request(), unknown); res.Passed || res.FailureCode != FailureMalformedBinding {
		t.Fatalf("VerifyCounterpartyBytes(unknown field): passed=%v code=%s, want fail %s", res.Passed, res.FailureCode, FailureMalformedBinding)
	}
}

func TestVerifyCounterpartyFailClosedNegatives(t *testing.T) {
	testCases := []struct {
		name string
		mut  func(*fixture, *VerifyRequest)
		want FailureCode
	}{
		{
			name: "TestCounterpartyVerifyRejectsTamperedPayloadHashSender",
			mut: func(fx *fixture, req *VerifyRequest) {
				// Sender validly attests a DIFFERENT payload than the binding.
				capture := *req.Sender
				capture.Capture = signCapture(t, fx.senderPriv, capture.Receipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: PayloadHash([]byte("different sender bytes")), direction: DirectionEgress, party: "agent-a", counterparty: "agent-b"})
				req.Sender = &capture
			},
			want: FailurePayloadHashMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsTamperedPayloadHashReceiver",
			mut: func(fx *fixture, req *VerifyRequest) {
				capture := *req.Receiver
				capture.Capture = signCapture(t, fx.recvPriv, capture.Receipt, captureTestSpec{keyID: "receiver-receipt-key", payloadHash: PayloadHash([]byte("different receiver bytes")), direction: DirectionIngress, party: "agent-b", counterparty: "agent-a"})
				req.Receiver = &capture
			},
			want: FailurePayloadHashMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsMissingSenderReceipt",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.Sender = nil
			},
			want: FailureMissingInput,
		},
		{
			name: "TestCounterpartyVerifyRejectsMissingReceiverSideRecord",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.Record = nil
			},
			want: FailureMissingInput,
		},
		{
			name: "TestCounterpartyVerifyRejectsInvalidSenderReceipt",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.Sender.Receipt.Signature = "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
			want: FailureInvalidReceipt,
		},
		{
			name: "TestCounterpartyVerifyRejectsInvalidReceiverReceipt",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.Receiver.Receipt.SignerKey = strings.Repeat("0", ed25519.PublicKeySize*2)
				req.ReceiverReceiptKey = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
			},
			want: FailureInvalidReceipt,
		},
		{
			name: "TestCounterpartyVerifyRejectsSenderReceiptIDMismatch",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Record = fx.resign(func(b *Binding) { b.SenderReceiptID = "wrong-sender-receipt" })
			},
			want: FailureReceiptIDMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsSenderReceiptHashMismatch",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Record = fx.resign(func(b *Binding) { b.SenderReceiptHash = PayloadHash([]byte("wrong sender receipt")) })
			},
			want: FailureReceiptHashMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsReceiverReceiptIDMismatch",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Record = fx.resign(func(b *Binding) { b.ReceiverReceiptID = "wrong-receiver-receipt" })
			},
			want: FailureReceiptIDMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsReceiverReceiptHashMismatch",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Record = fx.resign(func(b *Binding) { b.ReceiverReceiptHash = PayloadHash([]byte("wrong receiver receipt")) })
			},
			want: FailureReceiptHashMismatch,
		},
		{
			name: "TestCounterpartyVerifyRejectsWrongEnrolledSideRecordKeyID",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.ReceiverSideRecordKeyID = "not-the-enrolled-key"
			},
			want: FailureTrust,
		},
		{
			name: "TestCounterpartyVerifyRejectsInvalidSideRecordSignature",
			mut: func(_ *fixture, req *VerifyRequest) {
				req.Record.Signature.Sig = "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
			want: FailureSignature,
		},
		{
			name: "TestCounterpartyVerifyRejectsSameIdentity",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Record = fx.resign(func(b *Binding) { b.ReceiverIdentity = b.SenderIdentity })
			},
			want: FailureSelfCounterparty,
		},
		{
			name: "TestCounterpartyVerifyRejectsSameReceiptSignerKey",
			mut: func(fx *fixture, req *VerifyRequest) {
				req.Receiver.Receipt = signReceipt(t, fx.senderPriv, "receiver-action", "agent-b")
				req.Receiver.Capture = signCapture(t, fx.senderPriv, req.Receiver.Receipt, captureTestSpec{keyID: "receiver-receipt-key", payloadHash: fx.payloadHash, direction: DirectionIngress, party: "agent-b", counterparty: "agent-a"})
				req.ReceiverReceiptKey = fx.senderPub
				req.Record = fx.resign(func(b *Binding) {
					b.ReceiverReceiptHash = mustReceiptHashLabel(t, req.Receiver.Receipt)
				})
			},
			want: FailureSelfCounterparty,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newFixture(t)
			req := fx.request()
			tc.mut(fx, &req)
			res := VerifyCounterparty(req)
			if res.Passed {
				t.Fatal("VerifyCounterparty() passed, want fail closed")
			}
			if res.FailureCode != tc.want {
				t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, tc.want)
			}
		})
	}
}

func TestCounterpartyVerifyRejectsMissingTrustedReceiptKeys(t *testing.T) {
	fx := newFixture(t)
	for _, tc := range []struct {
		name string
		mut  func(*VerifyRequest)
	}{
		{
			name: "missing sender key",
			mut: func(req *VerifyRequest) {
				req.SenderReceiptKey = nil
			},
		},
		{
			name: "missing receiver key",
			mut: func(req *VerifyRequest) {
				req.ReceiverReceiptKey = nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := fx.request()
			tc.mut(&req)
			res := VerifyCounterparty(req)
			if res.Passed {
				t.Fatal("VerifyCounterparty() passed without a trusted receipt key, want fail closed")
			}
			if res.FailureCode != FailureTrust {
				t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureTrust)
			}
		})
	}
}

func TestCounterpartyVerifyRejectsReceiptIdentityMismatch(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	req.Sender.Receipt = signReceipt(t, fx.senderPriv, "sender-action", "agent-x")
	req.Sender.Capture = signCapture(t, fx.senderPriv, req.Sender.Receipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: fx.payloadHash, direction: DirectionEgress, party: "agent-x", counterparty: "agent-b"})
	req.Record = fx.resign(func(b *Binding) {
		b.SenderReceiptHash = mustReceiptHashLabel(t, req.Sender.Receipt)
	})

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() passed with mismatched sender receipt identity, want fail closed")
	}
	if res.FailureCode != FailureIdentityMismatch {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureIdentityMismatch)
	}
}

func TestCounterpartyVerifyRejectsSideRecordKeyReuse(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	// Enroll the sender's receipt key as the receiver's side-record key: the
	// side record must be signed by a key separate from both receipt keys.
	req.ReceiverSideRecordKey = fx.senderPub
	req.ReceiverSideRecordKeyID = "sender-counterparty-key"
	req.Record = fx.signWith(func(_ *Binding) {}, "sender-counterparty-key", fx.senderPriv)

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() passed with side-record key reused as a receipt key, want fail closed")
	}
	if res.FailureCode != FailureTrust {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureTrust)
	}
}

func TestCounterpartyRecordStrictParsingRejectsUnknownFields(t *testing.T) {
	fx := newFixture(t)
	raw, err := json.Marshal(fx.record)
	if err != nil {
		t.Fatalf("Marshal record: %v", err)
	}
	raw = append(raw[:len(raw)-1], []byte(`,"extra":true}`)...)
	_, err = UnmarshalRecord(raw)
	if !errors.Is(err, ErrUnknownField) {
		t.Fatalf("UnmarshalRecord unknown field error = %v, want ErrUnknownField", err)
	}
}

func TestUnmarshalPayloadCaptureStrict(t *testing.T) {
	fx := newFixture(t)
	raw, err := json.Marshal(fx.sender.Capture)
	if err != nil {
		t.Fatalf("Marshal capture: %v", err)
	}
	if _, err := UnmarshalPayloadCapture(raw); err != nil {
		t.Fatalf("UnmarshalPayloadCapture(valid) = %v", err)
	}
	if _, err := UnmarshalPayloadCapture([]byte(`{"record_type":"x","record_type":"y"}`)); !errors.Is(err, receipt.ErrDuplicateKey) {
		t.Fatalf("dup keys = %v", err)
	}
	unknown := append(raw[:len(raw)-1:len(raw)-1], []byte(`,"extra":true}`)...)
	if _, err := UnmarshalPayloadCapture(unknown); !errors.Is(err, ErrUnknownField) {
		t.Fatalf("unknown field = %v", err)
	}
	trailing := append(append([]byte{}, raw...), []byte(" junk")...)
	if _, err := UnmarshalPayloadCapture(trailing); !errors.Is(err, ErrTrailingTokens) {
		t.Fatalf("trailing tokens = %v", err)
	}
}

func TestCounterpartyRecordStrictParsingRejectsDuplicateKeys(t *testing.T) {
	_, err := UnmarshalRecord([]byte(`{"record_type":"counterparty_receipt_v1","record_type":"counterparty_receipt_v1"}`))
	if !errors.Is(err, receipt.ErrDuplicateKey) {
		t.Fatalf("UnmarshalRecord duplicate key error = %v, want duplicate-key sentinel", err)
	}
}

func TestCounterpartyRecordSignatureRejectsNonCanonicalBase64(t *testing.T) {
	fx := newFixture(t)
	req := fx.request()
	req.Record.Signature.Sig = strings.Replace(req.Record.Signature.Sig, "ed25519:", "ed25519:\n", 1)

	res := VerifyCounterparty(req)
	if res.Passed {
		t.Fatal("VerifyCounterparty() passed with non-canonical base64 signature, want fail closed")
	}
	if res.FailureCode != FailureSignature {
		t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureSignature)
	}
}

func TestCounterpartySignAndSignatureVerifyRequireFleetFeatureFailClosed(t *testing.T) {
	fx := newFixture(t)
	for _, lic := range []license.License{
		{},
		{Features: []string{license.FeatureAgents}},
	} {
		if _, err := SignRecord(lic, Record{Binding: fx.record.Binding}, "receiver-counterparty-key", fx.cpPriv); !errors.Is(err, ErrFleetRequired) {
			t.Fatalf("SignRecord() error = %v, want ErrFleetRequired", err)
		}
		if err := VerifyRecordSignature(lic, fx.record, "receiver-counterparty-key", fx.cpPub); !errors.Is(err, ErrFleetRequired) {
			t.Fatalf("VerifyRecordSignature() error = %v, want ErrFleetRequired", err)
		}
	}
}

func TestCounterpartyCoSignRequiresFleetFeatureFailClosed(t *testing.T) {
	fx := newFixture(t)
	for _, tc := range []struct {
		name string
		lic  license.License
	}{
		{name: "no license", lic: license.License{}},
		{name: "wrong tier agents only", lic: license.License{Features: []string{license.FeatureAgents}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := fx.request()
			req.License = tc.lic
			res := VerifyCounterparty(req)
			if res.Passed {
				t.Fatal("VerifyCounterparty() passed without fleet license, want fail closed")
			}
			if res.FailureCode != FailureLicense {
				t.Fatalf("failure code = %s err=%s, want %s", res.FailureCode, res.Error, FailureLicense)
			}
		})
	}

	if err := receipt.VerifyWithKey(fx.sender.Receipt, fx.sender.Receipt.SignerKey); err != nil {
		t.Fatalf("free receipt verification changed: %v", err)
	}
}

func TestMemReplayStoreConcurrentCommitExactlyOnce(t *testing.T) {
	store := NewMemReplayStore()
	entry := ReplayEntry{
		NonceKey:    NonceKey{SideRecordKeyID: "k", SenderIdentity: "a", ReceiverIdentity: "b", Nonce: "n"},
		TransferKey: TransferKey{SenderIdentity: "a", ReceiverIdentity: "b", PayloadHash: replayHashA, SenderReceiptID: "s", ReceiverReceiptID: "r", SenderActionHash: replayHashC, ReceiverActionHash: replayHashD},
		RecordHash:  replayHashE,
		Timestamp:   time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
	}
	const workers = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if err := store.CommitIfNew(entry); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if !errors.Is(err, ErrReplayConflict) {
				t.Errorf("CommitIfNew unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent CommitIfNew succeeded %d times, want exactly 1", successes)
	}
}

type fixture struct {
	senderPub  ed25519.PublicKey
	senderPriv ed25519.PrivateKey
	recvPub    ed25519.PublicKey
	recvPriv   ed25519.PrivateKey
	cpPriv     ed25519.PrivateKey
	cpPub      ed25519.PublicKey

	sender      BoundReceipt
	receiver    BoundReceipt
	payloadHash string
	record      Record
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(sender): %v", err)
	}
	recvPub, recvPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(receiver): %v", err)
	}
	cpPub, cpPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(counterparty): %v", err)
	}
	payloadHash := PayloadHash([]byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"url":"https://api.vendor.example/v1/tasks"}}`))
	senderReceipt := signReceipt(t, senderPriv, "sender-action", "agent-a")
	receiverReceipt := signReceipt(t, recvPriv, "receiver-action", "agent-b")
	senderCapture := signCapture(t, senderPriv, senderReceipt, captureTestSpec{keyID: "sender-receipt-key", payloadHash: payloadHash, direction: DirectionEgress, party: "agent-a", counterparty: "agent-b"})
	receiverCapture := signCapture(t, recvPriv, receiverReceipt, captureTestSpec{keyID: "receiver-receipt-key", payloadHash: payloadHash, direction: DirectionIngress, party: "agent-b", counterparty: "agent-a"})
	fx := &fixture{
		senderPub:   senderPub,
		senderPriv:  senderPriv,
		recvPub:     recvPub,
		recvPriv:    recvPriv,
		cpPriv:      cpPriv,
		cpPub:       cpPub,
		payloadHash: payloadHash,
		sender:      BoundReceipt{Receipt: senderReceipt, Capture: senderCapture},
		receiver:    BoundReceipt{Receipt: receiverReceipt, Capture: receiverCapture},
	}
	rec := Record{
		Binding: Binding{
			PayloadHash:         payloadHash,
			SenderIdentity:      "agent-a",
			ReceiverIdentity:    "agent-b",
			Nonce:               "nonce-001",
			SenderReceiptID:     senderReceipt.ActionRecord.ActionID,
			SenderReceiptHash:   mustReceiptHashLabel(t, senderReceipt),
			ReceiverReceiptID:   receiverReceipt.ActionRecord.ActionID,
			ReceiverReceiptHash: mustReceiptHashLabel(t, receiverReceipt),
			Timestamp:           time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
			Version:             Version,
		},
	}
	signed, err := SignRecord(fleetLicense(), rec, "receiver-counterparty-key", cpPriv)
	if err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	fx.record = signed
	return fx
}

func (fx *fixture) request() VerifyRequest {
	return VerifyRequest{
		License:                 license.License{Features: []string{license.FeatureFleet}},
		Sender:                  &fx.sender,
		Receiver:                &fx.receiver,
		Record:                  &fx.record,
		SenderReceiptKey:        fx.senderPub,
		ReceiverReceiptKey:      fx.recvPub,
		ReceiverSideRecordKey:   fx.cpPub,
		ReceiverSideRecordKeyID: "receiver-counterparty-key",
		Now:                     fx.record.Binding.Timestamp,
		MaxAge:                  24 * time.Hour,
		MaxFutureSkew:           5 * time.Minute,
		ReplayStore:             NewMemReplayStore(),
	}
}

func (fx *fixture) resign(mut func(*Binding)) *Record {
	return fx.signWith(mut, "receiver-counterparty-key", fx.cpPriv)
}

func (fx *fixture) signWith(mut func(*Binding), keyID string, privKey ed25519.PrivateKey) *Record {
	rec := fx.record
	mut(&rec.Binding)
	signed, err := SignRecord(fleetLicense(), Record{Binding: rec.Binding}, keyID, privKey)
	if err != nil {
		panic(err)
	}
	return &signed
}

// captureTestSpec holds the inputs for signing a test payload capture, keeping
// the signing helpers within the parameter-count guideline.
type captureTestSpec struct {
	keyID        string
	actionID     string
	actionHash   string
	payloadHash  string
	direction    string
	party        string
	counterparty string
}

// signCapture signs a payload capture, deriving action id and action hash from r.
func signCapture(t *testing.T, priv ed25519.PrivateKey, r receipt.Receipt, spec captureTestSpec) PayloadCapture {
	t.Helper()
	actionHash, err := signedActionHash(r)
	if err != nil {
		t.Fatalf("signedActionHash: %v", err)
	}
	spec.actionID = r.ActionRecord.ActionID
	spec.actionHash = actionHash
	return signCaptureForAction(t, priv, spec)
}

func signCaptureForAction(t *testing.T, priv ed25519.PrivateKey, spec captureTestSpec) PayloadCapture {
	t.Helper()
	c, err := SignPayloadCapture(PayloadCapture{
		ActionID:             spec.actionID,
		ActionHash:           spec.actionHash,
		PayloadHash:          spec.payloadHash,
		Direction:            spec.direction,
		PartyIdentity:        spec.party,
		CounterpartyIdentity: spec.counterparty,
	}, spec.keyID, priv)
	if err != nil {
		t.Fatalf("SignPayloadCapture: %v", err)
	}
	return c
}

func signReceipt(t *testing.T, priv ed25519.PrivateKey, actionID, actor string) receipt.Receipt {
	t.Helper()
	r, err := receipt.Sign(receipt.ActionRecord{
		Version:         receipt.ActionRecordVersion,
		ActionID:        actionID,
		ActionType:      receipt.ActionWrite,
		Timestamp:       time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
		Principal:       actor,
		Actor:           actor,
		DelegationChain: []string{actor},
		Target:          "https://api.vendor.example/v1/tasks",
		Intent:          "counterparty fixture",
		SideEffectClass: receipt.SideEffectExternalWrite,
		Reversibility:   receipt.ReversibilityCompensatable,
		PolicyHash:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Verdict:         "allow",
		Transport:       "a2a-http",
		Method:          "POST",
		ChainPrevHash:   receipt.GenesisHash,
	}, priv)
	if err != nil {
		t.Fatalf("receipt.Sign: %v", err)
	}
	return r
}

func mustReceiptHashLabel(t *testing.T, r receipt.Receipt) string {
	t.Helper()
	h, err := receipt.ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	return hashPrefix + h
}

func fleetLicense() license.License {
	return license.License{Features: []string{license.FeatureFleet}}
}
