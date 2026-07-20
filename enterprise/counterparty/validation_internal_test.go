//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package counterparty

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const goodHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validBinding() Binding {
	return Binding{
		PayloadHash:         goodHash,
		SenderIdentity:      "agent-a",
		ReceiverIdentity:    "agent-b",
		Nonce:               "nonce-001",
		SenderReceiptID:     "sender-action",
		SenderReceiptHash:   goodHash,
		ReceiverReceiptID:   "receiver-action",
		ReceiverReceiptHash: goodHash,
		Timestamp:           time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC),
		Version:             Version,
	}
}

func TestValidateBindingRejects(t *testing.T) {
	cases := map[string]func(*Binding){
		"bad version":          func(b *Binding) { b.Version = 99 },
		"bad payload hash":     func(b *Binding) { b.PayloadHash = "nope" },
		"empty sender id":      func(b *Binding) { b.SenderIdentity = "" },
		"empty receiver id":    func(b *Binding) { b.ReceiverIdentity = "" },
		"empty nonce":          func(b *Binding) { b.Nonce = "" },
		"empty sender rcpt id": func(b *Binding) { b.SenderReceiptID = "" },
		"bad sender rcpt hash": func(b *Binding) { b.SenderReceiptHash = "x" },
		"empty recv rcpt id":   func(b *Binding) { b.ReceiverReceiptID = "" },
		"bad recv rcpt hash":   func(b *Binding) { b.ReceiverReceiptHash = "sha256:zz" },
		"zero ts":              func(b *Binding) { b.Timestamp = time.Time{} },
		"non-ascii identity":   func(b *Binding) { b.SenderIdentity = "agént" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			b := validBinding()
			mut(&b)
			if err := validateBinding(b); !errors.Is(err, ErrMalformedBinding) {
				t.Fatalf("validateBinding(%s) = %v, want ErrMalformedBinding", name, err)
			}
		})
	}
	if err := validateBinding(validBinding()); err != nil {
		t.Fatalf("validateBinding(valid) = %v, want nil", err)
	}
}

func TestValidateHashRejects(t *testing.T) {
	for name, v := range map[string]string{
		"no prefix":  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
		"bad hex":    "sha256:zzzz",
		"wrong len":  "sha256:00",
		"upper case": "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateHash("f", v); err == nil {
				t.Fatalf("validateHash(%s) = nil, want error", name)
			}
		})
	}
	if err := validateHash("f", goodHash); err != nil {
		t.Fatalf("validateHash(good) = %v", err)
	}
}

func TestValidateTokenRejects(t *testing.T) {
	for name, v := range map[string]string{
		"empty":     "",
		"too long":  strings.Repeat("a", maxTokenLen+1),
		"space":     "a b",
		"non-ascii": "café",
		"control":   "a\tb",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateToken("f", v); err == nil {
				t.Fatalf("validateToken(%s) = nil, want error", name)
			}
		})
	}
	if err := validateToken("f", "agent-a.1:x/y"); err != nil {
		t.Fatalf("validateToken(good) = %v", err)
	}
}

func TestDecodeSignatureRejects(t *testing.T) {
	valid := "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	for name, v := range map[string]string{
		"no prefix":     base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		"bad base64":    "ed25519:!!!!",
		"wrong len":     "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 8)),
		"non-canonical": strings.Replace(valid, "ed25519:", "ed25519:\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeSignature(v); err == nil {
				t.Fatalf("decodeSignature(%s) = nil, want error", name)
			}
		})
	}
	if _, err := decodeSignature(valid); err != nil {
		t.Fatalf("decodeSignature(valid) = %v", err)
	}
}

func TestSignRecordErrors(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := Record{Binding: validBinding()}
	if _, err := SignRecord(fleetLicense(), rec, "kid", priv[:8]); err == nil {
		t.Fatal("SignRecord(bad key size) = nil")
	}
	if _, err := SignRecord(fleetLicense(), rec, "", priv); err == nil {
		t.Fatal("SignRecord(empty keyID) = nil")
	}
	bad := Record{Binding: validBinding()}
	bad.Binding.Nonce = ""
	if _, err := SignRecord(fleetLicense(), bad, "kid", priv); !errors.Is(err, ErrMalformedBinding) {
		t.Fatalf("SignRecord(bad binding) = %v", err)
	}
}

func TestSignPayloadCaptureErrors(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := PayloadCapture{ActionID: "a", ActionHash: goodHash, PayloadHash: goodHash, Direction: DirectionEgress, PartyIdentity: "agent-a", CounterpartyIdentity: "agent-b"}
	if _, err := SignPayloadCapture(c, "kid", priv[:8]); err == nil {
		t.Fatal("SignPayloadCapture(bad key size) = nil")
	}
	if _, err := SignPayloadCapture(c, "", priv); err == nil {
		t.Fatal("SignPayloadCapture(empty keyID) = nil")
	}
	bad := c
	bad.Direction = "sideways"
	if _, err := SignPayloadCapture(bad, "kid", priv); !errors.Is(err, ErrPayloadCapture) {
		t.Fatalf("SignPayloadCapture(bad direction) = %v", err)
	}
	bad = c
	bad.PayloadHash = "nope"
	if _, err := SignPayloadCapture(bad, "kid", priv); !errors.Is(err, ErrPayloadCapture) {
		t.Fatalf("SignPayloadCapture(bad hash) = %v", err)
	}
}

func TestVerifyRecordSignatureErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signed, err := SignRecord(fleetLicense(), Record{Binding: validBinding()}, "kid", priv)
	if err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	lic := fleetLicense()

	if err := VerifyRecordSignature(lic, signed, "kid", pub); err != nil {
		t.Fatalf("VerifyRecordSignature(valid) = %v", err)
	}

	bad := signed
	bad.RecordType = "other"
	if err := VerifyRecordSignature(lic, bad, "kid", pub); err == nil {
		t.Fatal("VerifyRecordSignature(bad record_type) = nil")
	}

	bad = signed
	bad.Signature.Alg = "rsa"
	if err := VerifyRecordSignature(lic, bad, "kid", pub); err == nil {
		t.Fatal("VerifyRecordSignature(bad alg) = nil")
	}

	bad = signed
	bad.Signature.KeyID = ""
	if err := VerifyRecordSignature(lic, bad, "kid", pub); err == nil {
		t.Fatal("VerifyRecordSignature(empty keyID) = nil")
	}

	if err := VerifyRecordSignature(lic, signed, "", pub); !errors.Is(err, ErrUntrustedSideRecordKey) {
		t.Fatalf("VerifyRecordSignature(empty expected) = %v", err)
	}
	if err := VerifyRecordSignature(lic, signed, "other", pub); !errors.Is(err, ErrUntrustedSideRecordKey) {
		t.Fatalf("VerifyRecordSignature(keyID mismatch) = %v", err)
	}
	if err := VerifyRecordSignature(lic, signed, "kid", pub[:8]); !errors.Is(err, ErrUntrustedSideRecordKey) {
		t.Fatalf("VerifyRecordSignature(bad key size) = %v", err)
	}

	bad = signed
	bad.Signature.Sig = "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := VerifyRecordSignature(lic, bad, "kid", pub); err == nil {
		t.Fatal("VerifyRecordSignature(bad sig) = nil")
	}
}

func mustCaptureErr(t *testing.T, c PayloadCapture, k ed25519.PublicKey, exp captureExpectation) {
	t.Helper()
	if _, err := verifyPayloadCapture("s", c, k, exp); !errors.Is(err, ErrPayloadCapture) {
		t.Fatalf("verifyPayloadCapture = %v, want ErrPayloadCapture", err)
	}
}

func TestVerifyPayloadCaptureErrors(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good, err := SignPayloadCapture(PayloadCapture{ActionID: "a", ActionHash: goodHash, PayloadHash: goodHash, Direction: DirectionEgress, PartyIdentity: "agent-a", CounterpartyIdentity: "agent-b"}, "kid", priv)
	if err != nil {
		t.Fatalf("SignPayloadCapture: %v", err)
	}
	exp := captureExpectation{direction: DirectionEgress, actionID: "a", actionHash: goodHash, actor: "agent-a", counterpartyIdentity: "agent-b"}
	if _, err := verifyPayloadCapture("s", good, pub, exp); err != nil {
		t.Fatalf("verifyPayloadCapture(valid) = %v", err)
	}

	badType := good
	badType.RecordType = "other"
	mustCaptureErr(t, badType, pub, exp)

	dirWrong := exp
	dirWrong.direction = DirectionIngress
	mustCaptureErr(t, good, pub, dirWrong)
	aidWrong := exp
	aidWrong.actionID = "b"
	mustCaptureErr(t, good, pub, aidWrong)
	ahWrong := exp
	ahWrong.actionHash = PayloadHash([]byte("other action"))
	mustCaptureErr(t, good, pub, ahWrong)
	partyWrong := exp
	partyWrong.actor = "agent-x"
	mustCaptureErr(t, good, pub, partyWrong)
	cpWrong := exp
	cpWrong.counterpartyIdentity = "agent-c"
	mustCaptureErr(t, good, pub, cpWrong)

	badAlg := good
	badAlg.Signature.Alg = "rsa"
	mustCaptureErr(t, badAlg, pub, exp)

	if _, err := verifyPayloadCapture("s", good, pub[:8], exp); !errors.Is(err, ErrPayloadCapture) {
		t.Fatalf("bad key size = %v", err)
	}

	badSig := good
	badSig.Signature.Sig = "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	mustCaptureErr(t, badSig, pub, exp)

	badField := good
	badField.PayloadHash = "nope"
	mustCaptureErr(t, badField, pub, exp)
}

func TestValidateCaptureFieldsRejects(t *testing.T) {
	base := PayloadCapture{RecordType: PayloadCaptureRecordType, ActionID: "a", ActionHash: goodHash, PayloadHash: goodHash, Direction: DirectionEgress, PartyIdentity: "agent-a", CounterpartyIdentity: "agent-b"}
	for name, mut := range map[string]func(*PayloadCapture){
		"bad action":       func(c *PayloadCapture) { c.ActionID = "" },
		"bad action hash":  func(c *PayloadCapture) { c.ActionHash = "x" },
		"bad party":        func(c *PayloadCapture) { c.PartyIdentity = "a b" },
		"bad counterparty": func(c *PayloadCapture) { c.CounterpartyIdentity = "a b" },
		"bad hash":         func(c *PayloadCapture) { c.PayloadHash = "x" },
		"bad direction":    func(c *PayloadCapture) { c.Direction = "up" },
	} {
		t.Run(name, func(t *testing.T) {
			c := base
			mut(&c)
			if err := validateCaptureFields(c); !errors.Is(err, ErrPayloadCapture) {
				t.Fatalf("validateCaptureFields(%s) = %v", name, err)
			}
		})
	}
	if err := validateCaptureFields(base); err != nil {
		t.Fatalf("validateCaptureFields(valid) = %v", err)
	}
}

func TestRejectSideRecordKeyReuse(t *testing.T) {
	a, _, _ := ed25519.GenerateKey(rand.Reader)
	b, _, _ := ed25519.GenerateKey(rand.Reader)
	c, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := rejectSideRecordKeyReuse(c, a, b); err != nil {
		t.Fatalf("distinct keys = %v", err)
	}
	if err := rejectSideRecordKeyReuse(a, a, b); !errors.Is(err, ErrSideRecordKeyReuse) {
		t.Fatalf("reuse sender = %v", err)
	}
	if err := rejectSideRecordKeyReuse(b, a, b); !errors.Is(err, ErrSideRecordKeyReuse) {
		t.Fatalf("reuse receiver = %v", err)
	}
	if err := rejectSideRecordKeyReuse(c[:8], a, b); !errors.Is(err, ErrUntrustedSideRecordKey) {
		t.Fatalf("bad size = %v", err)
	}
}

func TestUnmarshalRecordErrors(t *testing.T) {
	for name, v := range map[string]string{
		"not json":      "not json",
		"not object":    "[1,2,3]",
		"trailing junk": `{"record_type":"counterparty_receipt_v1"} extra`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalRecord([]byte(v)); err == nil {
				t.Fatalf("UnmarshalRecord(%s) = nil", name)
			}
		})
	}
}
