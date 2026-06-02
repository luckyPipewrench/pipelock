// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package aarp

import (
	"crypto/ed25519"
	"errors"
	"strconv"
	"testing"
)

// buildChain returns n envelopes forming a valid issuer stream starting at
// genesis (seq 0), each signed and each link's prior_hash bound to the previous
// envelope's payload digest, plus the public key they were signed with.
func buildChain(t *testing.T, n int) ([]Envelope, ed25519.PublicKey) {
	t.Helper()
	pub, priv := genKey(t)
	signer, err := NewEd25519Signer(testKeyID, "issuer", priv)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	stream := make([]Envelope, 0, n)
	prior := GenesisPriorHash
	for i := 0; i < n; i++ {
		e := baseEnvelope()
		e.Chain = &ChainLink{
			IssuerID:  "issuer-1",
			Seq:       strconv.Itoa(i),
			PriorHash: prior,
		}
		signed, err := Sign(e, signer)
		if err != nil {
			t.Fatalf("Sign link %d: %v", i, err)
		}
		stream = append(stream, signed)
		digest, err := signed.PayloadDigest()
		if err != nil {
			t.Fatalf("PayloadDigest link %d: %v", i, err)
		}
		prior = digest
	}
	return stream, pub
}

func TestVerifyChain_Valid(t *testing.T) {
	stream, _ := buildChain(t, 4)
	if err := VerifyChain(stream); err != nil {
		t.Fatalf("VerifyChain(valid) = %v, want nil", err)
	}
}

func TestVerifyChain_Segment(t *testing.T) {
	// A contiguous segment that starts mid-stream is allowed (chain_scope:segment).
	stream, _ := buildChain(t, 4)
	if err := VerifyChain(stream[1:]); err != nil {
		t.Fatalf("VerifyChain(segment) = %v, want nil", err)
	}
}

func TestVerifyChain_ReorderDetected(t *testing.T) {
	stream, _ := buildChain(t, 4)
	stream[1], stream[2] = stream[2], stream[1]
	if err := VerifyChain(stream); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(reordered) = %v, want ErrChainBroken", err)
	}
}

func TestVerifyChain_PriorHashTamperDetected(t *testing.T) {
	stream, _ := buildChain(t, 3)
	stream[2].Chain.PriorHash = digest64(7)
	if err := VerifyChain(stream); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(tampered prior_hash) = %v, want ErrChainBroken", err)
	}
}

func TestVerifyChain_GapDetected(t *testing.T) {
	stream, _ := buildChain(t, 3)
	// Drop the middle element: seq jumps 0 -> 2, prior_hash no longer matches.
	gapped := []Envelope{stream[0], stream[2]}
	if err := VerifyChain(gapped); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(gap) = %v, want ErrChainBroken", err)
	}
}

func TestVerifyChain_MixedIssuerDetected(t *testing.T) {
	stream, _ := buildChain(t, 2)
	stream[1].Chain.IssuerID = "issuer-2"
	if err := VerifyChain(stream); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(mixed issuer) = %v, want ErrChainBroken", err)
	}
}

func TestVerifyChain_Empty(t *testing.T) {
	if err := VerifyChain(nil); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(nil) = %v, want ErrChainBroken", err)
	}
}

func TestVerifyChain_MissingLink(t *testing.T) {
	stream, _ := buildChain(t, 2)
	stream[1].Chain = nil
	if err := VerifyChain(stream); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("VerifyChain(missing link) = %v, want ErrChainBroken", err)
	}
}

func TestChainLink_Validate(t *testing.T) {
	cases := []struct {
		name string
		link ChainLink
		ok   bool
	}{
		{"genesis", ChainLink{IssuerID: "i", Seq: "0", PriorHash: GenesisPriorHash}, true},
		{"normal", ChainLink{IssuerID: "i", Seq: "5", PriorHash: digest64(1)}, true},
		{"empty_issuer", ChainLink{IssuerID: "", Seq: "0", PriorHash: GenesisPriorHash}, false},
		{"bad_seq", ChainLink{IssuerID: "i", Seq: "-1", PriorHash: digest64(1)}, false},
		{"bad_prior_hash", ChainLink{IssuerID: "i", Seq: "1", PriorHash: "short"}, false},
		{"genesis_nonzero_prior", ChainLink{IssuerID: "i", Seq: "0", PriorHash: digest64(1)}, false},
		{"nongenesis_zero_prior", ChainLink{IssuerID: "i", Seq: "1", PriorHash: GenesisPriorHash}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.link.validate()
			if tc.ok && err != nil {
				t.Fatalf("validate(%+v) = %v, want nil", tc.link, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("validate(%+v) = nil, want error", tc.link)
			}
		})
	}
}

func TestVerifyChain_BindsIntoSignature(t *testing.T) {
	// A chained envelope's link is part of the signed payload: tampering the seq
	// after signing must break the signature, proving backdating is not just
	// linkage-detectable but signature-detectable.
	stream, pub := buildChain(t, 2)
	env := stream[1]
	// Tamper the signed chain seq.
	env.Chain.Seq = "99"
	ap, err := Verify(env, VerifyOptions{TrustedKeys: map[string]ed25519.PublicKey{testKeyID: pub}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ap.AssertionSigned {
		t.Fatal("AssertionSigned = true after tampering signed chain seq")
	}
}
