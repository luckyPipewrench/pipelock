// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// A verified Agent Card signature is a 64-byte stamp the signer does not
// choose the spelling of. An occasional one contains a run that a credential
// rule reads as a token. These tests pin that such a card is not
// blocked for its own stamp, and that nothing else a peer controls gets the
// same pass.

const (
	// stampSeedIndex selects the Ed25519 key (seed = sha256 of the index as a
	// little-endian uint64) that signs stampedCard's fixed body to a signature
	// containing a Hugging Face shaped run. stampSeedIndexUnparseable does the
	// same for a card the typed Agent Card parser rejects. The fixtures assert
	// the collision, so a change to either card fails loudly instead of
	// silently turning every allow test vacuous.
	stampSeedIndex            = 2042
	stampSeedIndexUnparseable = 99844
)

// hfRule mirrors the shipped Hugging Face credential rule closely enough to
// prove the fixture collides with it. Detection itself is the scanner's.
var hfRule = regexp.MustCompile(`(?i)hf_[A-Za-z0-9]{34,37}\b`)

func stampKeyFor(t *testing.T, index uint64) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	var le [8]byte
	binary.LittleEndian.PutUint64(le[:], index)
	seed := sha256.Sum256(le[:])
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("ed25519 public key has unexpected type")
	}
	return pub, priv
}

// realToken builds a credential-shaped Hugging Face token at runtime.
func realToken() string {
	return "hf" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
}

// forgedSignature is a canonical-looking 64-byte signature spelling (86
// unpadded base64url characters) that carries token and verifies against no
// key. A peer can choose these bytes freely; the hyphen ends the token on a
// word boundary, as the credential rules require.
func forgedSignature(token string) string {
	return token + "-" + strings.Repeat("A", 85-len(token))
}

// stampedCard returns a card validly signed by a key trusted for testCardOrigin
// whose signature string matches the Hugging Face rule, plus that key and
// string.
func stampedCard(t *testing.T) (body []byte, pub ed25519.PublicKey, stamp string) {
	t.Helper()
	pub, priv := stampKeyFor(t, stampSeedIndex)
	body = signCard(t, baseCard(), priv, edHeader())
	stamp = signatureStrings(t, body)[0]
	assertStampCollides(t, body, stamp)
	return body, pub, stamp
}

func assertStampCollides(t *testing.T, body []byte, stamp string) {
	t.Helper()
	if !hfRule.MatchString(stamp) {
		t.Fatalf("fixture stamp %q no longer matches the Hugging Face rule", stamp)
	}
	var card map[string]any
	if err := json.Unmarshal(body, &card); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	sigs, _ := card["signatures"].([]any)
	entry, _ := sigs[0].(map[string]any)
	if protected, _ := entry["protected"].(string); hfRule.MatchString(protected) {
		t.Fatal("fixture collides in protected, not only in the signature")
	}
}

func signatureStrings(t *testing.T, body []byte) []string {
	t.Helper()
	var card struct {
		Signatures []struct {
			Signature string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(body, &card); err != nil {
		t.Fatalf("unmarshal signatures: %v", err)
	}
	out := make([]string, 0, len(card.Signatures))
	for _, s := range card.Signatures {
		out = append(out, s.Signature)
	}
	return out
}

// mutateSignatures rewrites the signatures array of a signed card. The array
// is outside the signed preimage, so the original signature still verifies.
func mutateSignatures(t *testing.T, body []byte, mutate func([]any) []any) []byte {
	t.Helper()
	var card map[string]any
	if err := json.Unmarshal(body, &card); err != nil {
		t.Fatalf("unmarshal card: %v", err)
	}
	sigs, _ := card["signatures"].([]any)
	card["signatures"] = mutate(sigs)
	out, err := json.Marshal(card)
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	return out
}

func cardScanCfg(pub ed25519.PublicKey, origins ...string) *config.A2AScanning {
	cfg := sigScanCfg(pub, false)
	cfg.ScanAgentCards = true
	if pub != nil && len(origins) > 0 {
		cfg.TrustedAgentCardKeys[0].AllowedOrigins = origins
	}
	return cfg
}

func scanCardHTTP(t *testing.T, body []byte, cfg *config.A2AScanning) AgentCardScanResult {
	t.Helper()
	key := CardCacheKeyFromRequest(testCardURL, "")
	return ScanAgentCard(context.Background(), body, testA2AScanner(t), nil, key, cfg)
}

func rpcResponse(card []byte) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"result":` + string(card) + `}`)
}

func scanCardMCP(t *testing.T, body []byte, cfg *config.A2AScanning) (clean bool, dlp int) {
	t.Helper()
	verdict := ScanResponseA2A(rpcResponse(body), testA2AScanner(t), &A2AResponseOpts{
		Cfg:     cfg,
		Method:  methodGetExtendedAgentCard,
		CardKey: CardCacheKeyFromRequest(testCardURL, ""),
	})
	if verdict.Error != "" {
		t.Fatalf("MCP scan errored instead of judging the card: %s", verdict.Error)
	}
	return verdict.Clean, len(verdict.DLPMatches)
}

func TestVerifiedSignatureStampIsNotCredentialScanned(t *testing.T) {
	body, pub, stamp := stampedCard(t)

	// Without the exemption this is the reported false positive: the same card,
	// with no trusted key configured, is blocked for its own stamp.
	t.Run("same card without a trusted key is blocked for the stamp", func(t *testing.T) {
		res := scanCardHTTP(t, body, cardScanCfg(nil))
		if res.Clean || len(res.Findings.DLPFindings) == 0 {
			t.Fatalf("control: stamped card must hit the credential rule without a trusted key, got clean=%v dlp=%d", res.Clean, len(res.Findings.DLPFindings))
		}
	})

	t.Run("HTTP card path", func(t *testing.T) {
		res := scanCardHTTP(t, body, cardScanCfg(pub))
		if !res.Clean || !res.SignatureVerified || len(res.Findings.DLPFindings) != 0 {
			t.Fatalf("verified stamp blocked: clean=%v verified=%v dlp=%+v reason=%q", res.Clean, res.SignatureVerified, res.Findings.DLPFindings, res.Reason)
		}
	})

	// The MCP path also merges a generic inbound scan of the whole line, which
	// runs whether or not card content scanning is on.
	for _, scanCards := range []bool{true, false} {
		name := "MCP response path scan_agent_cards=false"
		if scanCards {
			name = "MCP response path scan_agent_cards=true"
		}
		t.Run(name, func(t *testing.T) {
			cfg := cardScanCfg(pub)
			cfg.ScanAgentCards = scanCards
			if clean, dlp := scanCardMCP(t, body, cfg); !clean || dlp != 0 {
				t.Fatalf("verified stamp blocked on the MCP path: clean=%v dlp=%d", clean, dlp)
			}
		})
	}

	t.Run("verified entry that is not the first is the one exempted", func(t *testing.T) {
		later := mutateSignatures(t, body, func(sigs []any) []any {
			first := map[string]any{"protected": "e30", "signature": forgedSignature("AAAA")}
			return append([]any{first}, sigs...)
		})
		cfg := cardScanCfg(pub)
		if res := scanCardHTTP(t, later, cfg); !res.Clean || !res.SignatureVerified {
			t.Fatalf("HTTP: clean=%v verified=%v dlp=%+v", res.Clean, res.SignatureVerified, res.Findings.DLPFindings)
		}
		if clean, dlp := scanCardMCP(t, later, cfg); !clean || dlp != 0 {
			t.Fatalf("MCP: clean=%v dlp=%d", clean, dlp)
		}
	})

	t.Run("a stamp that drifts one character is not the verified string", func(t *testing.T) {
		// Same position, different value: verification fails, nothing is exempt.
		other := strings.Replace(string(body), stamp, stamp[:len(stamp)-1]+"A", 1)
		if other == string(body) {
			t.Skip("stamp already ends in the replacement character")
		}
		res := scanCardHTTP(t, []byte(other), cardScanCfg(pub))
		if res.Clean {
			t.Fatal("a tampered stamp must not verify")
		}
	})
}

func TestVerifiedSignatureUnparseableCardStampIsNotCredentialScanned(t *testing.T) {
	pub, priv := stampKeyFor(t, stampSeedIndexUnparseable)
	card := baseCard()
	card["skills"] = "not-an-array"
	body := signCard(t, card, priv, edHeader())
	stamp := signatureStrings(t, body)[0]
	assertStampCollides(t, body, stamp)

	res := scanCardHTTP(t, body, cardScanCfg(pub))
	if !res.SignatureVerified || len(res.Findings.DLPFindings) != 0 {
		t.Fatalf("unparseable but verified card: verified=%v dlp=%+v", res.SignatureVerified, res.Findings.DLPFindings)
	}
	if res.Reason != "a2a: unparseable Agent Card" {
		t.Fatalf("an unparseable card keeps its own verdict, got %q", res.Reason)
	}
	// And the control: without a key the stamp is scanned.
	if got := scanCardHTTP(t, body, cardScanCfg(nil)); len(got.Findings.DLPFindings) == 0 {
		t.Fatal("control: unverified unparseable card must still hit the credential rule")
	}
}

type dlpBlockCase struct {
	name  string
	build func(t *testing.T) (body []byte, cfg *config.A2AScanning)
}

func dlpBlockCases() []dlpBlockCase {
	return []dlpBlockCase{
		{
			name: "real token in description of a validly signed card",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				pub, priv := stampKeyFor(t, 1)
				card := baseCard()
				card["description"] = "use " + realToken() + " here"
				return signCard(t, card, priv, edHeader()), cardScanCfg(pub)
			},
		},
		{
			name: "real token in a second, unverified signature entry",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, _ := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					return append(sigs, map[string]any{"protected": "e30", "signature": forgedSignature(realToken())})
				}), cardScanCfg(pub)
			},
		},
		{
			name: "real token in an unverified entry that precedes the verified one",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, _ := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					first := map[string]any{"protected": "e30", "signature": forgedSignature(realToken())}
					return append([]any{first}, sigs...)
				}), cardScanCfg(pub)
			},
		},
		{
			name: "real token in the protected header kid",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				pub, priv := stampKeyFor(t, 1)
				hdr := map[string]any{"alg": "EdDSA", "kid": realToken()}
				return signCard(t, baseCard(), priv, hdr), cardScanCfg(pub)
			},
		},
		{
			name: "real token in an unknown protected header member",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				pub, priv := stampKeyFor(t, 1)
				hdr := map[string]any{"alg": "EdDSA", "kid": testKeyID, "note": realToken()}
				return signCard(t, baseCard(), priv, hdr), cardScanCfg(pub)
			},
		},
		{
			name: "real token in the unprotected header of the verified entry",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, _ := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					sigs[0].(map[string]any)["header"] = map[string]any{"note": realToken()}
					return sigs
				}), cardScanCfg(pub)
			},
		},
		{
			name: "forged signature carrying a token and no valid key",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				pub, priv := stampKeyFor(t, 1)
				body := signCard(t, baseCard(), priv, edHeader())
				return mutateSignatures(t, body, func(sigs []any) []any {
					sigs[0].(map[string]any)["signature"] = forgedSignature(realToken())
					return sigs
				}), cardScanCfg(pub)
			},
		},
		{
			name: "stamp but no trusted key configured",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, _, _ := stampedCard(t)
				return body, cardScanCfg(nil)
			},
		},
		{
			name: "stamp from a key trusted only for another origin",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, _ := stampedCard(t)
				return body, cardScanCfg(pub, "https://other.example.com")
			},
		},
		{
			name: "token in an entry beyond the signature cap",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, _ := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					for len(sigs) < maxCardSignatures {
						sigs = append(sigs, map[string]any{"protected": "e30", "signature": forgedSignature("AAAA")})
					}
					return append(sigs, map[string]any{"protected": "e30", "signature": forgedSignature(realToken())})
				}), cardScanCfg(pub)
			},
		},
		{
			name: "verified stamp characters copied into the unprotected header",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, stamp := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					sigs[0].(map[string]any)["header"] = map[string]any{"copy": stamp}
					return sigs
				}), cardScanCfg(pub)
			},
		},
		{
			name: "verified stamp repeated as a second signature entry",
			build: func(t *testing.T) ([]byte, *config.A2AScanning) {
				body, pub, stamp := stampedCard(t)
				return mutateSignatures(t, body, func(sigs []any) []any {
					return append(sigs, map[string]any{"protected": "e30", "signature": stamp})
				}), cardScanCfg(pub)
			},
		},
	}
}

func TestVerifiedSignatureExemptionFailsClosed(t *testing.T) {
	for _, tc := range dlpBlockCases() {
		t.Run(tc.name, func(t *testing.T) {
			body, cfg := tc.build(t)
			t.Run("HTTP card path", func(t *testing.T) {
				res := scanCardHTTP(t, body, cfg)
				if res.Clean || len(res.Findings.DLPFindings) == 0 {
					t.Fatalf("must block on a credential finding: clean=%v dlp=%+v reason=%q", res.Clean, res.Findings.DLPFindings, res.Reason)
				}
			})
			t.Run("MCP response path", func(t *testing.T) {
				clean, dlp := scanCardMCP(t, body, cfg)
				if clean || dlp == 0 {
					t.Fatalf("must block on a credential finding: clean=%v dlp=%d", clean, dlp)
				}
			})
		})
	}
}

func TestCardBodyWithoutVerifiedSignature(t *testing.T) {
	canonical := forgedSignature("AAAA")
	verified := func(index int, sig string) CardSignatureResult {
		return CardSignatureResult{Outcome: SigOutcomeVerified, SignatureIndex: index, Signature: sig}
	}
	entry := func(sig string) string { return `{"protected":"p","signature":"` + sig + `"}` }
	card := func(desc string, entries ...string) string {
		return `{"description":"` + desc + `","signatures":[` + strings.Join(entries, ",") + `]}`
	}

	cases := []struct {
		name   string
		doc    string
		prefix []string
		sig    CardSignatureResult
		want   string // empty means unchanged
	}{
		{
			name: "blanks only the signature, not the same characters elsewhere",
			doc:  card(canonical, entry(canonical)),
			sig:  verified(0, canonical),
			want: card(canonical, `{"protected":"p","signature":""}`),
		},
		{
			name: "blanks the verified entry, not an identical earlier one",
			doc:  card("d", entry(canonical), entry(canonical)),
			sig:  verified(1, canonical),
			want: card("d", entry(canonical), `{"protected":"p","signature":""}`),
		},
		{
			name:   "follows a JSON-RPC result prefix",
			doc:    `{"jsonrpc":"2.0","id":1,"result":` + card("d", entry(canonical)) + `}`,
			prefix: []string{"result"},
			sig:    verified(0, canonical),
			want:   `{"jsonrpc":"2.0","id":1,"result":` + card("d", `{"protected":"p","signature":""}`) + `}`,
		},
		{
			name: "tolerates whitespace and member order",
			doc:  "{\n \"signatures\" : [ { \"signature\" :\n \"" + canonical + "\" , \"protected\":\"p\"} ] ,\"description\":\"d\"}",
			sig:  verified(0, canonical),
			want: "{\n \"signatures\" : [ { \"signature\" :\n \"\" , \"protected\":\"p\"} ] ,\"description\":\"d\"}",
		},
		{
			name: "matches an escaped spelling of the verified string",
			doc:  card("d", `{"protected":"p","signature":"`+fmt.Sprintf(`\u%04x`, canonical[0])+canonical[1:]+`"}`),
			sig:  verified(0, canonical),
			want: card("d", `{"protected":"p","signature":""}`),
		},
		{name: "not verified", doc: card("d", entry(canonical)), sig: CardSignatureResult{Outcome: SigOutcomeFailed, Signature: canonical}},
		{name: "unsigned outcome", doc: card("d", entry(canonical)), sig: CardSignatureResult{Outcome: SigOutcomeUnsigned, Signature: canonical}},
		{name: "negative index", doc: card("d", entry(canonical)), sig: verified(-1, canonical)},
		{name: "index past the array", doc: card("d", entry(canonical)), sig: verified(1, canonical)},
		{name: "value at the index differs", doc: card("d", entry(forgedSignature("BBBB"))), sig: verified(0, canonical)},
		{name: "repeated signatures member", doc: `{"signatures":[` + entry(canonical) + `],"signatures":[]}`, sig: verified(0, canonical)},
		{name: "repeated signature member", doc: `{"signatures":[{"signature":"` + canonical + `","signature":"x"}]}`, sig: verified(0, canonical)},
		{name: "repeated signatures member with the same entry", doc: `{"signatures":[` + entry(canonical) + `],"signatures":[` + entry(canonical) + `]}`, sig: verified(0, canonical)},
		{name: "repeated signature member with the same value", doc: `{"signatures":[{"signature":"` + canonical + `","signature":"` + canonical + `"}]}`, sig: verified(0, canonical)},
		{name: "repeated prefix member with the same card", doc: `{"result":` + card("d", entry(canonical)) + `,"result":` + card("d", entry(canonical)) + `}`, prefix: []string{"result"}, sig: verified(0, canonical)},
		{name: "signature is not a string", doc: `{"signatures":[{"signature":7}]}`, sig: verified(0, canonical)},
		{name: "signatures is not an array", doc: `{"signatures":{"signature":"` + canonical + `"}}`, sig: verified(0, canonical)},
		{name: "entry is not an object", doc: `{"signatures":["` + canonical + `"]}`, sig: verified(0, canonical)},
		{name: "missing prefix", doc: card("d", entry(canonical)), prefix: []string{"result"}, sig: verified(0, canonical)},
		{name: "escaped quote inside the literal", doc: `{"signatures":[{"signature":"AAAA\"BBBB"}]}`, sig: verified(0, canonical)},
		{name: "escaped backslash and quote inside the literal", doc: `{"signatures":[{"signature":"AA\\\"BB"}]}`, sig: verified(0, canonical)},
		{name: "truncated before the signatures value", doc: `{"signatures":`, sig: verified(0, canonical)},
		{name: "non-string object key", doc: `{"signatures":[{1:2}]}`, sig: verified(0, canonical)},
		{name: "missing colon in a sibling member", doc: `{"signatures":[{"a" 1}]}`, sig: verified(0, canonical)},
		{name: "trailing comma in the entry", doc: `{"signatures":[{"signature":"` + canonical + `",}]}`, sig: verified(0, canonical)},
		{name: "malformed JSON", doc: `{"signatures":[{"signature":"` + canonical, sig: verified(0, canonical)},
		{name: "not JSON", doc: `nope`, sig: verified(0, canonical)},
		{name: "too deeply nested", doc: strings.Repeat(`{"signatures":`, maxJSONNesting+2) + `[]` + strings.Repeat(`}`, maxJSONNesting+2), sig: verified(0, canonical)},
		// The exemption is only for the canonical spelling of exactly 64 bytes.
		{name: "short signature", doc: card("d", entry(canonical[:85])), sig: verified(0, canonical[:85])},
		{name: "long signature", doc: card("d", entry(canonical+"A")), sig: verified(0, canonical+"A")},
		{name: "padded signature", doc: card("d", entry(canonical+"==")), sig: verified(0, canonical+"==")},
		{name: "non-canonical trailing bits", doc: card("d", entry(canonical[:85]+"B")), sig: verified(0, canonical[:85]+"B")},
		{name: "embedded line break", doc: card("d", entry(canonical[:40]+`\n`+canonical[40:])), sig: verified(0, canonical[:40]+"\n"+canonical[40:])},
		{name: "standard base64 alphabet", doc: card("d", entry(canonical[:10]+"+/"+canonical[12:])), sig: verified(0, canonical[:10]+"+/"+canonical[12:])},
		{name: "empty signature", doc: card("d", entry("")), sig: verified(0, "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := cardBodyWithoutVerifiedSignature([]byte(tc.doc), tc.prefix, tc.sig)
			want := tc.want
			if want == "" {
				want = tc.doc
			}
			if !bytes.Equal(got, []byte(want)) {
				t.Fatalf("got  %s\nwant %s", got, want)
			}
		})
	}
}

func TestVerifyAgentCardSignaturesNamesTheVerifiedEntry(t *testing.T) {
	body, pub, stamp := stampedCard(t)
	cfg := cardScanCfg(pub)

	got := VerifyAgentCardSignatures(body, testCardOrigin, cfg)
	if got.Outcome != SigOutcomeVerified || got.SignatureIndex != 0 || got.Signature != stamp {
		t.Fatalf("verified entry = %+v, want index 0 and the stamp", got)
	}

	// The verified entry is the one that verified, wherever it sits.
	moved := mutateSignatures(t, body, func(sigs []any) []any {
		first := map[string]any{"protected": "e30", "signature": forgedSignature("AAAA")}
		return append([]any{first}, sigs...)
	})
	got = VerifyAgentCardSignatures(moved, testCardOrigin, cfg)
	if got.Outcome != SigOutcomeVerified || got.SignatureIndex != 1 || got.Signature != stamp {
		t.Fatalf("verified entry = %+v, want index 1 and the stamp", got)
	}

	failed := VerifyAgentCardSignatures(body, "https://other.example.com", cfg)
	if failed.Outcome != SigOutcomeFailed || failed.Signature != "" {
		t.Fatalf("failed verification must name no entry: %+v", failed)
	}
}

func TestLineWithoutVerifiedCardSignature(t *testing.T) {
	body, pub, stamp := stampedCard(t)
	opts := &A2AResponseOpts{Cfg: cardScanCfg(pub), CardKey: CardCacheKeyFromRequest(testCardURL, "")}

	t.Run("blanks the stamp in a result", func(t *testing.T) {
		line := rpcResponse(body)
		got := lineWithoutVerifiedCardSignature(line, opts)
		if bytes.Contains(got, []byte(stamp)) || !bytes.Contains(got, []byte(`"signature":""`)) {
			t.Fatalf("stamp not blanked: %s", got)
		}
	})

	same := map[string][]byte{
		"error response": []byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"},"result":` + string(body) + `}`),
		"null result":    []byte(`{"jsonrpc":"2.0","id":1,"result":null}`),
		"no result":      []byte(`{"jsonrpc":"2.0","id":1}`),
		"invalid JSON":   []byte(`{"jsonrpc":`),
	}
	for name, line := range same {
		t.Run(name+" is left whole", func(t *testing.T) {
			if got := lineWithoutVerifiedCardSignature(line, opts); !bytes.Equal(got, line) {
				t.Fatalf("line changed: %s", got)
			}
		})
	}

	t.Run("verification inactive leaves the line whole", func(t *testing.T) {
		line := rpcResponse(body)
		inactive := &A2AResponseOpts{Cfg: cardScanCfg(nil), CardKey: opts.CardKey}
		if got := lineWithoutVerifiedCardSignature(line, inactive); !bytes.Equal(got, line) {
			t.Fatal("no trusted key must exempt nothing")
		}
	})

	t.Run("no origin leaves the line whole", func(t *testing.T) {
		line := rpcResponse(body)
		noOrigin := &A2AResponseOpts{Cfg: opts.Cfg}
		if got := lineWithoutVerifiedCardSignature(line, noOrigin); !bytes.Equal(got, line) {
			t.Fatal("an unknown origin verifies nothing and must exempt nothing")
		}
	})
}

func escapeJSONString(s string) string {
	var b strings.Builder
	for _, c := range s {
		_, _ = fmt.Fprintf(&b, `\u%04x`, c)
	}
	return b.String()
}

// JSON escapes in the signature value or the member names do not move the
// exemption off the verified entry, and an escaped copy elsewhere still blocks.
func TestVerifiedSignatureEscapedSpellings(t *testing.T) {
	body, pub, stamp := stampedCard(t)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", " \t"); err != nil {
		t.Fatal(err)
	}
	variants := map[string][]byte{
		"one escaped character":   []byte(strings.Replace(string(body), stamp, fmt.Sprintf(`\u%04x`, stamp[0])+stamp[1:], 1)),
		"every character escaped": []byte(strings.Replace(string(body), stamp, escapeJSONString(stamp), 1)),
		"escaped signature key":   []byte(strings.Replace(string(body), `"signature":`, `"signature":`, 1)),
		"escaped signatures key":  []byte(strings.Replace(string(body), `"signatures":`, `"signatures":`, 1)),
		"indented":                pretty.Bytes(),
	}
	for name, b := range variants {
		t.Run(name, func(t *testing.T) {
			cfg := cardScanCfg(pub)
			sig := VerifyAgentCardSignatures(b, testCardOrigin, cfg)
			if sig.Outcome != SigOutcomeVerified {
				t.Fatalf("fixture did not verify: %+v", sig)
			}
			var want, got map[string]any
			if err := json.Unmarshal(b, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(cardBodyWithoutVerifiedSignature(b, nil, sig), &got); err != nil {
				t.Fatal(err)
			}
			want["signatures"].([]any)[0].(map[string]any)["signature"] = ""
			wantJSON, _ := json.Marshal(want)
			gotJSON, _ := json.Marshal(got)
			if !bytes.Equal(wantJSON, gotJSON) {
				t.Fatalf("blanked the wrong span:\n got %s\nwant %s", gotJSON, wantJSON)
			}
			if h := scanCardHTTP(t, b, cfg); !h.Clean || !h.SignatureVerified {
				t.Fatalf("HTTP blocked a verified escaped card: %+v", h)
			}
			if clean, dlp := scanCardMCP(t, b, cfg); !clean || dlp != 0 {
				t.Fatalf("MCP blocked a verified escaped card: clean=%v dlp=%d", clean, dlp)
			}
			copied := bytes.Replace(b, []byte(`"protected":`), []byte(`"header":{"copy":"`+escapeJSONString(stamp)+`"},"protected":`), 1)
			if h := scanCardHTTP(t, copied, cfg); h.Clean || len(h.Findings.DLPFindings) == 0 {
				t.Fatalf("HTTP missed an escaped copy of the stamp: %+v", h)
			}
			if clean, dlp := scanCardMCP(t, copied, cfg); clean || dlp == 0 {
				t.Fatalf("MCP missed an escaped copy of the stamp: clean=%v dlp=%d", clean, dlp)
			}
		})
	}
}

// Blanking the verified signature shortens the line, so the size bound must
// read the bytes received: one byte over the limit is refused, not scanned.
func TestVerifiedSignatureDoesNotShrinkUnderSizeLimit(t *testing.T) {
	body, pub, _ := stampedCard(t)
	line := rpcResponse(body)
	line = append(line, bytes.Repeat([]byte(" "), transport.MaxLineSize+1-len(line))...)
	opts := &A2AResponseOpts{Cfg: cardScanCfg(pub), Method: methodGetExtendedAgentCard, CardKey: CardCacheKeyFromRequest(testCardURL, "")}
	if n := len(lineWithoutVerifiedCardSignature(line, opts)); n > transport.MaxLineSize {
		t.Fatalf("fixture: blanked line %d bytes is not under the limit", n)
	}
	v := ScanResponseA2A(line, testA2AScanner(t), opts)
	if v.Clean || v.Error == "" {
		t.Fatalf("oversized card response was scanned: clean=%v error=%q", v.Clean, v.Error)
	}
}
