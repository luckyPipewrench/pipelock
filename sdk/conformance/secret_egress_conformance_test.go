// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract/egress"
	"github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

var updateSecretEgress = flag.Bool("update-secret-egress", false, "regenerate benign signed secret-egress-v1 fixtures")

const secretEgressCorpusDir = "testdata/secret-egress-v1"

const secretEgressPolicyHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type secretEgressCorpusCase struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type secretEgressCorpusManifest struct {
	Version           int                      `json:"version"`
	Status            string                   `json:"status"`
	PublicKeyHex      string                   `json:"public_key_hex"`
	TestKeyDerivation string                   `json:"test_key_derivation"`
	RegistryHash      string                   `json:"registry_hash"`
	RegistryManifest  string                   `json:"registry_manifest"`
	Cases             []secretEgressCorpusCase `json:"cases"`
}

// This additive corpus records structural facts only. All identities and keys
// are deterministic public test material, no transports or emitters run, and
// no case grants permission to forward or proves production coverage.
func TestSecretEgressSignedCorpus(t *testing.T) {
	manifest, files := makeSecretEgressCorpus(t)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = append(manifestBytes, '\n')
	if *updateSecretEgress {
		if err := os.MkdirAll(secretEgressCorpusDir, 0o750); err != nil {
			t.Fatal(err)
		}
		for name, raw := range files {
			if err := os.WriteFile(filepath.Join(secretEgressCorpusDir, name), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Clean(filepath.Join(secretEgressCorpusDir, name)))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("fixture %s drifted or unavailable: %v; regenerate with -update-secret-egress", name, err)
		}
	}
	pub, err := hex.DecodeString(manifest.PublicKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			raw := files[c.File]
			r, err := receipt.ParseEvidenceReceipt(raw)
			if err == nil {
				err = receipt.VerifyWithKey(r, pub, manifest.PublicKeyHex)
			}
			if (err == nil) != c.Valid {
				t.Fatalf("VerifyWithKey = %v, valid=%v (%s)", err, c.Valid, c.Reason)
			}
			if err := receipt.VerifyV2BytesWithKey(raw, pub, manifest.PublicKeyHex); (err == nil) != c.Valid {
				t.Fatalf("VerifyV2BytesWithKey = %v, valid=%v (%s)", err, c.Valid, c.Reason)
			}
		})
	}
}

func makeSecretEgressCorpus(t *testing.T) (secretEgressCorpusManifest, map[string][]byte) {
	t.Helper()
	seed := sha256.Sum256([]byte("pipelock secret-egress-v1 conformance test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	manifest := secretEgressCorpusManifest{
		Version: 1, Status: "fixture_only", PublicKeyHex: hex.EncodeToString(pub),
		TestKeyDerivation: "Ed25519 seed = SHA-256(UTF-8(pipelock secret-egress-v1 conformance test key)); TEST ONLY",
		RegistryManifest:  "registry-manifest.json",
	}
	files := make(map[string][]byte)
	names := []string{"intent-block", "outcome-mismatch", "local-mcp", "raw-unrewritable-intent", "raw-unrewritable-outcome", "blocked-fallback-intent", "blocked-fallback-outcome", "builtin-core-authorization", "redacted-network-intent", "redacted-network-outcome", "redacted-local-intent", "redacted-local-outcome"}
	decisions := make([]egressevidence.Decision, 0, len(names)+2)
	siteMap := make(map[egressevidence.SiteID]egressevidence.Site)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Clean(filepath.Join("../../internal/egressevidence/testdata/decision-v1", name+".json")))
		if err != nil {
			t.Fatal(err)
		}
		d, err := egressevidence.ParseDecision(raw)
		if err != nil {
			t.Fatal(err)
		}
		decisions = append(decisions, d)
		siteMap[d.SiteID] = egressevidence.Site{ID: d.SiteID, Plane: d.Plane, Transport: d.Transport, Location: d.Location, View: d.View, Boundary: d.Boundary}
	}
	// These carrier literals come from the proxy constructors, independently of
	// the candidate enum. Fixtures assert wire vocabulary, not live coverage.
	for _, carrier := range []string{"mcp_http_upstream", "mcp_ws", "mcp_http_listener"} {
		d := decisions[0]
		d.SiteID = egressevidence.SiteID("fixture." + carrier + ".tool.original")
		d.Transport, d.Location, d.Boundary = egressevidence.Transport(carrier), egressevidence.LocationToolArguments, egressevidence.BoundaryToolDispatch
		names, decisions = append(names, carrier), append(decisions, d)
		siteMap[d.SiteID] = egressevidence.Site{ID: d.SiteID, Plane: d.Plane, Transport: d.Transport, Location: d.Location, View: d.View, Boundary: d.Boundary}
	}
	for i, host := range []string{"192.0.2.1", "2001:db8::1", "123.api.vendor.example", "0x.api.vendor.example", "api.vendor.0xnothex"} {
		d := decisions[0]
		d.DestinationRef = host
		names, decisions = append(names, fmt.Sprintf("canonical-destination-%d", i)), append(decisions, d)
	}
	transformed := decisions[0]
	transformed.FindingDisposition = egressevidence.FindingRedact
	transformed.PlannedByteForm = egressevidence.ByteFormTransformed
	names = append(names, "transformed-intent", "transformed-outcome")
	decisions = append(decisions, transformed)
	transformed.Phase = egressevidence.PhaseOutcome
	transformed.Outcome = &egressevidence.Outcome{Release: egressevidence.ReleaseComplete, ByteForm: egressevidence.ByteFormTransformed}
	decisions = append(decisions, transformed)
	sites := make([]egressevidence.Site, 0, len(siteMap))
	for _, site := range siteMap {
		sites = append(sites, site)
	}
	registry, err := egressevidence.NewRegistry(sites)
	if err != nil {
		t.Fatal(err)
	}
	manifest.RegistryHash, err = egress.RegistryHash(registry)
	if err != nil {
		t.Fatal(err)
	}
	files[manifest.RegistryManifest], err = egress.RegistryManifest(registry)
	if err != nil {
		t.Fatal(err)
	}
	add := func(name string, raw []byte, valid bool, reason string) {
		filename := name + ".json"
		files[filename] = raw
		manifest.Cases = append(manifest.Cases, secretEgressCorpusCase{Name: name, File: filename, Valid: valid, Reason: reason})
	}
	var base receipt.EvidenceReceipt
	for i, decision := range decisions {
		r, err := contractruntime.BuildSecretEgressDecisionReceipt(contractruntime.SecretEgressDecisionInput{
			Decision: decision, Registry: registry, PolicyHash: secretEgressPolicyHash,
			EventID:   fmt.Sprintf("01990000-0000-7000-8000-%012x", 0x100+i),
			Timestamp: time.Date(2026, 9, 30, 12, 0, i, 0, time.UTC),
			Principal: "fixture-principal", Actor: "fixture-builder", ChainPrevHash: receipt.GenesisHash,
		})
		if err != nil {
			t.Fatal(err)
		}
		raw := signSecretEgressFixture(t, &r, priv)
		add("valid-"+names[i], raw, true, "Typed recorded facts; no coverage, authority-resolution or durability claim")
		if i == 0 {
			base = r
		}
	}
	// An offline verifier intentionally cannot resolve a registry commitment.
	unbound := base
	unbound.Payload = bytes.Replace(unbound.Payload, []byte(manifest.RegistryHash), []byte("sha256:"+strings.Repeat("b", 64)), 1)
	add("valid-unbound-registry-hash", signSecretEgressFixture(t, &unbound, priv), true, "Offline verification checks digest grammar, not registry binding")
	addSecretEgressRejects(t, base, priv, add)
	addSecretEgressWireCases(t, base, priv, add)
	addSecretEgressDestinationCases(t, base, priv, add)
	return manifest, files
}

func signSecretEgressFixture(t *testing.T, r *receipt.EvidenceReceipt, priv ed25519.PrivateKey) []byte {
	t.Helper()
	preimage, err := r.SignablePreimage()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = receipt.SignatureProof{
		SignerKeyID: receipt.SignerKeyID(priv.Public().(ed25519.PublicKey)), KeyPurpose: "receipt-signing",
		Algorithm: "ed25519", Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(priv, preimage)),
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func addSecretEgressRejects(t *testing.T, base receipt.EvidenceReceipt, priv ed25519.PrivateKey, add func(string, []byte, bool, string)) {
	t.Helper()
	// These negative shape cases are re-signed where representable by the
	// existing signing profile, so a signature failure cannot mask a missing
	// field, enum, null or critical-feature validation regression.
	cases := []struct {
		name   string
		mutate func(*receipt.EvidenceReceipt)
	}{
		{"missing-chain-prev-hash", func(r *receipt.EvidenceReceipt) { r.ChainPrevHash = "" }},
		{"missing-policy", func(r *receipt.EvidenceReceipt) { r.PolicyHash = "" }},
		{"uppercase-policy", func(r *receipt.EvidenceReceipt) { r.PolicyHash = strings.ToUpper(secretEgressPolicyHash) }},
		{"missing-critical-feature", func(r *receipt.EvidenceReceipt) { r.Crit = []string{receipt.CritCanonicalization} }},
		{"duplicate-critical-feature", func(r *receipt.EvidenceReceipt) { r.Crit = append(r.Crit, receipt.CritSecretEgressDecisionV1) }},
		{"unknown-critical-feature", func(r *receipt.EvidenceReceipt) { r.Crit = append(r.Crit, "unknown_feature") }},
		{"unexpected-source-spans", func(r *receipt.EvidenceReceipt) { r.Crit = append(r.Crit, receipt.CritSourceSpans) }},
		{"critical-feature-old-kind", func(r *receipt.EvidenceReceipt) {
			r.PayloadKind = receipt.PayloadProxyDecision
			r.Payload = json.RawMessage(`{"action_type":"http_request","target":"api.vendor.example","verdict":"block","transport":"forward","policy_sources":["scanner"],"winning_source":"scanner"}`)
		}},
		{"event-action-alias", func(r *receipt.EvidenceReceipt) { r.EventID = "01990000-0000-7000-8000-000000000001" }},
		{"event-decision-alias", func(r *receipt.EvidenceReceipt) { r.EventID = "01990000-0000-7000-8000-000000000002" }},
		{"null-payload", func(r *receipt.EvidenceReceipt) { r.Payload = json.RawMessage(`null`) }},
	}
	for _, c := range cases {
		r := base
		r.Crit = append([]string(nil), base.Crit...)
		c.mutate(&r)
		add("invalid-"+c.name, signSecretEgressFixture(t, &r, priv), false, "Signed envelope or feature shape must reject")
	}
	payloadCases := []struct{ name, old, replacement string }{
		{"missing-registry", `"registry_hash":"` + registryHashFromFixture(t, base) + `",`, ``},
		{"uppercase-registry", registryHashFromFixture(t, base), strings.ToUpper(registryHashFromFixture(t, base))},
		{"null-registry", `"registry_hash":"` + registryHashFromFixture(t, base) + `"`, `"registry_hash":null`},
		{"case-registry", `"registry_hash":`, `"Registry_Hash":`},
		{"case-decision", `"decision":`, `"Decision":`},
		{"unknown-wrapper", `"decision":`, `"unknown":true,"decision":`},
		{"null-decision", string(base.Payload[strings.Index(string(base.Payload), `"decision":`)+11 : len(base.Payload)-1]), `null`},
		{"unknown-decision", `"version":1`, `"version":1,"unknown":true`},
		{"case-decision-field", `"action_id":`, `"Action_ID":`},
		{"missing-decision-version", `"version":1,`, ``},
		{"unsupported-decision-version", `"version":1`, `"version":2`},
		{"null-action-id", `"action_id":"01990000-0000-7000-8000-000000000001"`, `"action_id":null`},
		{"null-authorization", `"authorization":{"kind":"none"}`, `"authorization":null`},
		{"unknown-authorization", `"authorization":{"kind":"none"}`, `"authorization":{"kind":"none","unknown":true}`},
		{"case-authorization", `"authorization":{"kind":"none"}`, `"authorization":{"Kind":"none"}`},
		{"null-authorization-kind", `"authorization":{"kind":"none"}`, `"authorization":{"kind":null}`},
		{"none-authorization-ref", `"authorization":{"kind":"none"}`, `"authorization":{"kind":"none","ref":""}`},
		{"null-outcome", `"persistence_policy":`, `"outcome":null,"persistence_policy":`},
		{"null-fallback", `"persistence_policy":`, `"rewrite_fallback":null,"persistence_policy":`},
		{"unknown-fallback", `"persistence_policy":`, `"rewrite_fallback":{"reason":"unparseable_body","policy_ref":"builtin.block_residual","policy_origin":"builtin","unknown":true},"persistence_policy":`},
		{"invalid-phase", `"phase":"intent"`, `"phase":"unknown"`},
		{"action-decision-alias", `"decision_id":"01990000-0000-7000-8000-000000000002"`, `"decision_id":"01990000-0000-7000-8000-000000000001"`},
	}
	for _, c := range payloadCases {
		r := base
		r.Payload = replaceSecretEgress(t, base.Payload, c.old, c.replacement)
		add("invalid-"+c.name, signSecretEgressFixture(t, &r, priv), false, "Signed payload shape must reject")
	}
	for i, host := range []string{"0xc0000201", "3221225985", "0300.0.2.1", "192.513", "192.0.513", "::ffff:192.0.2.1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1%example", "[2001:db8::1]", "192.0.2.1.", " 192.0.2.1", "192.0.2.999", "999.0.2.1", "192.0.2.1.1", "192.0.2.09", "4294967296", "0x100000000", "0x", "api.vendor.123", "api.vendor.0x", "api.vendor.0xff"} {
		r := base
		r.Payload = replaceSecretEgress(t, base.Payload, `"destination_ref":"api.vendor.example"`, `"destination_ref":"`+host+`"`)
		add(fmt.Sprintf("invalid-canonical-destination-%d", i), signSecretEgressFixture(t, &r, priv), false, "Destination identity must use a canonical host spelling")
	}
	for _, carrier := range []string{"mcp_stdio", "mcp_http", "mcp_websocket"} {
		r := base
		r.Payload = replaceSecretEgress(t, base.Payload, `"transport":"forward"`, `"transport":"`+carrier+`"`)
		add("invalid-network-"+carrier, signSecretEgressFixture(t, &r, priv), false, "Network destination must use a supported network carrier")
	}
	for _, carrier := range []string{"mcp_http_upstream", "mcp_ws", "mcp_http_listener"} {
		r := base
		r.Payload = replaceSecretEgress(t, base.Payload, `"transport":"forward"`, `"transport":"`+carrier+`"`)
		r.Payload = replaceSecretEgress(t, r.Payload, `"destination_kind":"network"`, `"destination_kind":"local_process"`)
		add("invalid-local-"+carrier, signSecretEgressFixture(t, &r, priv), false, "Remote MCP carrier cannot name a local-process destination")
	}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	// Lexical/duplicate tests preserve the original signature. Whitespace does
	// not change the JCS preimage; floats and duplicates are outside its grammar.
	for _, c := range []struct{ name, old, replacement string }{
		{"decimal-version", `"version":1`, `"version":1.0`},
		{"exponent-version", `"version":1`, `"version":1e0`},
		{"duplicate-registry", `"registry_hash":`, `"registry_hash":"sha256:` + strings.Repeat("b", 64) + `","registry_hash":`},
		{"duplicate-decision-field", `"version":1`, `"version":1,"version":1`},
		{"oversized-raw-decision", `"decision":{`, `"decision":{` + strings.Repeat(" ", 16*1024)},
		{"wrong-key-purpose", `"key_purpose":"receipt-signing"`, `"key_purpose":"contract-activation-signing"`},
		{"changed-policy", secretEgressPolicyHash, "sha256:" + strings.Repeat("c", 64)},
		{"changed-registry", registryHashFromFixture(t, base), "sha256:" + strings.Repeat("d", 64)},
		{"changed-view", `"view":"original"`, `"view":"normalized"`},
		{"wrong-signature", base.Signature.Signature, "ed25519:" + strings.Repeat("0", 128)},
	} {
		add("invalid-"+c.name, replaceSecretEgress(t, raw, c.old, c.replacement), false, "Raw lexical, signed metadata or signature mismatch must reject")
	}
}

func registryHashFromFixture(t *testing.T, r receipt.EvidenceReceipt) string {
	t.Helper()
	var payload receipt.PayloadSecretEgressDecisionV1Struct
	if err := json.Unmarshal(r.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.RegistryHash
}

func replaceSecretEgress(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if old == "" || !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("fixture replacement absent: %q", old)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}
