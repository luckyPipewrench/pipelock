// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package emit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

type fixtureSigner struct {
	keyID string
	priv  ed25519.PrivateKey
}

func (f fixtureSigner) KeyID() string { return f.keyID }

func (f fixtureSigner) Sign(message []byte) ([]byte, error) {
	return ed25519.Sign(f.priv, message), nil
}

func testSigner() (fixtureSigner, ed25519.PublicKey) {
	seed := sha256.Sum256([]byte("emit fixture signer"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	return fixtureSigner{keyID: "compile-test-key", priv: priv}, priv.Public().(ed25519.PublicKey)
}

func baseContract() contract.Contract {
	at := time.Date(2026, 4, 29, 20, 0, 0, 0, time.UTC)
	return contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector: contract.Selector{
			Agent:      "agent-a",
			SelectorID: "sha256:selector",
		},
		ObservationWindow: contract.ObservationWindow{
			Start:                 at.Add(-time.Hour),
			End:                   at,
			EventCount:            3,
			SessionCount:          1,
			ObservationWindowRoot: "sha256:window",
		},
		Defaults: contract.ContractDefaults{
			Fidelity: "medium",
			Confidence: map[string]any{
				"min_events": 20,
			},
			Privacy: contract.ContractDefaultsPrivacy{
				DefaultDataClass: contract.DataClassInternal,
				ForbidClasses:    []contract.DataClass{contract.DataClassRegulated},
			},
		},
		Rules: []contract.Rule{{
			RuleID:         "r-test",
			DisplayName:    "api_example_com_get",
			RuleKind:       "http_destination",
			LifecycleState: "capture_only",
			Confidence:     "stable",
			WilsonLower:    "0.95",
			Observation:    map[string]any{"events_observed": 3},
			Selector:       map[string]any{"host": map[string]any{"value": "api.example.com", "data_class": "public"}},
			Rationale:      map[string]any{"summary": "Observed repeatedly.", "data_class": "internal"},
			RecurringSupport: map[string]any{
				"windows_seen_in_last_n": 1,
				"windows_floor":          1,
			},
			OpportunityHealth: map[string]any{"missing_alert_threshold": "0.50"},
		}},
	}
}

func TestEmitContract_DeterministicAndVerifiable(t *testing.T) {
	t.Parallel()
	signer, pub := testSigner()
	opts := EmitOptions{
		StartedAt:         time.Date(2026, 4, 29, 20, 0, 0, 0, time.UTC),
		FinishedAt:        time.Date(2026, 4, 29, 20, 0, 1, 0, time.UTC),
		CompileConfigHash: "sha256:config",
		Inputs: []contract.InputRef{{
			Path:       "/tmp/input.jsonl",
			SHA256:     "sha256:input",
			EventCount: 3,
		}},
		Settings: map[string]any{
			"confidence":    map[string]any{"min_events": 20},
			"normalization": map[string]any{},
		},
	}

	first, err := EmitContract(baseContract(), signer, opts)
	if err != nil {
		t.Fatalf("EmitContract first: %v", err)
	}
	second, err := EmitContract(baseContract(), signer, opts)
	if err != nil {
		t.Fatalf("EmitContract second: %v", err)
	}
	if string(first.YAML) != string(second.YAML) {
		t.Fatal("contract yaml is not deterministic")
	}
	if string(first.ManifestJSON) != string(second.ManifestJSON) {
		t.Fatal("manifest json is not deterministic")
	}
	if string(first.ContractPreimage) != string(second.ContractPreimage) {
		t.Fatal("contract preimage is not deterministic")
	}
	if string(first.ManifestPreimage) != string(second.ManifestPreimage) {
		t.Fatal("manifest preimage is not deterministic")
	}

	var env contract.ContractEnvelope
	if err := contract.DecodeStrictYAML(first.YAML, &env); err != nil {
		t.Fatalf("strict yaml decode: %v\n%s", err, first.YAML)
	}
	if env.Body.ContractHash == "" {
		t.Fatal("contract hash is empty")
	}
	sig, err := hex.DecodeString(env.Signature[len(ed25519Prefix):])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !contract.VerifyEd25519PureEdDSA(pub, first.ContractPreimage, sig) {
		t.Fatal("contract signature did not verify")
	}

	var manifestEnv contract.CompileManifestEnvelope
	if err := contract.DecodeStrictJSON(first.ManifestJSON, &manifestEnv); err != nil {
		t.Fatalf("strict manifest json decode: %v", err)
	}
	if manifestEnv.Body.ModuleDigestRoot == "" {
		t.Fatal("module digest root is empty")
	}
	manifestSig, err := hex.DecodeString(manifestEnv.Signature[len(ed25519Prefix):])
	if err != nil {
		t.Fatalf("decode manifest signature: %v", err)
	}
	if !contract.VerifyEd25519PureEdDSA(pub, first.ManifestPreimage, manifestSig) {
		t.Fatal("manifest signature did not verify")
	}
}

func TestEmitContract_RejectsNilSigner(t *testing.T) {
	t.Parallel()
	_, err := EmitContract(baseContract(), nil, EmitOptions{})
	if !errors.Is(err, ErrNilSigner) {
		t.Fatalf("got %v, want ErrNilSigner", err)
	}
}

func TestEmitContract_RejectsInvalidContract(t *testing.T) {
	t.Parallel()
	signer, _ := testSigner()
	c := baseContract()
	c.SchemaVersion = 99
	_, err := EmitContract(c, signer, EmitOptions{})
	if !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("got %v, want ErrInvalidArtifact", err)
	}
}

func TestEmitContract_PropagatesSignError(t *testing.T) {
	t.Parallel()
	_, err := EmitContract(baseContract(), failingSigner{}, EmitOptions{})
	if !errors.Is(err, errSignBoom) {
		t.Fatalf("got %v, want errSignBoom", err)
	}
}

func TestEmitContract_RejectsInvalidManifestSettings(t *testing.T) {
	t.Parallel()
	signer, _ := testSigner()
	_, err := EmitContract(baseContract(), signer, EmitOptions{
		Settings: map[string]any{"disallowed": map[string]any{}},
	})
	if !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("got %v, want ErrInvalidArtifact", err)
	}
}

func TestEmitContract_ManifestPreimageError(t *testing.T) {
	t.Parallel()
	signer, _ := testSigner()
	_, err := EmitContract(baseContract(), signer, EmitOptions{
		Settings: map[string]any{"confidence": map[string]any{"bad": make(chan int)}},
	})
	if err == nil || !strings.Contains(err.Error(), "manifest preimage") {
		t.Fatalf("got %v, want manifest preimage error", err)
	}
}

func TestEmitContract_ManifestSignError(t *testing.T) {
	t.Parallel()
	fixture, _ := testSigner()
	_, err := EmitContract(baseContract(), &failSecondSigner{priv: fixture.priv}, EmitOptions{})
	if !errors.Is(err, errSignBoom) {
		t.Fatalf("got %v, want errSignBoom", err)
	}
}

func TestEmitContract_ContractHashPreimageErrorFeedsValidation(t *testing.T) {
	t.Parallel()
	signer, _ := testSigner()
	c := baseContract()
	c.Defaults.Confidence = map[string]any{"bad": make(chan int)}
	_, err := EmitContract(c, signer, EmitOptions{})
	if err == nil || !strings.Contains(err.Error(), "compute contract hash") {
		t.Fatalf("got %v, want contract hash error", err)
	}
	if hash, err := hashContractWithEmptyHash(c); err == nil || hash != "" {
		t.Fatalf("hashContractWithEmptyHash = %q, %v; want empty hash and error", hash, err)
	}
}

func TestHelpers(t *testing.T) {
	t.Parallel()
	if got := signatureString([]byte{0xab}); got != "ed25519:ab" {
		t.Fatalf("signatureString = %q", got)
	}
	if got := cloneSettings(nil); len(got) != 0 {
		t.Fatalf("cloneSettings(nil) len = %d, want 0", len(got))
	}
	settings := map[string]any{"nested": map[string]any{"items": []any{map[string]any{"k": "v"}}}}
	cloned := cloneSettings(settings)
	settings["nested"].(map[string]any)["items"].([]any)[0].(map[string]any)["k"] = "mutated"
	gotNested := cloned["nested"].(map[string]any)["items"].([]any)[0].(map[string]any)["k"]
	if gotNested != "v" {
		t.Fatalf("cloneSettings nested value = %q, want independent copy", gotNested)
	}
	if _, err := marshalDeterministicJSON(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("marshalDeterministicJSON expected error")
	}
	if _, err := marshalDeterministicYAML(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("marshalDeterministicYAML expected error")
	}
}

func TestModuleDigestsFromBuildInfo(t *testing.T) {
	t.Parallel()
	got := moduleDigestsFromBuildInfo(&debug.BuildInfo{
		Main: debug.Module{Path: "main", Version: "v1"},
		Deps: []*debug.Module{
			{Path: "dep", Version: "v2"},
			{Path: "old", Version: "v0", Replace: &debug.Module{Path: "new", Version: "v3"}},
		},
	})
	for _, key := range []string{"main", "dep", "old=>new"} {
		if got[key] == "" {
			t.Fatalf("missing digest for %s: %#v", key, got)
		}
	}
	if got := moduleDigestsFromBuildInfo(nil); len(got) != 0 {
		t.Fatalf("nil build info = %#v, want empty", got)
	}
}

func TestModuleDigestsFallbackUsesUnavailableMarker(t *testing.T) {
	oldReadBuildInfo := readBuildInfo
	t.Cleanup(func() {
		readBuildInfo = oldReadBuildInfo
	})
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return nil, false
	}

	got := moduleDigests()
	if got[moduleDigestUnavailableKey] == "" {
		t.Fatalf("moduleDigests fallback missing unavailable marker: %#v", got)
	}
}

func TestYAMLNodeScalars(t *testing.T) {
	t.Parallel()
	tree := map[string]any{
		"array": []any{"x", nil},
		"off":   false,
		"bool":  true,
		"float": json.Number("1.5"),
		"int":   json.Number("7"),
	}
	out, err := marshalDeterministicYAML(tree)
	if err != nil {
		t.Fatalf("marshalDeterministicYAML: %v", err)
	}
	text := string(out)
	for _, want := range []string{"array:", "bool: true", "off: false", "float: 1.5", "int: 7", "- null"} {
		if !strings.Contains(text, want) {
			t.Fatalf("yaml %q missing %q", text, want)
		}
	}
	if node := yamlNode(42); node.Value != "42" || node.Tag != "!!str" {
		t.Fatalf("yamlNode default = %#v, want string 42", node)
	}
}

type failingSigner struct{}

func (failingSigner) KeyID() string { return "failing" }

func (failingSigner) Sign(_ []byte) ([]byte, error) { return nil, errSignBoom }

type failSecondSigner struct {
	calls int
	priv  ed25519.PrivateKey
}

func (failSecondSigner) KeyID() string { return "fail-second" }

func (s *failSecondSigner) Sign(message []byte) ([]byte, error) {
	s.calls++
	if s.calls == 2 {
		return nil, errSignBoom
	}
	return ed25519.Sign(s.priv, message), nil
}

var errSignBoom = errors.New("sign boom")
