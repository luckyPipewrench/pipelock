// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contractruntimetest

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// Key IDs the fixture stamps onto the generated keystore + roster +
// signed contract/manifest bodies. Using named constants prevents typo
// drift between the keystore (where the private key lives) and the
// roster + signature header (which look the key up by ID).
const (
	keyIDRosterRoot        = "roster-root"
	keyIDActivationPrimary = "activation-primary"
	keyIDCompilePrimary    = "compile-primary"
	signaturePrefixEd25519 = "ed25519:"
)

// Fixture holds a verified roster and signing keys for runtime loader tests.
type Fixture struct {
	root            string
	rosterPath      string
	rootFingerprint string
	rootPriv        ed25519.PrivateKey
	activationPub   ed25519.PublicKey
	activationPriv  ed25519.PrivateKey
	compilePub      ed25519.PublicKey
	compilePriv     ed25519.PrivateKey
}

// NewFixture creates a real roster rooted in a temporary keystore.
func NewFixture(t *testing.T) Fixture {
	t.Helper()
	root := t.TempDir()
	keystoreDir := filepath.Join(root, "keys")
	ks := signing.NewKeystore(keystoreDir)

	rootPub, err := ks.GenerateAgent(keyIDRosterRoot)
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	rootPriv, err := ks.LoadPrivateKey(keyIDRosterRoot)
	if err != nil {
		t.Fatalf("load root priv: %v", err)
	}
	activationPub, err := ks.GenerateAgent(keyIDActivationPrimary)
	if err != nil {
		t.Fatalf("generate activation: %v", err)
	}
	activationPriv, err := ks.LoadPrivateKey(keyIDActivationPrimary)
	if err != nil {
		t.Fatalf("load activation priv: %v", err)
	}
	compilePub, err := ks.GenerateAgent(keyIDCompilePrimary)
	if err != nil {
		t.Fatalf("generate compile: %v", err)
	}
	compilePriv, err := ks.LoadPrivateKey(keyIDCompilePrimary)
	if err != nil {
		t.Fatalf("load compile priv: %v", err)
	}

	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: keyIDRosterRoot,
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			rosterKey(keyIDRosterRoot, signing.PurposeRosterRoot, rootPub, contract.KeyStatusRoot, "root"),
			rosterKey(keyIDActivationPrimary, signing.PurposeContractActivationSigning, activationPub, contract.KeyStatusActive, "operator"),
			rosterKey(keyIDCompilePrimary, signing.PurposeContractCompileSigning, compilePub, contract.KeyStatusActive, "compiler"),
		},
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("roster preimage: %v", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: signaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(rootPriv, preimage)),
	}
	rosterPath := filepath.Join(root, "roster.json")
	rosterBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal roster: %v", err)
	}
	if err := os.WriteFile(rosterPath, append(rosterBytes, '\n'), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	if _, err := signing.LoadRoster(rosterPath, rootFingerprint); err != nil {
		t.Fatalf("verify roster fixture: %v", err)
	}

	return Fixture{
		root:            root,
		rosterPath:      rosterPath,
		rootFingerprint: rootFingerprint,
		rootPriv:        rootPriv,
		activationPub:   activationPub,
		activationPriv:  activationPriv,
		compilePub:      compilePub,
		compilePriv:     compilePriv,
	}
}

func (f Fixture) RosterPath() string {
	return f.rosterPath
}

func (f Fixture) RootFingerprint() string {
	return f.rootFingerprint
}

func (f Fixture) Root() string {
	return f.root
}

func Env() contract.Environment {
	return contract.Environment{ID: "prod"}
}

// ActiveStoreOptions bundles the per-generation knobs WriteSignedActiveStore
// and WriteAcceptedActiveStore need so the helpers stay under the project's
// 6-parameter guideline as more knobs are inevitably added by future tests.
// Generation, PriorHash, and Environment have no zero-value safety, so
// callers must populate them explicitly; PreviousGeneration is only
// consulted by WriteAcceptedActiveStore (the CAS path) and is ignored by
// WriteSignedActiveStore (the raw-write path).
type ActiveStoreOptions struct {
	Agent              string
	Rules              []contract.Rule
	Generation         uint64
	PriorHash          string
	PreviousGeneration uint64
	Environment        contract.Environment
}

func WriteSignedActiveStore(t *testing.T, fixture Fixture, storeDir string, opts ActiveStoreOptions) {
	t.Helper()
	st := contractstore.New(storeDir)
	contractHash := putSignedContract(t, st, fixture, opts)
	active := signedManifest(t, contractHash, opts.Generation, opts.PriorHash, opts.Environment, fixture, opts.Agent)
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatalf("marshal active manifest: %v", err)
	}
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	// atomicfile.Write mirrors how the production promote path lands the
	// active manifest (temp + rename). Tests that rewrite active.json
	// while a Watch goroutine is reading it would otherwise produce
	// parse-error outcomes under -race load instead of the intended
	// signature/generation/same-hash outcomes.
	if err := atomicfile.Write(filepath.Join(storeDir, "active.json"), append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
}

// WriteAcceptedActiveStore writes a signed active manifest through the
// store's CAS path so the journal records an accepted promotion entry.
// Use this instead of WriteSignedActiveStore when a test needs the
// loader to recover a missed intermediate generation, since recovery
// walks the accepted-history chain rather than raw on-disk active.json.
// Returns the manifest hash so callers can chain PriorHash for
// subsequent generations.
func WriteAcceptedActiveStore(t *testing.T, fixture Fixture, storeDir string, opts ActiveStoreOptions) string {
	t.Helper()
	st := contractstore.New(storeDir)
	contractHash := putSignedContract(t, st, fixture, opts)
	active := signedManifest(t, contractHash, opts.Generation, opts.PriorHash, opts.Environment, fixture, opts.Agent)
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatalf("marshal active manifest: %v", err)
	}
	loadedRoster, err := signing.LoadRoster(fixture.rosterPath, fixture.rootFingerprint)
	if err != nil {
		t.Fatalf("load roster: %v", err)
	}
	storeOpts := contractstore.Options{
		Environment:        opts.Environment,
		Roster:             loadedRoster,
		PreviousHash:       opts.PriorHash,
		PreviousGeneration: opts.PreviousGeneration,
		MinSignatures:      1,
		Now:                func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}
	hash, err := st.WriteActive(raw, storeOpts)
	if err != nil {
		t.Fatalf("WriteActive generation %d: %v", opts.Generation, err)
	}
	if _, err := st.Reload(storeOpts); err != nil {
		t.Fatalf("Reload generation %d: %v", opts.Generation, err)
	}
	return hash
}

func HTTPEnforceRule(ruleID, host, pathValue, method string) contract.Rule {
	return contract.Rule{
		RuleID:               ruleID,
		DisplayName:          ruleID,
		RuleKind:             contract.RuleKindHTTPDestination,
		LifecycleState:       contract.LifecycleEnforce,
		RequiredCaptureGrade: contract.CaptureGradeFull,
		ObservedCaptureGrade: contract.CaptureGradeFull,
		Confidence:           "1.0",
		WilsonLower:          "1.0",
		Observation:          map[string]any{},
		Selector: map[string]any{
			"host":    map[string]any{"value": host},
			"paths":   []any{map[string]any{"value": pathValue}},
			"methods": []any{method},
		},
		Rationale:         map[string]any{},
		RecurringSupport:  map[string]any{},
		OpportunityHealth: map[string]any{},
	}
}

func putSignedContract(t *testing.T, st contractstore.Store, fixture Fixture, opts ActiveStoreOptions) string {
	t.Helper()
	agent := opts.Agent
	if agent == "" {
		agent = "agent-a"
	}
	body := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      keyIDCompilePrimary,
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: agent, SelectorID: "sha256:selector"},
		Rules:            append([]contract.Rule(nil), opts.Rules...),
	}
	hash, err := contractstore.ContractHash(body)
	if err != nil {
		t.Fatalf("contract hash: %v", err)
	}
	body.ContractHash = hash
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("contract preimage: %v", err)
	}
	env := contract.ContractEnvelope{
		Body:      body,
		Signature: signaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(fixture.compilePriv, preimage)),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal contract: %v", err)
	}
	loadedRoster, err := signing.LoadRoster(fixture.rosterPath, fixture.rootFingerprint)
	if err != nil {
		t.Fatalf("load roster: %v", err)
	}
	if got, err := st.PutHistoryContract(raw, contractstore.Options{
		Roster:        loadedRoster,
		MinSignatures: 1,
		Now:           func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}); err != nil {
		t.Fatalf("PutHistoryContract: %v", err)
	} else if got != hash {
		t.Fatalf("PutHistoryContract hash = %q, want %q", got, hash)
	}
	return hash
}

func signedManifest(t *testing.T, contractHash string, generation uint64, prior string, env contract.Environment, fixture Fixture, agent string) contract.ActiveManifestEnvelope {
	t.Helper()
	if agent == "" {
		agent = "agent-a"
	}
	selector := contract.ManifestSelector{Agent: agent, ContractHash: contractHash}
	selectorID, err := selector.ComputeSelectorID()
	if err != nil {
		t.Fatalf("ComputeSelectorID: %v", err)
	}
	selector.SelectorID = selectorID
	selectorSetHash, err := contract.ComputeSelectorSetHash([]contract.ManifestSelector{selector})
	if err != nil {
		t.Fatalf("ComputeSelectorSetHash: %v", err)
	}
	body := contract.ActiveManifest{
		SchemaVersion:     1,
		ManifestKind:      contract.ManifestKindActivation,
		Generation:        generation,
		PriorManifestHash: prior,
		SelectorSetHash:   selectorSetHash,
		Environment:       env,
		Selectors:         []contract.ManifestSelector{selector},
		HistoryRoot:       "contracts/history/",
		SignedAt:          time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("manifest preimage: %v", err)
	}
	return contract.ActiveManifestEnvelope{
		Body: body,
		Signatures: []contract.ManifestSignature{{
			KeyID:      keyIDActivationPrimary,
			Principal:  "operator",
			KeyPurpose: signing.PurposeContractActivationSigning.String(),
			Algorithm:  "ed25519",
			Signature:  signaturePrefixEd25519 + hex.EncodeToString(ed25519.Sign(fixture.activationPriv, preimage)),
		}},
	}
}

func rosterKey(keyID string, purpose signing.KeyPurpose, pub ed25519.PublicKey, status, principal string) contract.KeyInfo {
	return contract.KeyInfo{
		KeyID:        keyID,
		KeyPurpose:   purpose.String(),
		PublicKeyHex: hex.EncodeToString(pub),
		ValidFrom:    time.Date(2026, 4, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Status:       status,
		Principal:    principal,
	}
}
