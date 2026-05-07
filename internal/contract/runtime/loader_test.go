// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

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

	"github.com/luckyPipewrench/pipelock/internal/contract"
	contractstore "github.com/luckyPipewrench/pipelock/internal/contract/store"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestNewLoader_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	const validFP = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	validEnv := testLoaderEnv()
	cases := []struct {
		name string
		opts LoaderOptions
		want string
	}{
		{
			name: "missing store_dir",
			opts: LoaderOptions{RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "store_dir required",
		},
		{
			name: "missing roster_path",
			opts: LoaderOptions{StoreDir: "/tmp/s", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "roster_path required",
		},
		{
			name: "missing fingerprint",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", Environment: validEnv, MinSignatures: 1, Mode: ModeShadow},
			want: "pinned_root_fingerprint required",
		},
		{
			name: "missing environment",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: ModeShadow},
			want: "environment required",
		},
		{
			name: "zero min_signatures",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 0, Mode: ModeShadow},
			want: "min_signatures must be >= 1",
		},
		{
			name: "empty mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1},
			want: "mode",
		},
		{
			name: "unknown mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, Environment: validEnv, MinSignatures: 1, Mode: Mode("preview")},
			want: "mode",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewLoader(tc.opts, nil)
			if err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
			if !errors.Is(err, ErrInvalidDecisionInput) {
				t.Fatalf("%s: err = %v, want ErrInvalidDecisionInput", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s: err = %q, want to contain %q", tc.name, err.Error(), tc.want)
			}
		})
	}
}

func TestNewLoader_RejectsMissingRosterFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := NewLoader(LoaderOptions{
		StoreDir:              filepath.Join(dir, "store"),
		RosterPath:            filepath.Join(dir, "does-not-exist.json"),
		PinnedRootFingerprint: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Environment:           testLoaderEnv(),
		MinSignatures:         1,
		Mode:                  ModeShadow,
	}, nil)
	if err == nil {
		t.Fatal("missing roster file: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "load roster") {
		t.Fatalf("err = %v, want load roster wrap", err)
	}
}

func TestNewLoader_NoActiveManifest_ReturnsNilCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}

	metrics := &captureMetrics{}
	loader, err := NewLoader(LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
		Environment:           testLoaderEnv(),
		MinSignatures:         1,
		Mode:                  ModeShadow,
		Now:                   func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}, metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}

	if loader.Current() != nil {
		t.Fatalf("Current() = %v, want nil for empty store", loader.Current())
	}
	if loader.Mode() != ModeShadow {
		t.Fatalf("Mode() = %q, want shadow", loader.Mode())
	}
	if metrics.outcomes["no_active"] != 1 {
		t.Fatalf("expected one no_active reload outcome, got %v", metrics.outcomes)
	}
	if metrics.lastGeneration != 0 {
		t.Fatalf("expected generation 0 for empty store, got %d", metrics.lastGeneration)
	}
}

func TestLoader_ReloadAcceptsSameHashWithoutError(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}

	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload same hash: %v", err)
	}
	if loader.Current() != current {
		t.Fatal("same-hash reload should preserve active set pointer")
	}
	if metrics.outcomes["same_hash"] != 1 {
		t.Fatalf("same_hash metrics = %v, want one same_hash", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsMissingActiveAfterCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", testLoaderEnv())

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	if current == nil {
		t.Fatal("Current() = nil, want active set")
	}
	if err := os.Remove(filepath.Join(storeDir, "active.json")); err != nil {
		t.Fatalf("remove active.json: %v", err)
	}

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload after active.json deletion returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("missing active.json after a current manifest must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsEnvironmentMismatchAndKeepsCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	otherEnv := contract.Environment{ID: "staging", Tenant: env.Tenant, DeploymentID: env.DeploymentID}
	writeSignedActiveStore(t, fixture, storeDir, 2, current.ManifestHash(), otherEnv)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload environment mismatch returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("environment mismatch must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_ReloadRejectsGenerationDowngradeAndKeepsCurrent(t *testing.T) {
	t.Parallel()
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	env := testLoaderEnv()
	writeSignedActiveStore(t, fixture, storeDir, 2, "sha256:genesis", env)

	metrics := &captureMetrics{}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, env), metrics)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	current := loader.Current()
	writeSignedActiveStore(t, fixture, storeDir, 1, "sha256:older", env)

	if err := loader.Reload(); err == nil {
		t.Fatal("Reload generation downgrade returned nil error")
	}
	if loader.Current() != current {
		t.Fatal("generation downgrade must preserve previous active set")
	}
	if metrics.outcomes["rejected"] != 1 {
		t.Fatalf("metrics = %v, want one rejected outcome", metrics.outcomes)
	}
}

func TestLoader_NilReceiverAccessorsAreSafe(t *testing.T) {
	t.Parallel()
	// Defensive guard: a misconfigured caller that passes nil through to
	// Current() or Mode() must not panic. The proxy hot path calls these
	// on every request, and a nil-deref there would blackhole traffic.
	var l *Loader
	if got := l.Current(); got != nil {
		t.Fatalf("nil-loader Current() = %v, want nil", got)
	}
	if got := l.Mode(); got != "" {
		t.Fatalf("nil-loader Mode() = %q, want empty", got)
	}
	if err := l.Reload(); err == nil {
		t.Fatal("nil-loader Reload() returned nil error")
	}
}

func TestLoader_NilMetricsExercisesNoopImpl(t *testing.T) {
	t.Parallel()
	// Constructing a Loader with metrics=nil must wire the noopMetrics
	// implementation so all reload-outcome and generation calls land on
	// real method receivers. Coverage proves no panic and no nil-deref
	// from production code paths that assume metrics is always set.
	fixture := newRosterFixture(t)
	storeDir := filepath.Join(fixture.root, "store")
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	loader, err := NewLoader(loaderOptions(fixture, storeDir, testLoaderEnv()), nil)
	if err != nil {
		t.Fatalf("NewLoader: %v", err)
	}
	if loader.Current() != nil {
		t.Fatalf("Current() = %v, want nil for empty store", loader.Current())
	}
	// Reload again to confirm noopMetrics handles a same-no-active path
	// without surfacing an error.
	if err := loader.Reload(); err != nil {
		t.Fatalf("Reload with nil metrics: %v", err)
	}
}

// rosterFixture is the minimum fixture the Loader needs at construction
// time: a real Ed25519 root key, a real activation-signing key, and a
// roster file on disk that signing.LoadRoster can verify. Tests that
// build a real signed active.json reuse this fixture and add the
// manifest-side scaffolding on top in F3c.
type rosterFixture struct {
	root            string
	rosterPath      string
	rootFingerprint string
	rootPriv        ed25519.PrivateKey
	activationPub   ed25519.PublicKey
	activationPriv  ed25519.PrivateKey
	compilePub      ed25519.PublicKey
	compilePriv     ed25519.PrivateKey
}

func newRosterFixture(t *testing.T) rosterFixture {
	t.Helper()
	root := t.TempDir()
	keystoreDir := filepath.Join(root, "keys")
	ks := signing.NewKeystore(keystoreDir)

	rootPub, err := ks.GenerateAgent("roster-root")
	if err != nil {
		t.Fatalf("generate root: %v", err)
	}
	rootPriv, err := ks.LoadPrivateKey("roster-root")
	if err != nil {
		t.Fatalf("load root priv: %v", err)
	}
	activationPub, err := ks.GenerateAgent("activation-primary")
	if err != nil {
		t.Fatalf("generate activation: %v", err)
	}
	activationPriv, err := ks.LoadPrivateKey("activation-primary")
	if err != nil {
		t.Fatalf("load activation priv: %v", err)
	}
	compilePub, err := ks.GenerateAgent("compile-primary")
	if err != nil {
		t.Fatalf("generate compile: %v", err)
	}
	compilePriv, err := ks.LoadPrivateKey("compile-primary")
	if err != nil {
		t.Fatalf("load compile priv: %v", err)
	}

	rootFingerprint, err := signing.Fingerprint(rootPub)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}

	body := contract.KeyRoster{
		SchemaVersion:  1,
		RosterSignedBy: "roster-root",
		DataClassRoot:  string(contract.DataClassInternal),
		Keys: []contract.KeyInfo{
			rosterKey("roster-root", signing.PurposeRosterRoot, rootPub, contract.KeyStatusRoot, "root"),
			rosterKey("activation-primary", signing.PurposeContractActivationSigning, activationPub, contract.KeyStatusActive, "operator"),
			rosterKey("compile-primary", signing.PurposeContractCompileSigning, compilePub, contract.KeyStatusActive, "compiler"),
		},
	}
	preimage, err := body.SignablePreimage()
	if err != nil {
		t.Fatalf("roster preimage: %v", err)
	}
	envelope := contract.RosterEnvelope{
		Body:      body,
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(rootPriv, preimage)),
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

	return rosterFixture{
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

func loaderOptions(fixture rosterFixture, storeDir string, env contract.Environment) LoaderOptions {
	return LoaderOptions{
		StoreDir:              storeDir,
		RosterPath:            fixture.rosterPath,
		PinnedRootFingerprint: fixture.rootFingerprint,
		Environment:           env,
		MinSignatures:         1,
		Mode:                  ModeShadow,
		Now:                   func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) },
	}
}

func testLoaderEnv() contract.Environment {
	return contract.Environment{ID: "prod", Tenant: "tenant-a", DeploymentID: "deploy-a"}
}

func writeSignedActiveStore(t *testing.T, fixture rosterFixture, storeDir string, generation uint64, prior string, env contract.Environment) {
	t.Helper()
	st := contractstore.New(storeDir)
	contractHash := putSignedLoaderContract(t, st, fixture)
	active := signedLoaderManifest(t, contractHash, generation, prior, env, fixture)
	raw, err := json.Marshal(active)
	if err != nil {
		t.Fatalf("marshal active manifest: %v", err)
	}
	if err := os.MkdirAll(storeDir, 0o750); err != nil {
		t.Fatalf("mkdir store: %v", err)
	}
	if err := os.WriteFile(filepath.Join(storeDir, "active.json"), append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write active.json: %v", err)
	}
}

func putSignedLoaderContract(t *testing.T, st contractstore.Store, fixture rosterFixture) string {
	t.Helper()
	body := contract.Contract{
		SchemaVersion:    contract.SchemaVersionContract,
		ContractKind:     contract.ContractKind,
		SignerKeyID:      "compile-primary",
		KeyPurpose:       signing.PurposeContractCompileSigning.String(),
		DataClassRoot:    string(contract.DataClassInternal),
		FieldDataClasses: map[string]string{},
		Selector:         contract.Selector{Agent: "agent-a", SelectorID: "sha256:selector"},
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
		Signature: "ed25519:" + hex.EncodeToString(ed25519.Sign(fixture.compilePriv, preimage)),
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

func signedLoaderManifest(t *testing.T, contractHash string, generation uint64, prior string, env contract.Environment, fixture rosterFixture) contract.ActiveManifestEnvelope {
	t.Helper()
	selector := contract.ManifestSelector{Agent: "agent-a", ContractHash: contractHash}
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
			KeyID:      "activation-primary",
			Principal:  "operator",
			KeyPurpose: signing.PurposeContractActivationSigning.String(),
			Algorithm:  "ed25519",
			Signature:  "ed25519:" + hex.EncodeToString(ed25519.Sign(fixture.activationPriv, preimage)),
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

// captureMetrics records LoaderMetrics calls for assertion in tests.
type captureMetrics struct {
	outcomes       map[string]int
	lastGeneration uint64
}

func (m *captureMetrics) IncReload(outcome string) {
	if m.outcomes == nil {
		m.outcomes = map[string]int{}
	}
	m.outcomes[outcome]++
}

func (m *captureMetrics) SetGeneration(generation uint64) {
	m.lastGeneration = generation
}
