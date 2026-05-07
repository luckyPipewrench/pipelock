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
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestNewLoader_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	const validFP = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []struct {
		name string
		opts LoaderOptions
		want string
	}{
		{
			name: "missing store_dir",
			opts: LoaderOptions{RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: ModeShadow},
			want: "store_dir required",
		},
		{
			name: "missing roster_path",
			opts: LoaderOptions{StoreDir: "/tmp/s", PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: ModeShadow},
			want: "roster_path required",
		},
		{
			name: "missing fingerprint",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", MinSignatures: 1, Mode: ModeShadow},
			want: "pinned_root_fingerprint required",
		},
		{
			name: "zero min_signatures",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 0, Mode: ModeShadow},
			want: "min_signatures must be >= 1",
		},
		{
			name: "empty mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 1},
			want: "mode",
		},
		{
			name: "unknown mode",
			opts: LoaderOptions{StoreDir: "/tmp/s", RosterPath: "/tmp/r.json", PinnedRootFingerprint: validFP, MinSignatures: 1, Mode: Mode("preview")},
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
		PinnedRootFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
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
