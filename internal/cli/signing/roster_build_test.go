// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	domsigning "github.com/luckyPipewrench/pipelock/internal/signing"
)

// rosterBuildFixture seeds a working root + activation + compile key triple
// and returns each path. Used by every roster-build positive test.
type rosterBuildFixture struct {
	dir            string
	rootPath       string
	rootPubHex     string
	activationPath string
	compilePath    string
}

func newRosterBuildFixture(t *testing.T) rosterBuildFixture {
	t.Helper()
	dir := t.TempDir()
	rootPath := filepath.Join(dir, "root.json")
	activationPath := filepath.Join(dir, "activation.json")
	compilePath := filepath.Join(dir, "compile.json")

	for _, e := range []struct {
		purpose string
		out     string
		id      string
	}{
		{string(domsigning.PurposeRosterRoot), rootPath, ""},
		{string(domsigning.PurposeContractActivationSigning), activationPath, "activation-primary"},
		{string(domsigning.PurposeContractCompileSigning), compilePath, "compile-test"},
	} {
		cmd := keyGenerateCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		args := []string{"--purpose", e.purpose, "--out", e.out}
		if e.id != "" {
			args = append(args, "--id", e.id)
		}
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("seed key generate %s: %v", e.purpose, err)
		}
	}

	rootRaw, err := os.ReadFile(filepath.Clean(rootPath))
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	var rootKF keyFile
	if err := json.Unmarshal(rootRaw, &rootKF); err != nil {
		t.Fatalf("unmarshal root: %v", err)
	}
	return rosterBuildFixture{
		dir:            dir,
		rootPath:       rootPath,
		rootPubHex:     rootKF.Public,
		activationPath: activationPath,
		compilePath:    compilePath,
	}
}

func TestRosterBuild_RoundTripVerifies(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning) + ",role=operator",
		"--include", "id=compile-test,key=" + fx.compilePath + ",purpose=" + string(domsigning.PurposeContractCompileSigning) + ",role=compiler",
		"--out", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("roster build: %v", err)
	}

	rootPubBytes, err := hex.DecodeString(fx.rootPubHex)
	if err != nil {
		t.Fatalf("decode root pub: %v", err)
	}
	pinnedFP, err := domsigning.Fingerprint(rootPubBytes)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	loaded, err := domsigning.LoadRoster(out, pinnedFP)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}
	if loaded == nil {
		t.Fatalf("LoadRoster returned nil")
	}
	if got := len(loaded.Body.Keys); got != 3 {
		t.Errorf("loaded.Keys = %d, want 3", got)
	}
}

func TestRosterBuild_EnforcesAtomicOutputPermissions(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--out", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("output mode = %o leaks group/world bits", info.Mode().Perm())
	}
}

func TestRosterBuild_RefusesDuplicateID(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=dup,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--include", "id=dup,key=" + fx.compilePath + ",purpose=" + string(domsigning.PurposeContractCompileSigning),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected duplicate-id error")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("err %q does not mention duplicate", err.Error())
	}
}

func TestRosterBuild_RefusesPurposeMismatchInJSONKeyFile(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractCompileSigning),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected purpose-mismatch error")
	}
	if !strings.Contains(err.Error(), "purpose flag") || !strings.Contains(err.Error(), "key file purpose") {
		t.Errorf("err %q does not name both flag and file purpose", err.Error())
	}
}

func TestRosterBuild_RefusesIncludeOfRosterRoot(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=second-root,key=" + fx.rootPath + ",purpose=" + string(domsigning.PurposeRosterRoot),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected refuse-roster-root-include error")
	}
	if !strings.Contains(err.Error(), "auto-included") {
		t.Errorf("err %q does not mention auto-include policy", err.Error())
	}
}

func TestRosterBuild_RefusesUnknownDataClass(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--data-class", "bogus",
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected data-class error")
	}
	if !strings.Contains(err.Error(), "invalid data_class") {
		t.Errorf("err %q does not name invalid data_class", err.Error())
	}
}

func TestRosterBuild_RefusesRegulatedDataClass(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--data-class", string(contract.DataClassRegulated),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected regulated-data-class error")
	}
	if !strings.Contains(err.Error(), "regulated") {
		t.Errorf("err %q does not name regulated", err.Error())
	}
}

func TestRosterBuild_RefusesUnknownIncludeStatus(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning) + ",status=bogus",
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected unknown-status error")
	}
	if !strings.Contains(err.Error(), "unknown status") {
		t.Errorf("err %q does not mention unknown status", err.Error())
	}
}

func TestRosterBuild_AllowsRevokedIncludeStatus(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning) + ",status=" + contract.KeyStatusRevoked,
		"--out", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}

	rootPubBytes, err := hex.DecodeString(fx.rootPubHex)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	pinnedFP, err := domsigning.Fingerprint(rootPubBytes)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	loaded, err := domsigning.LoadRoster(out, pinnedFP)
	if err != nil {
		t.Fatalf("LoadRoster: %v", err)
	}
	gotRevoked := false
	for _, k := range loaded.Body.Keys {
		if k.KeyID == "activation-primary" && k.Status == contract.KeyStatusRevoked {
			gotRevoked = true
		}
	}
	if !gotRevoked {
		t.Errorf("revoked status was not preserved")
	}
}

func TestRosterBuild_RefusesStatusRootInInclude(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning) + ",status=" + contract.KeyStatusRoot,
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected refuse-status-root error")
	}
	if !strings.Contains(err.Error(), "status=root is reserved") {
		t.Errorf("err %q does not name reserved-root policy", err.Error())
	}
}

func TestRosterBuild_RefusesWrongPurposeRoot(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.activationPath,
		"--include", "id=compile-test,key=" + fx.compilePath + ",purpose=" + string(domsigning.PurposeContractCompileSigning),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected wrong-purpose-root error")
	}
	if !strings.Contains(err.Error(), "purpose mismatch") {
		t.Errorf("err %q does not mention purpose mismatch", err.Error())
	}
}

func TestRosterBuild_RefusesRelativeOutPath(t *testing.T) {
	fx := newRosterBuildFixture(t)

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--out", "relative.json",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected absolute-path error")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Errorf("err %q does not mention absolute requirement", err.Error())
	}
}

func TestRosterBuild_RefusesUnsupportedSchemaVersion(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--schema-version", "2",
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected unsupported-schema-version error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("err %q does not mention unsupported schema", err.Error())
	}
}

func TestRosterBuild_RefusesOverwriteWithoutForce(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("seed output: %v", err)
	}

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--out", out,
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected refuse-overwrite error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("err %q does not mention existing output", err.Error())
	}
	got, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(got) != "preexisting" {
		t.Errorf("output changed without --force: %q", string(got))
	}
}

func TestRosterBuild_AllowsOverwriteWithForce(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")
	if err := os.WriteFile(out, []byte("preexisting"), 0o600); err != nil {
		t.Fatalf("seed output: %v", err)
	}

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--out", out,
		"--force",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if bytes.Equal(got, []byte("preexisting")) {
		t.Errorf("output was not overwritten under --force")
	}
}

func TestParseIncludeSpec_RejectsDuplicateKeys(t *testing.T) {
	cases := []string{
		"id=a,id=b,key=/k,purpose=p",
		"id=x,key=/k,key=/other,purpose=p",
		"id=x,key=/k,purpose=p,purpose=q",
		"id=x,key=/k,purpose=p,status=active,status=revoked",
		"id=x,key=/k,purpose=p,role=foo,role=bar",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := parseIncludeSpec(c)
			if err == nil {
				t.Fatalf("expected duplicate-key rejection for %q", c)
			}
			if !strings.Contains(err.Error(), "duplicate key") {
				t.Errorf("err %q does not mention duplicate key", err.Error())
			}
		})
	}
}

func TestParseIncludeSpec_TrimsWhitespaceAroundKeyAndValue(t *testing.T) {
	spec, err := parseIncludeSpec(" id = x , key = /k , purpose = p ")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if spec.ID != "x" || spec.KeyPath != "/k" || spec.Purpose != "p" {
		t.Errorf("trim failed: %+v", spec)
	}
}

func TestParseIncludeSpec_RejectsUnknownKey(t *testing.T) {
	_, err := parseIncludeSpec("id=x,key=/k,purpose=p,bogus=z")
	if err == nil {
		t.Fatalf("expected unknown-key error")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("err %q does not mention unknown key", err.Error())
	}
}

func TestParseIncludeSpec_RejectsMissingRequiredField(t *testing.T) {
	cases := []string{
		"key=/k,purpose=p",
		"id=x,purpose=p",
		"id=x,key=/k",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			_, err := parseIncludeSpec(c)
			if err == nil {
				t.Fatalf("expected missing-required-field error for %q", c)
			}
			if !strings.Contains(err.Error(), "missing required field") {
				t.Errorf("err %q does not mention missing required", err.Error())
			}
		})
	}
}

func TestRosterBuild_BuiltRosterIsLoadableByLoadRoster(t *testing.T) {
	// End-to-end: generate keys, build roster, sign with built-in workflow,
	// then load through the runtime LoadRoster path. Proves the wire shape
	// matches what the loader expects.
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--root", fx.rootPath,
		"--include", "id=activation-primary,key=" + fx.activationPath + ",purpose=" + string(domsigning.PurposeContractActivationSigning),
		"--include", "id=compile-test,key=" + fx.compilePath + ",purpose=" + string(domsigning.PurposeContractCompileSigning),
		"--out", out,
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("build: %v", err)
	}

	rootPubBytes, err := hex.DecodeString(fx.rootPubHex)
	if err != nil {
		t.Fatalf("decode pub: %v", err)
	}
	pinnedFP, err := domsigning.Fingerprint(rootPubBytes)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	loaded, err := domsigning.LoadRoster(out, pinnedFP)
	if err != nil {
		t.Fatalf("LoadRoster on built roster: %v", err)
	}
	if loaded.RosterRootFingerprint != pinnedFP {
		t.Errorf("loaded fingerprint = %s, want %s", loaded.RosterRootFingerprint, pinnedFP)
	}

	// And a forged signature must reject. Replace the body, keep the signature,
	// confirm LoadRoster rejects rather than trusting.
	raw, err := os.ReadFile(filepath.Clean(out))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope contract.RosterEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i := range envelope.Body.Keys {
		if envelope.Body.Keys[i].Status == contract.KeyStatusActive {
			envelope.Body.Keys[i].Principal = "tampered"
			break
		}
	}
	tampered, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	tamperedPath := filepath.Join(fx.dir, "tampered.json")
	if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if _, err := domsigning.LoadRoster(tamperedPath, pinnedFP); err == nil {
		t.Errorf("LoadRoster accepted tampered roster")
	}
}

// TestRosterBuild_IncludeRequiresAtLeastOne verifies cobra's MarkFlagRequired
// fires when --include is omitted. Defense in depth on top of parseIncludeSpecs.
func TestRosterBuild_IncludeRequiresAtLeastOne(t *testing.T) {
	fx := newRosterBuildFixture(t)
	out := filepath.Join(fx.dir, "roster.json")

	cmd := rosterBuildCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--root", fx.rootPath, "--out", out})
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected missing-include error")
	}
	if !strings.Contains(err.Error(), "include") {
		t.Errorf("err %q does not mention include", err.Error())
	}
}

// rosterBuildFixture sanity check: the test fixture itself is valid.
func TestNewRosterBuildFixture_GeneratesParseableKeys(t *testing.T) {
	fx := newRosterBuildFixture(t)

	for _, p := range []string{fx.rootPath, fx.activationPath, fx.compilePath} {
		raw, err := os.ReadFile(filepath.Clean(p))
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		var kf keyFile
		if err := json.Unmarshal(raw, &kf); err != nil {
			t.Fatalf("unmarshal %s: %v", p, err)
		}
		pub, err := hex.DecodeString(kf.Public)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			t.Errorf("public hex bad in %s: err=%v len=%d", p, err, len(pub))
		}
	}
}
