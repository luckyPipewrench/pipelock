// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

func TestReleaseVerifierFixtureMain(t *testing.T) {
	var stderr bytes.Buffer
	outDir := filepath.Join(t.TempDir(), "fixture")
	if code := releaseVerifierFixtureMain([]string{"--out-dir", outDir}, &stderr); code != 0 {
		t.Fatalf("successful CLI exit = %d, stderr = %q", code, stderr.String())
	}
	for _, name := range []string{receiptFileName, tamperedFileName, keyFileName} {
		if _, err := os.Stat(filepath.Join(outDir, name)); err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
	}

	stderr.Reset()
	if code := releaseVerifierFixtureMain(nil, &stderr); code != 2 {
		t.Fatalf("missing argument exit = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--out-dir is required") {
		t.Fatalf("missing argument stderr = %q", stderr.String())
	}
}

func TestRunReleaseVerifierFixtureRejectsInvalidArgumentsAndPaths(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown flag", args: []string{"--unknown"}, want: "parse arguments"},
		{name: "blank output", args: []string{"--out-dir", "  "}, want: "--out-dir is required"},
		{name: "positional", args: []string{"--out-dir", t.TempDir(), "extra"}, want: "unexpected positional arguments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runReleaseVerifierFixture(test.args)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runReleaseVerifierFixture() error = %v, want %q", err, test.want)
			}
		})
	}

	parent := t.TempDir()
	blocker := filepath.Join(parent, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	err := runReleaseVerifierFixture([]string{"--out-dir", filepath.Join(blocker, "child")})
	if err == nil || !strings.Contains(err.Error(), "create output directory") {
		t.Fatalf("blocked output error = %v", err)
	}

	outDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(outDir, receiptFileName), 0o750); err != nil {
		t.Fatalf("create receipt blocker: %v", err)
	}
	err = runReleaseVerifierFixture([]string{"--out-dir", outDir})
	if err == nil || !strings.Contains(err.Error(), "write fixture: write receipt") {
		t.Fatalf("wrapped write error = %v", err)
	}
}

func TestWriteFixtureReportsProducerFailures(t *testing.T) {
	originalGenerate := generateSigningKey
	originalSign := signReceipt
	originalMarshal := marshalReceipt
	t.Cleanup(func() {
		generateSigningKey = originalGenerate
		signReceipt = originalSign
		marshalReceipt = originalMarshal
	})

	generateSigningKey = func(io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
		return nil, nil, errors.New("random source blocked")
	}
	if err := writeFixture(t.TempDir()); err == nil || !strings.Contains(err.Error(), "generate signing key") {
		t.Fatalf("generate error = %v", err)
	}
	generateSigningKey = originalGenerate

	signReceipt = func(receipt.ActionRecord, ed25519.PrivateKey) (receipt.Receipt, error) {
		return receipt.Receipt{}, errors.New("sign blocked")
	}
	if err := writeFixture(t.TempDir()); err == nil || !strings.Contains(err.Error(), "sign receipt") {
		t.Fatalf("sign error = %v", err)
	}
	signReceipt = originalSign

	marshalReceipt = func(receipt.Receipt) ([]byte, error) {
		return nil, errors.New("marshal blocked")
	}
	if err := writeFixture(t.TempDir()); err == nil || !strings.Contains(err.Error(), "marshal receipt") {
		t.Fatalf("marshal error = %v", err)
	}
	marshalReceipt = func(receipt.Receipt) ([]byte, error) { return []byte("{}"), nil }
	if err := writeFixture(t.TempDir()); err == nil || !strings.Contains(err.Error(), "replace signed target") {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestWriteFixtureReportsEachOutputFailure(t *testing.T) {
	tests := []struct {
		name    string
		blocker string
		want    string
	}{
		{name: "receipt", blocker: receiptFileName, want: "write receipt"},
		{name: "tampered receipt", blocker: tamperedFileName, want: "write tampered receipt"},
		{name: "public key", blocker: keyFileName, want: "write public key"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outDir := t.TempDir()
			if err := os.Mkdir(filepath.Join(outDir, test.blocker), 0o750); err != nil {
				t.Fatalf("create output blocker: %v", err)
			}
			err := writeFixture(outDir)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("writeFixture() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestWriteFixtureProducesSignedReceiptAndTamperedRejection(t *testing.T) {
	dir := t.TempDir()
	if err := writeFixture(dir); err != nil {
		t.Fatalf("writeFixture() error = %v", err)
	}

	key, err := os.ReadFile(filepath.Join(dir, keyFileName)) // #nosec G304 -- fixed fixture name under t.TempDir.
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	publicKey := strings.TrimSpace(string(key))
	if _, err := hex.DecodeString(publicKey); err != nil {
		t.Fatalf("fixture public key is not hex: %v", err)
	}

	validRaw, err := os.ReadFile(filepath.Join(dir, receiptFileName)) // #nosec G304 -- fixed fixture name under t.TempDir.
	if err != nil {
		t.Fatalf("read valid receipt: %v", err)
	}
	valid, err := receipt.Unmarshal(validRaw)
	if err != nil {
		t.Fatalf("unmarshal valid receipt: %v", err)
	}
	if err := receipt.VerifyWithKey(valid, publicKey); err != nil {
		t.Fatalf("valid fixture receipt did not verify: %v", err)
	}

	tamperedRaw, err := os.ReadFile(filepath.Join(dir, tamperedFileName)) // #nosec G304 -- fixed fixture name under t.TempDir.
	if err != nil {
		t.Fatalf("read tampered receipt: %v", err)
	}
	tampered, err := receipt.Unmarshal(tamperedRaw)
	if err != nil {
		t.Fatalf("unmarshal tampered receipt: %v", err)
	}
	if err := receipt.VerifyWithKey(tampered, publicKey); err == nil {
		t.Fatal("tampered fixture receipt verified")
	}
}

func TestReleaseVerifierInventoryRejectsTrailingDuplicate(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	inventoryPath := filepath.Join(root, "release", "verifier-installers.json")
	raw, err := os.ReadFile(inventoryPath) // #nosec G304 -- fixed inventory path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged inventory: %v", err)
	}
	var inventory struct {
		SchemaVersion int                      `json:"schema_version"`
		Verifiers     []map[string]interface{} `json:"verifiers"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatalf("decode staged inventory: %v", err)
	}
	inventory.Verifiers = append(inventory.Verifiers, inventory.Verifiers[0])
	raw, err = json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encode duplicate inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, raw, 0o600); err != nil {
		t.Fatalf("write duplicate inventory: %v", err)
	}

	output, err := runReleaseVerifierInventory(t, root)
	if err == nil {
		t.Fatalf("duplicate inventory passed:\n%s", output)
	}
	if !strings.Contains(output, "incomplete or duplicate verifier inventory entry") ||
		!strings.Contains(output, "verifier inventory validation failed") {
		t.Fatalf("duplicate inventory error = %q", output)
	}
}

func TestReleaseVerifierInventoryAcceptsCompleteInventory(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	output, err := runReleaseVerifierInventory(t, root)
	if err != nil {
		t.Fatalf("complete inventory failed: %v\n%s", err, output)
	}
	for _, language := range []string{"Go", "TypeScript", "Rust", "Python"} {
		if !strings.Contains(output, language) {
			t.Errorf("inventory output missing %s: %q", language, output)
		}
	}
}

func TestReleaseVerifierInventoryRejectsPackageSubstitution(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	inventoryPath := filepath.Join(root, "release", "verifier-installers.json")
	raw, err := os.ReadFile(inventoryPath) // #nosec G304 -- fixed inventory path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged inventory: %v", err)
	}
	var inventory struct {
		SchemaVersion int                      `json:"schema_version"`
		Verifiers     []map[string]interface{} `json:"verifiers"`
	}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatalf("decode staged inventory: %v", err)
	}
	for _, verifier := range inventory.Verifiers {
		if verifier["language"] == "TypeScript" {
			verifier["package"] = "@vendor/lookalike"
		}
	}
	raw, err = json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encode substituted inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, raw, 0o600); err != nil {
		t.Fatalf("write substituted inventory: %v", err)
	}

	output, err := runReleaseVerifierInventory(t, root)
	if err == nil {
		t.Fatalf("substituted package passed:\n%s", output)
	}
	if !strings.Contains(output, "unexpected TypeScript verifier publication contract") {
		t.Fatalf("substitution error = %q", output)
	}
}

func TestReleaseVerifierInventoryRejectsSourceVersionDrift(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	manifestPath := filepath.Join(root, "sdk", "verifiers", "ts", "package.json")
	raw, err := os.ReadFile(manifestPath) // #nosec G304 -- fixed manifest path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged manifest: %v", err)
	}
	var manifest map[string]interface{}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("decode staged manifest: %v", err)
	}
	manifest["version"] = "9.9.9"
	raw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatalf("encode drifted manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatalf("write drifted manifest: %v", err)
	}

	output, err := runReleaseVerifierInventory(t, root)
	if err == nil {
		t.Fatalf("source version drift passed:\n%s", output)
	}
	if !strings.Contains(output, "source manifests declare") {
		t.Fatalf("source drift error = %q", output)
	}
}

func TestReleaseVerifierInventoryRejectsLockRootDriftWithPythonOptimize(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	lockPath := filepath.Join(root, "sdk", "verifiers", "ts", "package-lock.json")
	raw, err := os.ReadFile(lockPath) // #nosec G304 -- fixed lockfile path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged lockfile: %v", err)
	}
	var lock map[string]interface{}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatalf("decode staged lockfile: %v", err)
	}
	packages, ok := lock["packages"].(map[string]interface{})
	if !ok {
		t.Fatal("staged lockfile packages is not an object")
	}
	rootPackage, ok := packages[""].(map[string]interface{})
	if !ok {
		t.Fatal("staged lockfile root package is not an object")
	}
	rootPackage["version"] = "9.9.9"
	raw, err = json.Marshal(lock)
	if err != nil {
		t.Fatalf("encode drifted lockfile: %v", err)
	}
	if err := os.WriteFile(lockPath, raw, 0o600); err != nil {
		t.Fatalf("write drifted lockfile: %v", err)
	}

	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "release-verifier-install-gate.sh"), // #nosec G204 -- executes the checked-in script copied under t.TempDir.
		"--tag", "v3.4.0", "--inventory-only")
	command.Env = append(os.Environ(), "PYTHONOPTIMIZE=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("lockfile root drift passed with Python optimization enabled:\n%s", output)
	}
	if !strings.Contains(string(output), "package-lock root version mismatch") {
		t.Fatalf("lockfile drift error = %q", output)
	}
}

func TestReleaseVerifierInstallGateRejectsMissingVerifierTag(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "release-verifier-install-gate.sh"), // #nosec G204 -- executes the checked-in script copied under t.TempDir.
		"--tag", "v3.4.0")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("missing verifier tag passed:\n%s", output)
	}
	if !strings.Contains(string(output), "required verifier release tag is missing") {
		t.Fatalf("missing tag error = %q", output)
	}
}

func TestReleaseVerifierInstallGateRejectsVerifierThatAcceptsTampering(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	verifier := filepath.Join(root, "accept-all")
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- executable permission is required for this test fixture.
		t.Fatalf("write verifier: %v", err)
	}
	valid := filepath.Join(root, "valid.json")
	tampered := filepath.Join(root, "tampered.json")
	for _, path := range []string{valid, tampered} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write receipt: %v", err)
		}
	}

	command := exec.CommandContext(t.Context(), "bash", "-c", // #nosec G204 -- command text is constant and arguments are test-owned temp paths.
		`source "$1"; verify_accepts_and_rejects Test "$2" "$3" "00" "$4"`,
		"bash", filepath.Join(root, "scripts", "release-verifier-install-gate-lib.sh"), valid, tampered, verifier)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier that accepts tampering passed:\n%s", output)
	}
	if !strings.Contains(string(output), "ACCEPTED the tampered candidate receipt") {
		t.Fatalf("tamper error = %q", output)
	}
}

func stageReleaseVerifierInventoryTest(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Dir(filepath.Dir(sourceFile))
	root := t.TempDir()
	for _, relativePath := range []string{
		"scripts/release-verifier-install-gate.sh",
		"scripts/release-verifier-install-gate-lib.sh",
		"release/verifier-installers.json",
		"sdk/verifiers/ts/package.json",
		"sdk/verifiers/ts/package-lock.json",
		"sdk/verifiers/rust/Cargo.toml",
		"sdk/verifiers/rust/Cargo.lock",
	} {
		raw, err := os.ReadFile(filepath.Join(repoRoot, relativePath)) // #nosec G304 -- relativePath comes from the fixed list above.
		if err != nil {
			t.Fatalf("read %s: %v", relativePath, err)
		}
		target := filepath.Join(root, relativePath)
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			t.Fatalf("create staged directory: %v", err)
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatalf("stage %s: %v", relativePath, err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Pipelock Test"},
		{"config", "user.email", "test@pipelock.invalid"},
		{"add", "scripts/release-verifier-install-gate.sh", "scripts/release-verifier-install-gate-lib.sh", "release/verifier-installers.json", "sdk/verifiers/ts/package.json", "sdk/verifiers/ts/package-lock.json", "sdk/verifiers/rust/Cargo.toml", "sdk/verifiers/rust/Cargo.lock"},
		{"commit", "-q", "-m", "test fixture"},
	} {
		command := exec.CommandContext(t.Context(), "git", args...) // #nosec G204 -- args come from the fixed fixture command list above.
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	return root
}

func runReleaseVerifierInventory(t *testing.T, root string) (string, error) {
	t.Helper()
	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "release-verifier-install-gate.sh"), // #nosec G204 -- executes the checked-in script copied under t.TempDir.
		"--tag", "v3.4.0", "--inventory-only")
	output, err := command.CombinedOutput()
	return string(output), err
}
