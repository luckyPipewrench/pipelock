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
	"reflect"
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
	for _, name := range []string{receiptFileName, tamperedFileName, signatureTamperedFileName, keyFileName} {
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
		{name: "signature-tampered receipt", blocker: signatureTamperedFileName, want: "write signature-tampered receipt"},
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

	signatureTamperedRaw, err := os.ReadFile(filepath.Join(dir, signatureTamperedFileName)) // #nosec G304 -- fixed fixture name under t.TempDir.
	if err != nil {
		t.Fatalf("read signature-tampered receipt: %v", err)
	}
	signatureTampered, err := receipt.Unmarshal(signatureTamperedRaw)
	if err != nil {
		t.Fatalf("unmarshal signature-tampered receipt: %v", err)
	}
	if !reflect.DeepEqual(signatureTampered.ActionRecord, valid.ActionRecord) {
		t.Fatal("signature tamper changed the signed payload")
	}
	if err := receipt.VerifyWithKey(signatureTampered, publicKey); err == nil {
		t.Fatal("signature-tampered fixture receipt verified")
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
		SchemaVersion  int                      `json:"schema_version"`
		ReleaseBlocked bool                     `json:"release_blocked"`
		Verifiers      []map[string]interface{} `json:"verifiers"`
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
		SchemaVersion  int                      `json:"schema_version"`
		ReleaseBlocked bool                     `json:"release_blocked"`
		Verifiers      []map[string]interface{} `json:"verifiers"`
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

// rewriteStagedVerifierInventory rewrites the staged inventory through its JSON
// structure. A fixture must set the state it asserts on rather than inheriting
// whatever the real release currently holds, because the real file legitimately
// changes across a release cycle.
func rewriteStagedVerifierInventory(t *testing.T, root string, apply func(inventory map[string]interface{})) {
	t.Helper()
	inventoryPath := filepath.Join(root, "release", "verifier-installers.json")
	raw, err := os.ReadFile(inventoryPath) // #nosec G304 -- fixed inventory path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged inventory: %v", err)
	}
	var inventory map[string]interface{}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatalf("decode staged inventory: %v", err)
	}
	apply(inventory)
	raw, err = json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encode staged inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, raw, 0o600); err != nil {
		t.Fatalf("write staged inventory: %v", err)
	}
}

// setStagedVerifierSourceCommits pins the named languages' publisher source
// commit. It fails when a named language is absent so a renamed or removed entry
// surfaces as a test failure instead of leaving the fixture asserting nothing.
func setStagedVerifierSourceCommits(t *testing.T, inventory map[string]interface{}, commit string, languages ...string) {
	t.Helper()
	entries, ok := inventory["verifiers"].([]interface{})
	if !ok {
		t.Fatal("staged inventory has no verifiers array")
	}
	for _, language := range languages {
		found := false
		for _, entry := range entries {
			record, ok := entry.(map[string]interface{})
			if !ok || record["language"] != language {
				continue
			}
			publisher, ok := record["publisher"].(map[string]interface{})
			if !ok {
				t.Fatalf("%s entry has no publisher object", language)
			}
			publisher["source_commit"] = commit
			found = true
		}
		if !found {
			t.Fatalf("staged inventory has no %s verifier entry", language)
		}
	}
}

func TestReleaseVerifierInstallGateRejectsMissingVerifierTag(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	inventoryPath := filepath.Join(root, "release", "verifier-installers.json")
	raw, err := os.ReadFile(inventoryPath) // #nosec G304 -- fixed inventory path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged inventory: %v", err)
	}
	var inventory map[string]interface{}
	if err := json.Unmarshal(raw, &inventory); err != nil {
		t.Fatalf("decode staged inventory: %v", err)
	}
	inventory["release_blocked"] = false
	raw, err = json.Marshal(inventory)
	if err != nil {
		t.Fatalf("encode staged inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, raw, 0o600); err != nil {
		t.Fatalf("write staged inventory: %v", err)
	}
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

func TestReleaseVerifierInstallGateHonorsExplicitReleaseBlock(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	// Set the flag this test is named for instead of depending on the real
	// inventory still carrying it. Once a release records its published digests
	// and unblocks, an inventory staged verbatim reaches a different refusal and
	// this test stops exercising the release block at all.
	rewriteStagedVerifierInventory(t, root, func(inventory map[string]interface{}) {
		inventory["release_blocked"] = true
	})
	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "release-verifier-install-gate.sh"), // #nosec G204 -- executes the checked-in script copied under t.TempDir.
		"--tag", "v3.4.0")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("explicitly blocked release passed:\n%s", output)
	}
	if !strings.Contains(string(output), "release is explicitly blocked") {
		t.Fatalf("release block error = %q", output)
	}
}

func TestReleaseVerifierInstallGateRejectsPostTagSourceDrift(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	gitHome := t.TempDir()
	hooksDir := filepath.Join(gitHome, "empty-hooks")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("create empty hooks directory: %v", err)
	}
	runGit := func(args ...string) string {
		t.Helper()
		gitArgs := append([]string{"-c", "core.hooksPath=" + hooksDir}, args...)
		command := exec.CommandContext(t.Context(), "git", gitArgs...) // #nosec G204 -- arguments are fixed by this test.
		command.Dir = root
		command.Env = append(os.Environ(),
			"HOME="+gitHome,
			"GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_CONFIG_SYSTEM="+os.DevNull,
		)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
		return strings.TrimSpace(string(output))
	}

	tagCommit := runGit("rev-parse", "HEAD")
	runGit("tag", "verifier-v0.3.0")
	// Point the inventory at this fixture's own tag commit and unblock it, so the
	// gate reaches the source-drift check. These were find-and-replace edits
	// against REPLACE_WITH_* and `"release_blocked": true`; both silently became
	// no-ops once the real release recorded its published digests, and the gate
	// then failed earlier on a commit mismatch instead.
	rewriteStagedVerifierInventory(t, root, func(inventory map[string]interface{}) {
		inventory["release_blocked"] = false
		setStagedVerifierSourceCommits(t, inventory, tagCommit, "TypeScript", "Rust")
	})
	sourcePath := filepath.Join(root, "sdk", "verifiers", "ts", "src", "types.ts")
	source, err := os.ReadFile(sourcePath) // #nosec G304 -- fixed source path under t.TempDir.
	if err != nil {
		t.Fatalf("read staged source: %v", err)
	}
	if err := os.WriteFile(sourcePath, append(source, []byte("\n// post-tag drift\n")...), 0o600); err != nil {
		t.Fatalf("write staged source drift: %v", err)
	}
	runGit("add", "release/verifier-installers.json", "sdk/verifiers/ts/src/types.ts")
	runGit("-c", "user.name=Pipelock Test", "-c", "user.email=test@pipelock.invalid", "commit", "--no-gpg-sign", "-m", "post-tag drift")

	command := exec.CommandContext(t.Context(), "bash", filepath.Join(root, "scripts", "release-verifier-install-gate.sh"), // #nosec G204 -- executes the checked-in script copied under t.TempDir.
		"--tag", "v3.4.0")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("post-tag source drift passed:\n%s", output)
	}
	if !strings.Contains(string(output), "verifier package source differs from immutable tag") {
		t.Fatalf("source drift error = %q", output)
	}
}

func TestReleaseVerifierInstallGateRejectsVerifierThatAcceptsTampering(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	verifier := filepath.Join(root, "accept-all")
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil { // #nosec G306 -- executable permission is required for this test fixture.
		t.Fatalf("write verifier: %v", err)
	}
	valid := filepath.Join(root, "valid.json")
	payloadTampered := filepath.Join(root, "payload-tampered.json")
	signatureTampered := filepath.Join(root, "signature-tampered.json")
	for _, path := range []string{valid, payloadTampered, signatureTampered} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("write receipt: %v", err)
		}
	}

	command := exec.CommandContext(t.Context(), "bash", "-c", // #nosec G204 -- command text is constant and arguments are test-owned temp paths.
		`source "$1"; verify_accepts_and_rejects Test "$2" "$3" "$4" "00" "$5"`,
		"bash", filepath.Join(root, "scripts", "release-verifier-install-gate-lib.sh"), valid, payloadTampered, signatureTampered, verifier)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("verifier that accepts tampering passed:\n%s", output)
	}
	if !strings.Contains(string(output), "ACCEPTED the payload-tampered candidate receipt") {
		t.Fatalf("tamper error = %q", output)
	}
}

func TestReleaseVerifierInstallGateRejectsTargetAllowlistingFake(t *testing.T) {
	root := stageReleaseVerifierInventoryTest(t)
	verifier := filepath.Join(root, "target-allowlist-only")
	if err := os.WriteFile(verifier, []byte("#!/usr/bin/env bash\ngrep -q api.vendor.example \"$1\"\n"), 0o700); err != nil { // #nosec G306 -- executable permission is required for this test fixture.
		t.Fatalf("write verifier: %v", err)
	}
	valid := filepath.Join(root, "valid.json")
	payloadTampered := filepath.Join(root, "payload-tampered.json")
	signatureTampered := filepath.Join(root, "signature-tampered.json")
	for path, body := range map[string]string{
		valid:             `{"target":"https://api.vendor.example","signature":"good"}`,
		payloadTampered:   `{"target":"https://tampered.vendor.example","signature":"good"}`,
		signatureTampered: `{"target":"https://api.vendor.example","signature":"bad"}`,
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write receipt: %v", err)
		}
	}

	command := exec.CommandContext(t.Context(), "bash", "-c", // #nosec G204 -- command text is constant and arguments are test-owned temp paths.
		`source "$1"; verify_accepts_and_rejects Test "$2" "$3" "$4" "00" "$5"`,
		"bash", filepath.Join(root, "scripts", "release-verifier-install-gate-lib.sh"), valid, payloadTampered, signatureTampered, verifier)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("target-allowlisting fake passed:\n%s", output)
	}
	if !strings.Contains(string(output), "ACCEPTED the signature-tampered candidate receipt") {
		t.Fatalf("signature tamper error = %q", output)
	}
}

func stageReleaseVerifierInventoryTest(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("release verifier gate tests require bash")
	}
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	repoRoot := filepath.Dir(filepath.Dir(sourceFile))
	root := t.TempDir()
	stagedPaths := []string{
		"scripts/release-verifier-install-gate.sh",
		"scripts/release-verifier-install-gate-lib.sh",
		"scripts/ci-retry.sh",
		"release/verifier-installers.json",
		"sdk/verifiers/ts/package.json",
		"sdk/verifiers/ts/package-lock.json",
		"sdk/verifiers/ts/src/types.ts",
		"sdk/verifiers/rust/Cargo.toml",
		"sdk/verifiers/rust/Cargo.lock",
	}
	for _, relativePath := range stagedPaths {
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
	gitHome := t.TempDir()
	hooksDir := filepath.Join(gitHome, "empty-hooks")
	templateDir := filepath.Join(gitHome, "empty-template")
	if err := os.MkdirAll(hooksDir, 0o750); err != nil {
		t.Fatalf("create empty hooks directory: %v", err)
	}
	if err := os.MkdirAll(templateDir, 0o750); err != nil {
		t.Fatalf("create empty template directory: %v", err)
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.name", "Pipelock Test"},
		{"config", "user.email", "test@pipelock.invalid"},
		append([]string{"add"}, stagedPaths...),
		{"commit", "-q", "--no-gpg-sign", "-m", "test fixture"},
	} {
		gitArgs := append([]string{"-c", "core.hooksPath=" + hooksDir, "-c", "init.templateDir=" + templateDir}, args...)
		command := exec.CommandContext(t.Context(), "git", gitArgs...) // #nosec G204 -- args come from the fixed fixture command list above.
		command.Dir = root
		command.Env = append(os.Environ(),
			"HOME="+gitHome,
			"GIT_CONFIG_GLOBAL="+os.DevNull,
			"GIT_CONFIG_SYSTEM="+os.DevNull,
		)
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
