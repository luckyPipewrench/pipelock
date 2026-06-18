// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

const (
	testAllowSigner = "eb1a572975f35b452cfb04c215ac89cef2439af7c3c556f5904827739dd4a75e"
	testFixtureTS   = 1_700_000_000
)

func bundleTestReceipt(verdict, layer, method, target, pattern string) receipt.Receipt {
	return receipt.Receipt{
		Version: 1,
		ActionRecord: receipt.ActionRecord{
			Version:   1,
			ActionID:  "act-" + verdict,
			Verdict:   verdict,
			Layer:     layer,
			Method:    method,
			Target:    target,
			Transport: "forward",
			Pattern:   pattern,
			Timestamp: time.Unix(testFixtureTS, 0).UTC(),
		},
		Signature: "ed25519:deadbeef",
		SignerKey: testAllowSigner,
	}
}

func bundleTestReceipts() []receipt.Receipt {
	return []receipt.Receipt{
		bundleTestReceipt(liveDemoAllowedVerdict, "", "GET", "http://safe.target.test:1/", ""),
		bundleTestReceipt(liveDemoExpectedVerdict, liveDemoExpectedBlockLayer, "POST", "http://exfil.target.test:2/?run=x", "request body contains secret: AWS Access ID"),
	}
}

func TestShortKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, want string
	}{
		{"long", strings.Repeat("a", 64), "ed25519:aaaa…aa"},
		{"exactly7", "abcdef0", "ed25519:abcd…f0"},
		{"short", "abcd", "ed25519:abcd"},
		{"empty", "", "ed25519:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := shortKey(tc.in); got != tc.want {
				t.Fatalf("shortKey(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestShortNonce(t *testing.T) {
	t.Parallel()
	if got := shortNonce("short"); got != "short" {
		t.Fatalf("short nonce should pass through, got %q", got)
	}
	if got := shortNonce("playground-demo-run"); got != "playground-d…" {
		t.Fatalf("long nonce trim = %q", got)
	}
}

func TestFindReceipt(t *testing.T) {
	t.Parallel()
	rs := bundleTestReceipts()

	if _, ok := findReceipt(rs, liveDemoAllowedVerdict, ""); !ok {
		t.Fatal("allow receipt should be found")
	}
	if _, ok := findReceipt(rs, liveDemoExpectedVerdict, liveDemoExpectedBlockLayer); !ok {
		t.Fatal("body_dlp block receipt should be found")
	}
	if _, ok := findReceipt(rs, liveDemoExpectedVerdict, "core_dlp"); ok {
		t.Fatal("layer mismatch must not match")
	}
	if _, ok := findReceipt(rs, "warn", ""); ok {
		t.Fatal("absent verdict must not match")
	}
}

func TestReceiptEnvelopeLines(t *testing.T) {
	t.Parallel()
	lines := receiptEnvelopeLines(bundleTestReceipts()[1])
	if len(lines) < 3 {
		t.Fatalf("envelope should be multi-line JSON, got %d lines", len(lines))
	}
	if lines[0] != "{" {
		t.Fatalf("envelope should start with '{', got %q", lines[0])
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "body_dlp") || !strings.Contains(joined, "signer_key") {
		t.Fatalf("envelope must contain real receipt fields:\n%s", joined)
	}
}

func TestCheckNamesAndFailed(t *testing.T) {
	t.Parallel()
	rep := VerifyReport{Checks: []Check{
		{Name: "a", OK: true},
		{Name: "b", OK: false},
		{Name: "c", OK: true},
	}}
	names := checkNames(rep)
	if len(names) != 3 || names[1] != "b" {
		t.Fatalf("checkNames = %v", names)
	}
	if got := failedCheckNames(rep); got != "b" {
		t.Fatalf("failedCheckNames = %q want b", got)
	}
	if got := failedCheckNames(VerifyReport{}); !strings.Contains(got, "none reported") {
		t.Fatalf("empty report failed = %q", got)
	}
}

func TestHydrateAgentActs(t *testing.T) {
	t.Parallel()
	rs := bundleTestReceipts()

	// Uncontained: allow + block hydrated, bypass (beat 7) left empty.
	acts := hydrateAgentActs(liveDemoNarrative, rs, nil)
	byBeat := map[int]BundleAgentAct{}
	for _, a := range acts {
		byBeat[a.Beat] = a
	}
	if !strings.HasPrefix(byBeat[liveDemoNarrative.allowBeat].Line, "GET ") {
		t.Fatalf("allow act not hydrated: %+v", byBeat[liveDemoNarrative.allowBeat])
	}
	if !strings.HasPrefix(byBeat[liveDemoNarrative.blockBeat].Line, "POST ") {
		t.Fatalf("block act not hydrated: %+v", byBeat[liveDemoNarrative.blockBeat])
	}
	if byBeat[liveDemoNarrative.containDecision.beat-1].Line != "" {
		t.Fatal("bypass act must be empty without a host-containment witness")
	}

	// Contained: bypass act hydrated from the witness probe target.
	hcw := bundleTestHCW()
	acts = hydrateAgentActs(liveDemoNarrative, rs, &hcw)
	for _, a := range acts {
		if a.Beat == liveDemoNarrative.containDecision.beat-1 {
			if !strings.Contains(a.Line, hcw.AgentProbes[0].Target) {
				t.Fatalf("bypass act not hydrated from witness: %q", a.Line)
			}
		}
	}
}

func bundleTestHCW() HostContainmentWitness {
	return HostContainmentWitness{
		RunNonce:    "n",
		AgentProbes: []ProbeResult{{Target: "169.254.169.254:80", Blocked: true}, {Target: "10.0.0.1:443", Blocked: true}},
		ProbedAt:    time.Unix(testFixtureTS, 0).UTC(),
	}
}

func TestBuildDecisions(t *testing.T) {
	t.Parallel()
	rs := bundleTestReceipts()
	rep := VerifyReport{
		OrchestratorKey: strings.Repeat("0", 64),
		CollectorKey:    strings.Repeat("c", 64),
	}
	witness := Witness{RunNonce: "playground-demo-run", ObservedCount: 0}

	// Uncontained: allow, block, witness; no containment decision.
	d := buildDecisions(liveDemoNarrative, rs, rep, witness, nil)
	if len(d) != 3 {
		t.Fatalf("uncontained should yield 3 decisions, got %d: %+v", len(d), d)
	}
	if d[0].Verdict != "ALLOW" || d[0].Class != string(ClassPipelockDecision) {
		t.Fatalf("decision 0 = %+v", d[0])
	}
	if d[1].Verdict != "BLOCKED" || !d[1].Pop || len(d[1].Envelope) == 0 {
		t.Fatalf("block decision missing pop/envelope: %+v", d[1])
	}
	if !strings.Contains(d[1].Meta, "body_dlp") {
		t.Fatalf("block meta missing layer: %q", d[1].Meta)
	}
	if d[2].Class != string(ClassCollectorWitness) || !strings.Contains(d[2].Headline, "observed = 0") {
		t.Fatalf("witness decision = %+v", d[2])
	}

	// Contained: a host-containment decision is inserted before the witness.
	hcw := bundleTestHCW()
	dc := buildDecisions(liveDemoNarrative, rs, rep, witness, &hcw)
	if len(dc) != 4 {
		t.Fatalf("contained should yield 4 decisions, got %d", len(dc))
	}
	if dc[2].Class != string(ClassHostContainment) || dc[2].Signer != bundleSignerOrch {
		t.Fatalf("containment decision = %+v", dc[2])
	}
	if !strings.Contains(dc[2].Body, "2 direct-egress routes") {
		t.Fatalf("containment body should reflect probe count: %q", dc[2].Body)
	}
}

func TestBuildVerifier(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("a", 64)
	runDir := "/tmp/playground/nested/some-run-dir"
	v := buildVerifier(runDir, key)
	if v.Key != key {
		t.Fatalf("verifier key = %q", v.Key)
	}
	if !strings.HasPrefix(v.Fingerprint, "ed25519:") {
		t.Fatalf("fingerprint = %q", v.Fingerprint)
	}
	if !strings.Contains(v.Command, "verify "+runDir+" --orchestrator-key "+key) {
		t.Fatalf("command = %q", v.Command)
	}
}

func TestLoaders_FailClosed(t *testing.T) {
	t.Parallel()
	empty := t.TempDir()
	if _, err := loadWitness(empty); err == nil {
		t.Fatal("loadWitness must fail on missing file")
	}
	if _, err := loadHostContainmentWitness(empty); err == nil {
		t.Fatal("loadHostContainmentWitness must fail on missing file")
	}
	if _, err := loadLaunchManifest(empty); err == nil {
		t.Fatal("loadLaunchManifest must fail on missing file")
	}

	// Malformed JSON also fails closed.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, witnessFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadWitness(bad); err == nil {
		t.Fatal("loadWitness must fail on malformed JSON")
	}
	if err := os.WriteFile(filepath.Join(bad, hostContainmentWitnessFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHostContainmentWitness(bad); err == nil {
		t.Fatal("loadHostContainmentWitness must fail on malformed JSON")
	}
}

func TestOrchestratorKey_GenerateLoadRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sub", "demo.key")

	pubHex, err := GenerateOrchestratorKey(path, false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad pub hex %q (err %v)", pubHex, err)
	}

	priv, err := LoadOrchestratorSigningKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
		t.Fatal("loaded private key does not match generated public key")
	}

	// Refuses to overwrite without force.
	if _, err := GenerateOrchestratorKey(path, false); err == nil {
		t.Fatal("generate must refuse to overwrite an existing key without force")
	}
	// Force rotates.
	pub2, err := GenerateOrchestratorKey(path, true)
	if err != nil {
		t.Fatalf("force generate: %v", err)
	}
	if pub2 == pubHex {
		t.Fatal("force should produce a new key")
	}
	// Empty path errors.
	if _, err := GenerateOrchestratorKey("", false); err == nil {
		t.Fatal("empty path must error")
	}
}

func TestGenerateOrchestratorKey_ParentFileFailsClosed(t *testing.T) {
	t.Parallel()

	parentFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateOrchestratorKey(filepath.Join(parentFile, "demo.key"), false); err == nil {
		t.Fatal("generate must fail when parent path is a regular file")
	}
}

func TestGenerateOrchestratorKey_InvalidWriteTargetsFailClosed(t *testing.T) {
	t.Parallel()

	if _, err := GenerateOrchestratorKey("bad\x00key", false); err == nil {
		t.Fatal("generate must fail on an invalid key path")
	}
	if _, err := GenerateOrchestratorKey(t.TempDir(), true); err == nil {
		t.Fatal("force generate must fail when target path is a directory")
	}
}

type failingOrchestratorKeyFile struct {
	writeErr error
	closeErr error
}

func (f failingOrchestratorKeyFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return len(p), nil
}

func (f failingOrchestratorKeyFile) Close() error {
	return f.closeErr
}

func TestGenerateOrchestratorKey_WriteFailuresFailClosed(t *testing.T) {
	for name, fake := range map[string]failingOrchestratorKeyFile{
		"write": {writeErr: errors.New("write boom")},
		"close": {closeErr: errors.New("close boom")},
	} {
		t.Run(name, func(t *testing.T) {
			orig := openOrchestratorKeyFile
			t.Cleanup(func() { openOrchestratorKeyFile = orig })
			openOrchestratorKeyFile = func(string, int, os.FileMode) (orchestratorKeyFile, error) {
				return fake, nil
			}

			path := filepath.Join(t.TempDir(), "demo.key")
			if _, err := GenerateOrchestratorKey(path, false); err == nil {
				t.Fatal("generate must fail closed on write/close error")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("failed generate must not leave key file, stat err=%v", err)
			}
		})
	}
}

func TestDefaultOrchestratorKeyPath_UsesConfigDir(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "config")
	t.Setenv("XDG_CONFIG_HOME", configDir)

	want := filepath.Join(configDir, orchestratorKeyConfigDir, orchestratorKeyFileName)
	if got := DefaultOrchestratorKeyPath(); got != want {
		t.Fatalf("DefaultOrchestratorKeyPath() = %q, want %q", got, want)
	}
}

func TestDefaultOrchestratorKeyPath_NoConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "")

	if got := DefaultOrchestratorKeyPath(); got != "" {
		t.Fatalf("DefaultOrchestratorKeyPath() = %q, want empty without config dir", got)
	}
}

func TestLoadOrchestratorSigningKey_Errors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	if _, err := LoadOrchestratorSigningKey(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file must error")
	}

	badHex := filepath.Join(dir, "badhex")
	if err := os.WriteFile(badHex, []byte("nothex!!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrchestratorSigningKey(badHex); err == nil {
		t.Fatal("bad hex must error")
	}

	wrongSize := filepath.Join(dir, "wrongsize")
	if err := os.WriteFile(wrongSize, []byte(hex.EncodeToString([]byte("tooshort"))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrchestratorSigningKey(wrongSize); err == nil {
		t.Fatal("wrong key size must error")
	}

	degenerate := filepath.Join(dir, "degenerate")
	if err := os.WriteFile(degenerate, []byte(hex.EncodeToString(make([]byte, ed25519.PrivateKeySize))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrchestratorSigningKey(degenerate); err == nil {
		t.Fatal("degenerate orchestrator key must error")
	}

	loosePerms := filepath.Join(dir, "loose")
	if err := os.WriteFile(loosePerms, []byte(hex.EncodeToString(make([]byte, ed25519.PrivateKeySize))), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loosePerms, 0o644); err != nil { // #nosec G302 -- intentionally loose for key-permission regression.
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if _, err := LoadOrchestratorSigningKey(loosePerms); err == nil {
			t.Fatal("loose orchestrator key permissions must error")
		}
	}
}

func TestGenerateOrchestratorKey_ForceDoesNotFollowSymlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("do not overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "demo.key")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := GenerateOrchestratorKey(link, false); err == nil {
		t.Fatal("non-force generate must refuse an existing symlink path")
	}
	if _, err := GenerateOrchestratorKey(link, true); err != nil {
		t.Fatalf("force generate through symlink path: %v", err)
	}
	victimData, err := os.ReadFile(victim) // #nosec G304 -- test file under t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	if string(victimData) != "do not overwrite" {
		t.Fatalf("force generate followed symlink and overwrote victim: %q", string(victimData))
	}
	linkInfo, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if linkInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("force generate must replace the symlink itself with a regular key file")
	}
}

func TestOrchestratorKeyMatchesPublished(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if OrchestratorKeyMatchesPublished(priv) {
		t.Fatal("random private key must not match published key")
	}
}

func writeJSONFile(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadBundleArtifacts(t *testing.T) {
	t.Parallel()

	// Uncontained: witness only, no host-containment witness.
	unc := t.TempDir()
	writeJSONFile(t, filepath.Join(unc, witnessFile), Witness{RunNonce: "n", ObservedCount: 0})
	w, hcw, err := loadBundleArtifacts(unc, false)
	if err != nil || hcw != nil || w.RunNonce != "n" {
		t.Fatalf("uncontained: w=%+v hcw=%v err=%v", w, hcw, err)
	}

	// Contained: witness + host-containment witness present.
	con := t.TempDir()
	writeJSONFile(t, filepath.Join(con, witnessFile), Witness{RunNonce: "n"})
	writeJSONFile(t, filepath.Join(con, hostContainmentWitnessFile), bundleTestHCW())
	w, hcw, err = loadBundleArtifacts(con, true)
	if err != nil || hcw == nil || len(hcw.AgentProbes) != 2 {
		t.Fatalf("contained: w=%+v hcw=%v err=%v", w, hcw, err)
	}

	// Contained but missing host-containment witness: fail closed.
	if _, _, err := loadBundleArtifacts(unc, true); err == nil {
		t.Fatal("contained run missing host-containment witness must fail closed")
	}

	// Missing witness: fail closed.
	if _, _, err := loadBundleArtifacts(t.TempDir(), false); err == nil {
		t.Fatal("missing witness must fail closed")
	}
}

func TestGenerateBundle_FailsClosedOnCollaboratorErrors(t *testing.T) {
	t.Run("verify-error", func(t *testing.T) {
		origVerify := verifyRunForBundle
		t.Cleanup(func() { verifyRunForBundle = origVerify })
		verifyRunForBundle = func(string, string) (VerifyReport, error) {
			return VerifyReport{}, errors.New("verify boom")
		}

		if _, err := GenerateBundle(t.TempDir(), strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "verify run") {
			t.Fatalf("GenerateBundle verify error = %v, want wrapped failure", err)
		}
	})

	t.Run("extract-receipts-error", func(t *testing.T) {
		origVerify := verifyRunForBundle
		origExtract := extractReceiptsForBundle
		t.Cleanup(func() {
			verifyRunForBundle = origVerify
			extractReceiptsForBundle = origExtract
		})
		verifyRunForBundle = func(string, string) (VerifyReport, error) {
			return VerifyReport{OK: true}, nil
		}
		extractReceiptsForBundle = func(string) ([]receipt.Receipt, error) {
			return nil, errors.New("extract boom")
		}

		dir := t.TempDir()
		writeJSONFile(t, filepath.Join(dir, launchManifestFile), LaunchManifest{ScenarioID: LiveDemoScenarioID})
		if _, err := GenerateBundle(dir, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "extract receipts") {
			t.Fatalf("GenerateBundle extract error = %v, want wrapped failure", err)
		}
	})

	t.Run("load-artifacts-error", func(t *testing.T) {
		origVerify := verifyRunForBundle
		origExtract := extractReceiptsForBundle
		origLoad := loadBundleArtifactsForBundle
		t.Cleanup(func() {
			verifyRunForBundle = origVerify
			extractReceiptsForBundle = origExtract
			loadBundleArtifactsForBundle = origLoad
		})
		verifyRunForBundle = func(string, string) (VerifyReport, error) {
			return VerifyReport{OK: true}, nil
		}
		extractReceiptsForBundle = func(string) ([]receipt.Receipt, error) {
			return nil, nil
		}
		loadBundleArtifactsForBundle = func(string, bool) (Witness, *HostContainmentWitness, error) {
			return Witness{}, nil, errors.New("artifact boom")
		}

		dir := t.TempDir()
		writeJSONFile(t, filepath.Join(dir, launchManifestFile), LaunchManifest{ScenarioID: LiveDemoScenarioID})
		if _, err := GenerateBundle(dir, strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "artifact boom") {
			t.Fatalf("GenerateBundle artifact error = %v, want wrapped failure", err)
		}
	})
}

func TestRequestLine_EmptyMethod(t *testing.T) {
	t.Parallel()
	got := requestLine(receipt.ActionRecord{Target: "http://x/"})
	if got != "REQ http://x/" {
		t.Fatalf("empty-method request line = %q", got)
	}
}

func TestLoadLaunchManifest_Malformed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, launchManifestFile), []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLaunchManifest(dir); err == nil {
		t.Fatal("malformed launch manifest must error")
	}
}

func TestDefaultOrchestratorKeyPath(t *testing.T) {
	t.Parallel()
	// On a normal dev/CI host UserConfigDir resolves, so the path ends with the
	// stable filename. We assert the suffix rather than the absolute prefix.
	p := DefaultOrchestratorKeyPath()
	if p != "" && !strings.HasSuffix(p, filepath.Join(orchestratorKeyConfigDir, orchestratorKeyFileName)) {
		t.Fatalf("unexpected default key path %q", p)
	}
}
