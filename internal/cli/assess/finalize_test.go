// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/cli/audit"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/report/attestation"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// setupCompletedRun creates a completed assessment run directory with evidence.
// Returns runDir for finalize testing.
func setupCompletedRun(t *testing.T) string {
	t.Helper()

	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, nil); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	// Verify status is completed before continuing.
	m := readTestManifest(t, runDir)
	if m.Status != assessStatusCompleted {
		t.Fatalf("expected completed status, got %q", m.Status)
	}
	return runDir
}

// setupCompletedRunWithSkip creates a completed run with a skipped primitive.
func setupCompletedRunWithSkip(t *testing.T) string {
	t.Helper()

	runDir, _ := initTestRun(t)

	if err := runAssessRun(runDir, false, []string{primitiveVerifyInstall}); err != nil {
		t.Fatalf("runAssessRun: %v", err)
	}

	return runDir
}

// generateTestKeys creates a temporary keystore with a test agent key pair.
// Returns the keystore directory and agent name.
func generateTestKeys(t *testing.T) (keystoreDir, agentName string) {
	t.Helper()

	keystoreDir = filepath.Join(t.TempDir(), "keystore")
	agentName = "test-agent"

	ks := signing.NewKeystore(keystoreDir)
	if _, err := ks.GenerateAgent(agentName); err != nil {
		t.Fatalf("generating test keys: %v", err)
	}

	return keystoreDir, agentName
}

func TestCheckAssessLicenseFeatureGate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	t.Run("tokenless denies paid assessment", func(t *testing.T) {
		runDir, _ := initTestRun(t)

		if checkAssessLicense(runDir) {
			t.Fatal("tokenless assess gate returned true")
		}
	})

	t.Run("malformed token denies paid assessment", func(t *testing.T) {
		runDir, cfgFile := initTestRun(t)
		writeAssessLicenseConfig(t, cfgFile, "not-a-license-token", hex.EncodeToString(pub), "")

		if checkAssessLicense(runDir) {
			t.Fatal("malformed assess token returned true")
		}
	})

	t.Run("unloadable CRL denies otherwise-valid assessment", func(t *testing.T) {
		// A configured-but-broken CRL must fail closed: an unreadable
		// revocation list means we cannot prove the license is unrevoked,
		// so the paid path is denied rather than silently falling back to
		// a no-revocation Verify.
		runDir, cfgFile := initTestRun(t)
		token, _ := issueAssessGateToken(t, priv, []string{license.FeatureAssess}, time.Now().Add(time.Hour), false)
		missingCRL := filepath.Join(t.TempDir(), "nonexistent.crl.json")
		writeAssessLicenseConfig(t, cfgFile, token, hex.EncodeToString(pub), missingCRL)

		if checkAssessLicense(runDir) {
			t.Fatal("assess gate returned true with an unloadable CRL; CRL-load failure must fail closed")
		}
	})

	cases := []struct {
		name      string
		features  []string
		expiresAt time.Time
		revoked   bool
		want      bool
	}{
		{
			name:      "under-tier agents token denies paid assessment",
			features:  []string{license.FeatureAgents},
			expiresAt: time.Now().Add(time.Hour),
			want:      false,
		},
		{
			name:      "expired assess token denies paid assessment",
			features:  []string{license.FeatureAssess},
			expiresAt: time.Now().Add(-time.Hour),
			want:      false,
		},
		{
			name:      "revoked assess token denies paid assessment",
			features:  []string{license.FeatureAssess},
			expiresAt: time.Now().Add(time.Hour),
			revoked:   true,
			want:      false,
		},
		{
			name:      "assess feature allows paid assessment",
			features:  []string{license.FeatureAssess},
			expiresAt: time.Now().Add(time.Hour),
			want:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runDir, cfgFile := initTestRun(t)
			token, crlFile := issueAssessGateToken(t, priv, tc.features, tc.expiresAt, tc.revoked)
			writeAssessLicenseConfig(t, cfgFile, token, hex.EncodeToString(pub), crlFile)

			if got := checkAssessLicense(runDir); got != tc.want {
				t.Fatalf("checkAssessLicense() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAssessFinalize_LicenseControlsContentNotSigning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	tests := []struct {
		name          string
		configure     func(*testing.T, string)
		wantPaidFiles bool
	}{
		{
			name: "no license",
		},
		{
			name: "license without assess feature",
			configure: func(t *testing.T, cfgFile string) {
				token, _ := issueAssessGateToken(t, priv, []string{license.FeatureAgents}, time.Now().Add(time.Hour), false)
				writeAssessLicenseConfig(t, cfgFile, token, hex.EncodeToString(pub), "")
			},
		},
		{
			name: "license with assess feature",
			configure: func(t *testing.T, cfgFile string) {
				token, _ := issueAssessGateToken(t, priv, []string{license.FeatureAssess}, time.Now().Add(time.Hour), false)
				writeAssessLicenseConfig(t, cfgFile, token, hex.EncodeToString(pub), "")
			},
			wantPaidFiles: true,
		},
		{
			name: "expired assess token",
			configure: func(t *testing.T, cfgFile string) {
				token, _ := issueAssessGateToken(t, priv, []string{license.FeatureAssess}, time.Now().Add(-time.Hour), false)
				writeAssessLicenseConfig(t, cfgFile, token, hex.EncodeToString(pub), "")
			},
		},
		{
			name: "malformed token",
			configure: func(t *testing.T, cfgFile string) {
				writeAssessLicenseConfig(t, cfgFile, "not-a-license-token", hex.EncodeToString(pub), "")
			},
		},
	}

	for _, tt := range tests {
		for _, unsigned := range []bool{false, true} {
			name := "signed"
			if unsigned {
				name = "unsigned"
			}
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				t.Setenv("PIPELOCK_AGENT", "")
				runDir, cfgFile := initTestRun(t)
				if tt.configure != nil {
					tt.configure(t, cfgFile)
				}
				if err := runAssessRun(runDir, tt.configure != nil, nil); err != nil {
					t.Fatalf("runAssessRun: %v", err)
				}

				keystoreDir := filepath.Join(t.TempDir(), "keystore")
				args := []string{runDir, "--keystore", keystoreDir, "--attestation", "--badge"}
				if unsigned {
					args = append(args, "--unsigned")
				}
				cmd := assessFinalizeCmd()
				cmd.SetOut(io.Discard)
				cmd.SetArgs(args)
				if err := cmd.Execute(); err != nil {
					t.Fatalf("assess finalize: %v", err)
				}

				assertFileExists := func(name string, want bool) {
					t.Helper()
					_, statErr := os.Stat(filepath.Join(runDir, name))
					if want && statErr != nil {
						t.Errorf("%s missing: %v", name, statErr)
					}
					if !want && !errors.Is(statErr, os.ErrNotExist) {
						t.Errorf("%s exists but should be gated", name)
					}
				}
				assertFileExists("assessment.json", tt.wantPaidFiles)
				assertFileExists("assessment.html", tt.wantPaidFiles)
				assertFileExists("summary.json", !tt.wantPaidFiles)
				assertFileExists("summary.html", !tt.wantPaidFiles)
				assertFileExists("attestation.json", tt.wantPaidFiles && !unsigned)
				assertFileExists("attestation.json.sig", tt.wantPaidFiles && !unsigned)
				assertFileExists("badge.svg", tt.wantPaidFiles && !unsigned)
				assertFileExists("manifest.json.sig", !unsigned)

				ks := signing.NewKeystore(keystoreDir)
				if unsigned {
					if ks.AgentExists(assessDefaultSigningAgent) {
						t.Error("--unsigned must not generate signing keys")
					}
					exitCode, verifyErr := runAssessVerify(runDir, "", keystoreDir)
					if verifyErr != nil || exitCode != verifyExitUnsigned {
						t.Errorf("unsigned verification = (%d, %v), want (%d, nil)", exitCode, verifyErr, verifyExitUnsigned)
					}
				} else {
					if !ks.AgentExists(assessDefaultSigningAgent) {
						t.Error("default signing identity was not generated")
					}
					exitCode, verifyErr := runAssessVerify(runDir, "", keystoreDir)
					if verifyErr != nil || exitCode != 0 {
						t.Errorf("signed verification = (%d, %v), want (0, nil)", exitCode, verifyErr)
					}
				}

				outputPath := "summary.json"
				var signed bool
				if tt.wantPaidFiles {
					outputPath = "assessment.json"
					var assessment Assessment
					readJSONFile(t, filepath.Join(runDir, outputPath), &assessment)
					signed = assessment.Signed
				} else {
					var summary Summary
					readJSONFile(t, filepath.Join(runDir, outputPath), &summary)
					signed = summary.Signed
				}
				if signed == unsigned {
					t.Errorf("%s signed=%v, want %v", outputPath, signed, !unsigned)
				}
			})
		}
	}
}

func readJSONFile(t *testing.T, path string, dst interface{}) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("reading %s: %v", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatalf("parsing %s: %v", filepath.Base(path), err)
	}
}

func issueAssessGateToken(
	t *testing.T,
	priv ed25519.PrivateKey,
	features []string,
	expiresAt time.Time,
	revoked bool,
) (token, crlFile string) {
	t.Helper()
	now := time.Now().UTC()
	lic := license.License{
		ID:        "assess-gate-test",
		Email:     "test@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		Features:  features,
		Tier:      "test",
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatalf("license.Issue: %v", err)
	}
	if !revoked {
		return token, ""
	}
	crl, err := license.SignCRL(license.CRLPayload{
		Version:   license.CRLVersion,
		IssuedAt:  now.Add(-time.Minute).Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        lic.ID,
			Reason:    "test revocation",
			RevokedAt: now.Unix(),
		}},
	}, priv)
	if err != nil {
		t.Fatalf("license.SignCRL: %v", err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatalf("json.Marshal(CRL): %v", err)
	}
	crlFile = filepath.Join(t.TempDir(), "license.crl.json")
	if err := os.WriteFile(crlFile, data, 0o600); err != nil {
		t.Fatalf("os.WriteFile(CRL): %v", err)
	}
	return token, crlFile
}

func writeAssessLicenseConfig(t *testing.T, cfgFile, token, publicKey, crlFile string) {
	t.Helper()
	lines := []string{
		"mode: audit",
		"license_key: " + strconv.Quote(token),
		"license_public_key: " + strconv.Quote(publicKey),
	}
	if crlFile != "" {
		lines = append(lines, "license_crl_file: "+strconv.Quote(crlFile))
	}
	if err := os.WriteFile(cfgFile, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile(config): %v", err)
	}
}

func TestAssessFinalize_Licensed_AutoSigns(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: assessment.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err != nil {
		t.Error("assessment.json not found after licensed finalize")
	}

	// Assert: assessment.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.html")); err != nil {
		t.Error("assessment.html not found after licensed finalize")
	}

	// Assert: manifest.json.sig exists.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err != nil {
		t.Error("manifest.json.sig not found after licensed finalize")
	}

	// Assert: verify.txt exists.
	if _, err := os.Stat(filepath.Join(runDir, "verify.txt")); err != nil {
		t.Error("verify.txt not found")
	}

	// Verify the signature is actually valid.
	ks := signing.NewKeystore(keystoreDir)
	pubKey, err := ks.LoadPublicKey(agentName)
	if err != nil {
		t.Fatalf("loading public key: %v", err)
	}
	if err := signing.VerifyFile(filepath.Join(runDir, "manifest.json"), "", pubKey); err != nil {
		t.Errorf("manifest signature verification failed: %v", err)
	}

	// Verify manifest status.
	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
	if m.LicenseTier != assessTierAssess {
		t.Errorf("LicenseTier = %q, want %q", m.LicenseTier, assessTierAssess)
	}
	if m.FinalizedAt == nil {
		t.Error("FinalizedAt must not be nil after finalize")
	}

	// Assert: NO summary files.
	if _, err := os.Stat(filepath.Join(runDir, "summary.json")); err == nil {
		t.Error("summary.json should not exist on licensed finalize")
	}
}

func TestCheckAssessLicense_IntermediateChain(t *testing.T) {
	now := time.Now().UTC()
	rootPub, rootPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intermediatePub, intermediatePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	im, err := license.SignIntermediate(license.IntermediatePayload{
		Serial:    "im_assess_valid",
		Purpose:   license.PurposeLicenseSigning,
		Algorithm: license.AlgorithmEd25519,
		PublicKey: hex.EncodeToString(intermediatePub),
		NotBefore: now.Add(-time.Minute).Unix(),
		NotAfter:  now.Add(time.Hour).Unix(),
		IssuedAt:  now.Add(-time.Minute).Unix(),
	}, rootPriv)
	if err != nil {
		t.Fatal(err)
	}
	certData, err := json.Marshal(im)
	if err != nil {
		t.Fatal(err)
	}

	runDir, cfgFile := initTestRun(t)
	certPath := filepath.Join(filepath.Dir(cfgFile), "intermediate.json")
	if err := os.WriteFile(certPath, certData, 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := license.Issue(license.License{
		ID:        "lic_assess_intermediate",
		Email:     "assess@example.com",
		Features:  []string{license.FeatureAssess},
		ExpiresAt: now.Add(time.Hour).Unix(),
	}, intermediatePriv)
	if err != nil {
		t.Fatal(err)
	}
	cfgData := "mode: audit\nlicense_key: " + token + "\nlicense_public_key: " + hex.EncodeToString(rootPub) + "\nlicense_intermediate_file: intermediate.json\n"
	if err := os.WriteFile(cfgFile, []byte(cfgData), 0o600); err != nil {
		t.Fatal(err)
	}
	if !checkAssessLicense(runDir) {
		t.Fatal("expected intermediate-signed assess license to be accepted")
	}

	if err := os.WriteFile(certPath, []byte("{bad json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if checkAssessLicense(runDir) {
		t.Fatal("expected malformed configured intermediate to deny assess license")
	}
}

func TestAssessFinalize_Licensed_Unsigned(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: true,
		Unsigned:  true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: assessment.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err != nil {
		t.Error("assessment.json not found")
	}

	// Assert: NO manifest.json.sig.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err == nil {
		t.Error("manifest.json.sig should not exist when --unsigned")
	}

	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
}

func TestAssessFinalize_FreeSummaryAutoSigns(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")

	opts := assessFinalizeOpts{
		HasAssess:   false,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Assert: summary.json exists.
	if _, err := os.Stat(filepath.Join(runDir, "summary.json")); err != nil {
		t.Error("summary.json not found after unlicensed finalize")
	}

	// Assert: summary.html exists.
	if _, err := os.Stat(filepath.Join(runDir, "summary.html")); err != nil {
		t.Error("summary.html not found after unlicensed finalize")
	}

	// Assert: NO assessment.json.
	if _, err := os.Stat(filepath.Join(runDir, "assessment.json")); err == nil {
		t.Error("assessment.json should not exist on unlicensed finalize")
	}

	// Free content is signed with a first-run identity by default.
	if _, err := os.Stat(filepath.Join(runDir, "manifest.json.sig")); err != nil {
		t.Error("manifest.json.sig not found on free finalize")
	}
	if !signing.NewKeystore(keystoreDir).AgentExists(assessDefaultSigningAgent) {
		t.Error("default assessment signing identity was not generated")
	}
	exitCode, err := runAssessVerify(runDir, "", keystoreDir)
	if err != nil || exitCode != 0 {
		t.Errorf("free manifest verification = (%d, %v), want (0, nil)", exitCode, err)
	}
	var summary Summary
	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.json")))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}
	if !summary.Signed {
		t.Error("free summary must report signed=true after successful signing")
	}

	m := readTestManifest(t, runDir)
	if m.LicenseTier != assessTierFree {
		t.Errorf("LicenseTier = %q, want %q", m.LicenseTier, assessTierFree)
	}
}

func TestAssessFinalize_SummaryNoLeakedFields(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.json")))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}

	// Unmarshal as generic map to check for leaked fields.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}

	// Summary should NOT have "findings" (full findings), "sources", or "annexes".
	for _, forbidden := range []string{"findings", "sources", "annexes", "cap_reasons", "weights"} {
		if _, ok := raw[forbidden]; ok {
			t.Errorf("summary.json contains forbidden field %q", forbidden)
		}
	}

	// Check top_findings have no remediation or evidence fields.
	if tfRaw, ok := raw["top_findings"]; ok {
		var topFindings []map[string]json.RawMessage
		if err := json.Unmarshal(tfRaw, &topFindings); err != nil {
			t.Fatalf("parsing top_findings: %v", err)
		}
		for i, tf := range topFindings {
			for _, leaked := range []string{"remediation", "evidence", "detail"} {
				if _, ok := tf[leaked]; ok {
					t.Errorf("top_findings[%d] contains leaked field %q", i, leaked)
				}
			}
		}
	}

	// Check discover finding IDs don't leak server/client names.
	if tfRaw2, ok := raw["top_findings"]; ok {
		var findings []map[string]json.RawMessage
		if err := json.Unmarshal(tfRaw2, &findings); err != nil {
			t.Fatalf("parsing top_findings for ID check: %v", err)
		}
		for i, tf := range findings {
			var id, source string
			if idRaw, ok := tf["id"]; ok {
				if err := json.Unmarshal(idRaw, &id); err != nil {
					t.Fatalf("top_findings[%d] id unmarshal: %v", i, err)
				}
			}
			if srcRaw, ok := tf["source"]; ok {
				if err := json.Unmarshal(srcRaw, &source); err != nil {
					t.Fatalf("top_findings[%d] source unmarshal: %v", i, err)
				}
			}
			if source == sourceDiscover && !strings.HasPrefix(id, "find-discover-redacted-") {
				t.Errorf("top_findings[%d] discover ID %q leaks server name (expected find-discover-redacted-*)", i, id)
			}
		}
	}

	// Check sections have no detail field.
	if secRaw, ok := raw["sections"]; ok {
		var sections []map[string]json.RawMessage
		if err := json.Unmarshal(secRaw, &sections); err != nil {
			t.Fatalf("parsing sections: %v", err)
		}
		for i, sec := range sections {
			if detailRaw, ok := sec["detail"]; ok {
				// detail may be present as empty string (omitempty drops it) or absent.
				var detail string
				if err := json.Unmarshal(detailRaw, &detail); err == nil && detail != "" {
					t.Errorf("sections[%d] has non-empty detail %q", i, detail)
				}
			}
		}
	}
}

func TestRedactDiscoverTitle(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{assessSevHigh, "A high-risk MCP server is unprotected"},
		{assessSevMedium, "An MCP server is unprotected"},
		{assessSevLow, "An MCP server is unprotected"},
		{assessSevCritical, "An MCP server is unprotected"},
		{assessSevInfo, "An MCP server is unprotected"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := redactDiscoverTitle(tt.severity)
			if got != tt.want {
				t.Errorf("redactDiscoverTitle(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestAssessFinalize_ManifestArtifactHashes(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	m := readTestManifest(t, runDir)
	if len(m.Artifacts) == 0 {
		t.Fatal("manifest.Artifacts should not be empty after finalize")
	}

	// Verify each artifact hash matches actual file content.
	for name, expectedHash := range m.Artifacts {
		path := filepath.Join(runDir, name)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Errorf("reading artifact %s: %v", name, err)
			continue
		}
		sum := sha256.Sum256(data)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != expectedHash {
			t.Errorf("artifact %s: hash mismatch (manifest=%s, actual=%s)", name, expectedHash[:12], actualHash[:12])
		}
	}

	// Verify specific artifacts are present.
	expectedArtifacts := []string{"summary.json", "summary.html"}
	for _, name := range expectedArtifacts {
		if _, ok := m.Artifacts[name]; !ok {
			t.Errorf("missing artifact hash for %s", name)
		}
	}
}

func TestAssessFinalize_SkippedWithoutAllowPartial(t *testing.T) {
	runDir := setupCompletedRunWithSkip(t)

	opts := assessFinalizeOpts{
		HasAssess:    false,
		AllowPartial: false,
	}

	err := runAssessFinalize(runDir, opts)
	if err == nil {
		t.Fatal("expected error for skipped primitives without --allow-partial, got nil")
	}

	if !strings.Contains(err.Error(), "skipped primitives") {
		t.Errorf("error should mention skipped primitives, got: %v", err)
	}
}

func TestAssessFinalize_SkippedWithAllowPartial(t *testing.T) {
	runDir := setupCompletedRunWithSkip(t)

	opts := assessFinalizeOpts{
		HasAssess:    false,
		AllowPartial: true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize with AllowPartial: %v", err)
	}

	m := readTestManifest(t, runDir)
	if m.Status != assessStatusFinalized {
		t.Errorf("Status = %q, want %q", m.Status, assessStatusFinalized)
	}
	if !m.AllowPartial {
		t.Error("AllowPartial should be true in manifest")
	}
}

func TestAssessFinalize_AlreadyFinalized(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	// First finalize should succeed.
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("first runAssessFinalize: %v", err)
	}

	// Second finalize should fail.
	err := runAssessFinalize(runDir, opts)
	if err == nil {
		t.Fatal("expected error on second finalize, got nil")
	}
	if !strings.Contains(err.Error(), "already finalized") {
		t.Errorf("error should say 'already finalized', got: %v", err)
	}
}

func TestAssessFinalize_Archive(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
		Archive:   true,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize with archive: %v", err)
	}

	// Find the archive file in the parent directory.
	parent := filepath.Dir(runDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading parent dir: %v", err)
	}

	var archivePath string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "summary-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			archivePath = filepath.Join(parent, e.Name())
			break
		}
	}
	if archivePath == "" {
		t.Fatal("archive .tar.gz not found")
	}

	// Verify it's a valid tar.gz.
	f, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	var fileNames []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		fileNames = append(fileNames, hdr.Name)
	}

	if len(fileNames) == 0 {
		t.Error("archive is empty")
	}

	// Should contain manifest.json at minimum.
	foundManifest := false
	for _, name := range fileNames {
		if strings.HasSuffix(name, "manifest.json") {
			foundManifest = true
			break
		}
	}
	if !foundManifest {
		t.Error("archive does not contain manifest.json")
	}
}

func TestAssessFinalize_ArchiveLicensed(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Archive:     true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Licensed archive should be named "assessment-*".
	parent := filepath.Dir(runDir)
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("reading parent dir: %v", err)
	}

	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "assessment-") && strings.HasSuffix(e.Name(), ".tar.gz") {
			found = true
			break
		}
	}
	if !found {
		t.Error("licensed archive should be named assessment-*.tar.gz")
	}
}

func TestAssessFinalize_ReadEvidenceSources(t *testing.T) {
	runDir := setupCompletedRun(t)

	sources, err := readEvidenceSources(runDir)
	if err != nil {
		t.Fatalf("readEvidenceSources: %v", err)
	}

	if sources.Simulate == nil {
		t.Error("Simulate source should not be nil")
	}
	if sources.AuditScore == nil {
		t.Error("AuditScore source should not be nil")
	}
	if sources.VerifyInstall == nil {
		t.Error("VerifyInstall source should not be nil")
	}
	if sources.Discover == nil {
		t.Error("Discover source should not be nil")
	}
}

func TestAssessFinalize_ReadEvidenceSources_MissingFiles(t *testing.T) {
	// Create a minimal run dir with no evidence files.
	tmp := t.TempDir()
	runDir := filepath.Join(tmp, "empty-run")
	if err := os.MkdirAll(filepath.Join(runDir, "evidence"), 0o750); err != nil {
		t.Fatalf("creating evidence dir: %v", err)
	}

	sources, err := readEvidenceSources(runDir)
	if err != nil {
		t.Fatalf("readEvidenceSources: %v", err)
	}

	// All sources should be nil (missing files = skipped primitives).
	if sources.Simulate != nil {
		t.Error("Simulate should be nil with missing evidence")
	}
	if sources.AuditScore != nil {
		t.Error("AuditScore should be nil with missing evidence")
	}
	if sources.VerifyInstall != nil {
		t.Error("VerifyInstall should be nil with missing evidence")
	}
	if sources.Discover != nil {
		t.Error("Discover should be nil with missing evidence")
	}
}

func TestAssessFinalize_ProjectToSummary(t *testing.T) {
	assessment := Assessment{
		SchemaVersion: assessSchemaVersion,
		OverallGrade:  assessGradeB,
		OverallScore:  85,
		GradeCap:      "",
		Sections: []AssessmentSection{
			{ID: sectionDetectionCoverage, Name: "Detection Coverage", Score: 90, MaxScore: 100, Detail: "18/20 detected"},
			{ID: sectionConfigPosture, Name: "Config Posture", Score: 80, MaxScore: 100, Detail: "80/100 points"},
		},
		Findings: []Finding{
			{ID: "find-1", Severity: assessSevCritical, Category: "DLP", Source: sourceSimulate, Title: "Missed leak", Remediation: "Add pattern", Evidence: json.RawMessage(`{"test":true}`)},
			{ID: "find-2", Severity: assessSevHigh, Category: "SSRF", Source: sourceSimulate, Title: "SSRF bypass"},
			{ID: "find-3", Severity: assessSevMedium, Category: "Config", Source: sourceAuditScore, Title: "Weak config"},
			{ID: "find-4", Severity: assessSevLow, Category: "Info", Source: sourceAuditScore, Title: "Low info"},
		},
		Sources: AssessSources{
			Simulate: &audit.SimulateResult{Percentage: 90},
			Discover: &AssessDiscoverReport{
				Summary: AssessDiscoverSummary{},
			},
		},
	}

	summary := projectToSummary(assessment)

	// Sections should have empty Detail.
	for _, s := range summary.Sections {
		if s.Detail != "" {
			t.Errorf("section %q Detail should be empty in summary, got %q", s.ID, s.Detail)
		}
	}

	// Top 3 findings only.
	if len(summary.TopFindings) != 3 {
		t.Fatalf("TopFindings count = %d, want 3", len(summary.TopFindings))
	}

	// TopFindings should be highest severity first.
	if summary.TopFindings[0].Severity != assessSevCritical {
		t.Errorf("first TopFinding severity = %q, want %q", summary.TopFindings[0].Severity, assessSevCritical)
	}

	// DetectionPct.
	if summary.DetectionPct != 90 {
		t.Errorf("DetectionPct = %d, want 90", summary.DetectionPct)
	}

	// Signed is always false for summary.
	if summary.Signed {
		t.Error("Signed should be false for summary")
	}
}

func TestAssessFinalize_ProjectToSummary_FewerThan3Findings(t *testing.T) {
	assessment := Assessment{
		SchemaVersion: assessSchemaVersion,
		Findings: []Finding{
			{ID: "only-one", Severity: assessSevHigh, Title: "Single finding"},
		},
		Sources: AssessSources{},
	}

	summary := projectToSummary(assessment)

	if len(summary.TopFindings) != 1 {
		t.Errorf("TopFindings count = %d, want 1", len(summary.TopFindings))
	}
}

func TestAssessFinalize_ReconstructSimulateResult(t *testing.T) {
	scenarios := []audit.ScenarioResult{
		{Name: "test1", Category: "DLP", Detected: true},
		{Name: "test2", Category: "DLP", Detected: false},
		{Name: "test3", Category: "DLP", Detected: true, Limitation: true},
	}

	result := reconstructSimulateResult(scenarios)
	if result == nil {
		t.Fatal("result should not be nil")
	}
	if result.Total != 3 {
		t.Errorf("Total = %d, want 3", result.Total)
	}
	if result.Passed != 1 {
		t.Errorf("Passed = %d, want 1", result.Passed)
	}
	if result.Failed != 1 {
		t.Errorf("Failed = %d, want 1", result.Failed)
	}
	if result.KnownLimits != 1 {
		t.Errorf("KnownLimits = %d, want 1", result.KnownLimits)
	}
	// Applicable = 3-1 = 2, percentage = (1*100)/2 = 50.
	if result.Percentage != 50 {
		t.Errorf("Percentage = %d, want 50", result.Percentage)
	}
}

func TestAssessFinalize_ReconstructSimulateResult_Empty(t *testing.T) {
	result := reconstructSimulateResult(nil)
	if result != nil {
		t.Error("empty scenarios should return nil")
	}

	result = reconstructSimulateResult([]audit.ScenarioResult{})
	if result != nil {
		t.Error("zero-length scenarios should return nil")
	}
}

func TestAssessFinalize_SplitJSONLines(t *testing.T) {
	input := []byte("{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n")
	lines := splitJSONLines(input)
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	// Verify each is valid JSON.
	for i, line := range lines {
		if !json.Valid(line) {
			t.Errorf("line %d is not valid JSON: %s", i, string(line))
		}
	}
}

func TestAssessFinalize_SplitJSONLines_NoTrailingNewline(t *testing.T) {
	input := []byte("{\"a\":1}\n{\"b\":2}")
	lines := splitJSONLines(input)
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
}

func TestAssessFinalize_MissingManifest(t *testing.T) {
	tmp := t.TempDir()
	err := runAssessFinalize(tmp, assessFinalizeOpts{})
	if err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestAssessFinalize_WrongStatus(t *testing.T) {
	runDir, _ := initTestRun(t)

	// Manifest is in "initialized" status, not "completed".
	err := runAssessFinalize(runDir, assessFinalizeOpts{})
	if err == nil {
		t.Fatal("expected error for wrong status")
	}
	if !strings.Contains(err.Error(), "initialized") {
		t.Errorf("error should mention current status, got: %v", err)
	}
}

func TestAssessFinalize_VerifyTxtContent(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "verify.txt")))
	if err != nil {
		t.Fatalf("reading verify.txt: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "Pipelock Assessment Verification") {
		t.Error("verify.txt missing header")
	}
	if !strings.Contains(content, "Run ID:") {
		t.Error("verify.txt missing Run ID")
	}
	if !strings.Contains(content, "pipelock assess verify") {
		t.Error("verify.txt missing verify command")
	}
}

func TestAssessFinalize_VerifyTxtFilename(t *testing.T) {
	t.Run("free tier references summary.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)
		if err := runAssessFinalize(runDir, assessFinalizeOpts{HasAssess: false}); err != nil {
			t.Fatalf("runAssessFinalize free: %v", err)
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "verify.txt")))
		if err != nil {
			t.Fatalf("reading verify.txt: %v", err)
		}
		if !strings.Contains(string(data), "summary.html") {
			t.Error("free-tier verify.txt should reference summary.html")
		}
		if strings.Contains(string(data), "assessment.html") {
			t.Error("free-tier verify.txt should not reference assessment.html")
		}
	})

	t.Run("paid tier references assessment.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)
		keystoreDir, agentName := generateTestKeys(t)
		opts := assessFinalizeOpts{
			HasAssess:   true,
			Agent:       agentName,
			KeystoreDir: keystoreDir,
		}
		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize paid: %v", err)
		}
		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "verify.txt")))
		if err != nil {
			t.Fatalf("reading verify.txt: %v", err)
		}
		if !strings.Contains(string(data), "assessment.html") {
			t.Error("paid-tier verify.txt should reference assessment.html")
		}
	})
}

func TestAssessFinalize_HTMLFilesCreated(t *testing.T) {
	t.Run("licensed produces assessment.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)
		keystoreDir, agentName := generateTestKeys(t)

		opts := assessFinalizeOpts{
			HasAssess:   true,
			Agent:       agentName,
			KeystoreDir: keystoreDir,
		}

		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize: %v", err)
		}

		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "assessment.html")))
		if err != nil {
			t.Fatalf("reading assessment.html: %v", err)
		}
		if !strings.Contains(string(data), "<html") {
			t.Error("assessment.html should be valid HTML")
		}
		if !strings.Contains(string(data), "Pipelock Security Assessment") {
			t.Error("assessment.html should contain title")
		}
	})

	t.Run("unlicensed produces summary.html", func(t *testing.T) {
		runDir := setupCompletedRun(t)

		opts := assessFinalizeOpts{
			HasAssess: false,
		}

		if err := runAssessFinalize(runDir, opts); err != nil {
			t.Fatalf("runAssessFinalize: %v", err)
		}

		data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.html")))
		if err != nil {
			t.Fatalf("reading summary.html: %v", err)
		}
		if !strings.Contains(string(data), "Signed summary") {
			t.Error("summary.html should report its signed state")
		}
	})
}

func TestAssessFinalize_FilePermissions(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	filesToCheck := []string{"summary.json", "summary.html", "verify.txt", "manifest.json"}
	for _, name := range filesToCheck {
		path := filepath.Join(runDir, name)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stat %s: %v", name, err)
			continue
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s permissions = %o, want 0600", name, perm)
		}
	}
}

func TestAssessFinalize_EvidenceHashes(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	m := readTestManifest(t, runDir)

	// At least one evidence file should be hashed.
	evidenceHashFound := false
	for name := range m.Artifacts {
		if strings.HasPrefix(name, "evidence/") {
			evidenceHashFound = true
			break
		}
	}
	if !evidenceHashFound {
		t.Error("manifest.Artifacts should contain evidence file hashes")
	}
}

// TestAssessFinalize_RoundTrip verifies the full init -> run -> finalize flow
// produces a valid, internally consistent assessment.
func TestAssessFinalize_RoundTrip(t *testing.T) {
	runDir := setupCompletedRun(t)

	opts := assessFinalizeOpts{
		HasAssess: false,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// Read and verify summary.json.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.json")))
	if err != nil {
		t.Fatalf("reading summary.json: %v", err)
	}

	var summary Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary.json: %v", err)
	}

	if summary.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", summary.SchemaVersion, assessSchemaVersion)
	}
	if summary.OverallGrade == "" {
		t.Error("OverallGrade should not be empty")
	}
	if summary.Manifest.Status != assessStatusFinalized {
		t.Errorf("Manifest.Status = %q, want %q", summary.Manifest.Status, assessStatusFinalized)
	}
}

// TestAssessFinalize_AssessmentRoundTrip verifies the licensed path produces valid assessment JSON.
func TestAssessFinalize_AssessmentRoundTrip(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	}

	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "assessment.json")))
	if err != nil {
		t.Fatalf("reading assessment.json: %v", err)
	}

	var assessment Assessment
	if err := json.Unmarshal(data, &assessment); err != nil {
		t.Fatalf("parsing assessment.json: %v", err)
	}

	if assessment.SchemaVersion != assessSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", assessment.SchemaVersion, assessSchemaVersion)
	}
	if len(assessment.Sections) != 4 {
		t.Errorf("Sections count = %d, want 4", len(assessment.Sections))
	}
	if assessment.Sources.Simulate == nil {
		t.Error("Sources.Simulate should not be nil in full assessment")
	}
}

func TestAssessFinalize_CreateTarGz(t *testing.T) {
	tmp := t.TempDir()
	sourceDir := filepath.Join(tmp, "source")
	if err := os.MkdirAll(filepath.Join(sourceDir, "sub"), 0o750); err != nil {
		t.Fatalf("creating source dirs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "file1.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing file1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "sub", "file2.txt"), []byte("world"), 0o600); err != nil {
		t.Fatalf("writing file2: %v", err)
	}

	archivePath := filepath.Join(tmp, "test.tar.gz")
	if err := createTarGz(archivePath, sourceDir); err != nil {
		t.Fatalf("createTarGz: %v", err)
	}

	// Verify archive contents.
	f, err := os.Open(filepath.Clean(archivePath))
	if err != nil {
		t.Fatalf("opening archive: %v", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("reading tar: %v", err)
		}
		names = append(names, hdr.Name)
	}

	// Should contain source dir, sub dir, and two files.
	if len(names) < 3 {
		t.Errorf("archive has %d entries, want at least 3: %v", len(names), names)
	}
}

func TestRewriteAssessmentArtifacts_Success(t *testing.T) {
	dir := t.TempDir()

	// Write initial artifacts with Signed=true.
	a := minimalAssessment(assessGradeB, 85)
	a.Signed = true
	if err := writeAssessmentJSON(filepath.Join(dir, "assessment.json"), a); err != nil {
		t.Fatalf("initial write JSON: %v", err)
	}
	if err := writeAssessmentHTML(filepath.Join(dir, "assessment.html"), a); err != nil {
		t.Fatalf("initial write HTML: %v", err)
	}

	// Rewrite with Signed=false.
	a.Signed = false
	artifacts := make(map[string]string)
	rewriteFinalizedArtifacts(dir, a, true, artifacts)

	// Verify JSON has Signed=false.
	data, err := os.ReadFile(filepath.Clean(filepath.Join(dir, "assessment.json")))
	if err != nil {
		t.Fatalf("reading rewritten JSON: %v", err)
	}
	if strings.Contains(string(data), `"signed": true`) {
		t.Error("rewritten assessment.json should have signed=false")
	}

	// Verify hashes were updated.
	if _, ok := artifacts["assessment.json"]; !ok {
		t.Error("artifacts should contain assessment.json hash")
	}
	if _, ok := artifacts["assessment.html"]; !ok {
		t.Error("artifacts should contain assessment.html hash")
	}
}

func TestRewriteAssessmentArtifacts_DeletesOnFailure(t *testing.T) {
	// Use a subdirectory that we can make read-only without affecting
	// t.TempDir() cleanup. The key insight: we need the parent writable
	// (for Remove) but the subdir read-only (to fail the write).
	parent := t.TempDir()
	dir := filepath.Join(parent, "run")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Write initial artifacts.
	a := minimalAssessment(assessGradeB, 85)
	a.Signed = true
	jsonPath := filepath.Join(dir, "assessment.json")
	htmlPath := filepath.Join(dir, "assessment.html")
	if err := writeAssessmentJSON(jsonPath, a); err != nil {
		t.Fatalf("initial write JSON: %v", err)
	}
	if err := writeAssessmentHTML(htmlPath, a); err != nil {
		t.Fatalf("initial write HTML: %v", err)
	}

	// Replace the JSON artifact with an empty directory. Writing to a path that
	// is a directory fails on every supported platform, where a read-only file
	// does not: Windows ignores the mode and so does root. The directory is
	// empty, so the purge step can still remove it and the assertions below
	// stay meaningful.
	if err := os.Remove(jsonPath); err != nil {
		t.Fatalf("removing json artifact: %v", err)
	}
	if err := os.Mkdir(jsonPath, 0o750); err != nil {
		t.Fatalf("creating directory at json path: %v", err)
	}

	a.Signed = false
	artifacts := make(map[string]string)
	rewriteFinalizedArtifacts(dir, a, true, artifacts)

	// Stale artifacts should be deleted since rewrite failed.
	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Error("assessment.json should be deleted after failed rewrite")
	}
	if _, err := os.Stat(htmlPath); !os.IsNotExist(err) {
		t.Error("assessment.html should be deleted after failed rewrite")
	}
}

func TestRewriteSummaryArtifacts_ErrorPathsPurgeSignedOutputs(t *testing.T) {
	tests := []struct {
		name       string
		blockedOut string
	}{
		{name: "json rewrite fails", blockedOut: "summary.json"},
		{name: "html rewrite fails", blockedOut: "summary.html"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			blockedPath := filepath.Join(dir, tt.blockedOut)
			if err := os.Mkdir(blockedPath, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blockedPath, "keep"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			other := "summary.html"
			if tt.blockedOut == other {
				other = "summary.json"
			}
			if err := os.WriteFile(filepath.Join(dir, other), []byte("stale signed output"), 0o600); err != nil {
				t.Fatal(err)
			}

			a := minimalAssessment(assessGradeB, 85)
			a.Signed = false
			artifacts := map[string]string{"summary.json": "stale", "summary.html": "stale"}
			rewriteFinalizedArtifacts(dir, a, false, artifacts)

			if _, ok := artifacts["summary.json"]; ok {
				t.Error("summary.json hash retained after rollback rewrite failure")
			}
			if _, ok := artifacts["summary.html"]; ok {
				t.Error("summary.html hash retained after rollback rewrite failure")
			}
			if _, err := os.Stat(filepath.Join(dir, other)); !errors.Is(err, os.ErrNotExist) {
				t.Error("stale counterpart was not purged")
			}
		})
	}
}

func TestRemoveStaleSignature(t *testing.T) {
	t.Run("removes regular signature", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json.sig")
		if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeStaleSignature(path); err != nil {
			t.Fatalf("removeStaleSignature: %v", err)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Error("stale signature was not removed")
		}
	})

	t.Run("refuses nonempty directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "manifest.json.sig")
		if err := os.Mkdir(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "entry"), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeStaleSignature(path); err == nil || !strings.Contains(err.Error(), "removing stale") {
			t.Errorf("removeStaleSignature error = %v, want wrapped removal failure", err)
		}
	})
}

func TestRecordArtifactHash(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), []byte("summary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string]string)
	if err := recordArtifactHash(dir, "summary.json", artifacts); err != nil {
		t.Fatalf("recordArtifactHash: %v", err)
	}
	want, err := hashFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := artifacts["summary.json"]; got != want {
		t.Errorf("recorded hash = %q, want %q", got, want)
	}
	if err := recordArtifactHash(dir, "missing.json", artifacts); err == nil || !strings.Contains(err.Error(), "hashing missing.json") {
		t.Errorf("missing artifact error = %v, want named hashing failure", err)
	}
}

func TestAssessFinalize_PartialSigningIdentityFailsClosed(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	ks := signing.NewKeystore(keystoreDir)
	if _, err := ks.GenerateAgent("partial-agent"); err != nil {
		t.Fatalf("generating test identity: %v", err)
	}
	if err := os.Remove(ks.PublicKeyPath("partial-agent")); err != nil {
		t.Fatalf("removing public half: %v", err)
	}

	opts := assessFinalizeOpts{
		HasAssess:   true,
		Agent:       "partial-agent",
		KeystoreDir: keystoreDir,
	}

	err := runAssessFinalize(runDir, opts)
	if err == nil {
		t.Fatal("expected signing failure")
	}
	if !strings.Contains(err.Error(), "loading public key") {
		t.Errorf("expected key loading error, got: %v", err)
	}

	// The identity is resolved before anything is rendered, so a failure here
	// must leave no report at all. Accepting "either absent, or present and
	// unsigned" would let a regression that renders a signed report slip
	// through on the second branch.
	jsonPath := filepath.Join(runDir, "assessment.json")
	if _, statErr := os.Stat(jsonPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("assessment.json exists after a signing-identity failure (stat err = %v), want no report written", statErr)
	}
}

func TestAssessFinalize_FreeSignatureSaveFailureClearsSignedClaim(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)
	sigPath := filepath.Join(runDir, "manifest.json.sig")
	// A directory at the signature path makes the save fail. Keeping it empty
	// lets the rollback remove it, so the cleanup half of the rollback runs
	// and can be asserted rather than silently failing.
	if err := os.Mkdir(sigPath, 0o750); err != nil {
		t.Fatalf("creating signature-path directory: %v", err)
	}

	err := runAssessFinalize(runDir, assessFinalizeOpts{
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	})
	if err == nil || !strings.Contains(err.Error(), "saving signature") {
		t.Fatalf("runAssessFinalize error = %v, want signature-save failure", err)
	}

	var summary Summary
	readJSONFile(t, filepath.Join(runDir, "summary.json"), &summary)
	if summary.Signed {
		t.Error("summary retained signed=true after detached signature save failed")
	}

	// The signer fields describe a signature that was never published. A
	// rolled-back bundle that still names a key and a fingerprint claims
	// provenance it does not have.
	rolledBack := readTestManifest(t, runDir)
	if rolledBack.SignerAgent != "" || rolledBack.SignerKeyFingerprint != "" {
		t.Errorf("rolled-back manifest still names a signer: agent=%q fingerprint=%q",
			rolledBack.SignerAgent, rolledBack.SignerKeyFingerprint)
	}

	// Nothing may remain at the signature path, or a later verify would treat
	// the bundle as signed and fail on a signature that was never written.
	if _, statErr := os.Stat(sigPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("detached signature path survived rollback (stat err = %v)", statErr)
	}

	// The end state a reader actually encounters: intact, and honestly unsigned.
	exitCode, verifyErr := runAssessVerify(runDir, agentName, keystoreDir)
	if verifyErr != nil {
		t.Fatalf("verifying rolled-back bundle: %v", verifyErr)
	}
	if exitCode != verifyExitUnsigned {
		t.Errorf("verify exit = %d, want %d (integrity intact, no signature)", exitCode, verifyExitUnsigned)
	}
	html, readErr := os.ReadFile(filepath.Clean(filepath.Join(runDir, "summary.html")))
	if readErr != nil {
		t.Fatalf("reading summary.html: %v", readErr)
	}
	if strings.Contains(string(html), "Signed summary") {
		t.Error("summary.html retained a signed claim after signature save failed")
	}

	manifest := readTestManifest(t, runDir)
	wantHash, hashErr := hashFile(filepath.Join(runDir, "summary.json"))
	if hashErr != nil {
		t.Fatalf("hashing summary.json: %v", hashErr)
	}
	if got := manifest.Artifacts["summary.json"]; got != wantHash {
		t.Errorf("summary hash after rollback = %q, want %q", got, wantHash)
	}
}

func TestAssessFinalize_AttestationSignatureFailureClearsSignedClaim(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir, agentName := generateTestKeys(t)
	attSigPath := filepath.Join(runDir, "attestation.json.sig")
	if err := os.Mkdir(attSigPath, 0o750); err != nil {
		t.Fatalf("creating attestation signature-path directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(attSigPath, "block-rename"), []byte("x"), 0o600); err != nil {
		t.Fatalf("making attestation signature-path directory non-empty: %v", err)
	}

	err := runAssessFinalize(runDir, assessFinalizeOpts{
		HasAssess:   true,
		Attestation: true,
		Agent:       agentName,
		KeystoreDir: keystoreDir,
	})
	if err == nil || !strings.Contains(err.Error(), "saving attestation signature") {
		t.Fatalf("runAssessFinalize error = %v, want attestation signature-save failure", err)
	}

	var assessment Assessment
	readJSONFile(t, filepath.Join(runDir, "assessment.json"), &assessment)
	if assessment.Signed {
		t.Error("assessment retained signed=true after attestation signature save failed")
	}
	manifest := readTestManifest(t, runDir)
	if _, ok := manifest.Artifacts["attestation.json"]; ok {
		t.Error("rolled-back manifest retained a torn attestation artifact")
	}
	if _, statErr := os.Stat(filepath.Join(runDir, "manifest.json.sig")); !errors.Is(statErr, os.ErrNotExist) {
		t.Error("manifest signature exists after attestation signing failed")
	}
}

func TestAssessFinalize_SignedFreeRerunPreservesIdentityAndBundle(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	opts := assessFinalizeOpts{KeystoreDir: keystoreDir}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("first finalize: %v", err)
	}

	ks := signing.NewKeystore(keystoreDir)
	pubBefore, err := ks.LoadPublicKey(assessDefaultSigningAgent)
	if err != nil {
		t.Fatalf("loading generated public key: %v", err)
	}
	manifestBefore, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "manifest.json")))
	if err != nil {
		t.Fatalf("reading manifest before rerun: %v", err)
	}
	sigBefore, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "manifest.json.sig")))
	if err != nil {
		t.Fatalf("reading signature before rerun: %v", err)
	}

	err = runAssessFinalize(runDir, opts)
	if err == nil || !strings.Contains(err.Error(), "already finalized") {
		t.Fatalf("second finalize error = %v, want already finalized", err)
	}
	pubAfter, err := ks.LoadPublicKey(assessDefaultSigningAgent)
	if err != nil {
		t.Fatalf("loading public key after rerun: %v", err)
	}
	manifestAfter, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "manifest.json")))
	if err != nil {
		t.Fatalf("reading manifest after rerun: %v", err)
	}
	sigAfter, err := os.ReadFile(filepath.Clean(filepath.Join(runDir, "manifest.json.sig")))
	if err != nil {
		t.Fatalf("reading signature after rerun: %v", err)
	}
	if !bytes.Equal(pubBefore, pubAfter) || !bytes.Equal(manifestBefore, manifestAfter) || !bytes.Equal(sigBefore, sigAfter) {
		t.Error("rerun changed an existing finalized identity or signed bundle")
	}
}

func TestAssessFinalize_SignedPartialSummaryIsSelfDescribing(t *testing.T) {
	runDir := setupCompletedRunWithSkip(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")
	if err := runAssessFinalize(runDir, assessFinalizeOpts{
		AllowPartial: true,
		KeystoreDir:  keystoreDir,
	}); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	var summary Summary
	readJSONFile(t, filepath.Join(runDir, "summary.json"), &summary)
	if !summary.Signed || summary.Manifest.Version == "" || summary.Manifest.ConfigFile == "" || summary.Manifest.ConfigHash == "" {
		t.Errorf("summary identity incomplete: signed=%v version=%q config=%q hash=%q", summary.Signed, summary.Manifest.Version, summary.Manifest.ConfigFile, summary.Manifest.ConfigHash)
	}
	if summary.Manifest.ScoringVersion == "" || summary.Manifest.RendererVersion == "" || summary.Manifest.Platform == "" {
		t.Errorf("summary method identity incomplete: scoring=%q renderer=%q platform=%q", summary.Manifest.ScoringVersion, summary.Manifest.RendererVersion, summary.Manifest.Platform)
	}
	if !summary.Manifest.AllowPartial || len(summary.Manifest.SkippedPrimitives) != 1 || summary.Manifest.SkippedPrimitives[0] != primitiveVerifyInstall {
		t.Errorf("summary scope = allow_partial:%v skipped:%v", summary.Manifest.AllowPartial, summary.Manifest.SkippedPrimitives)
	}
	if summary.Manifest.ComplianceOmittedReason == "" {
		t.Error("summary omitted the reason for a non-assessed compliance claim")
	}
	if len(summary.Manifest.EvidenceHashes) == 0 || len(summary.Sections) != 4 {
		t.Errorf("summary validation/metric vector incomplete: evidence=%d sections=%d", len(summary.Manifest.EvidenceHashes), len(summary.Sections))
	}
	if exitCode, verifyErr := runAssessVerify(runDir, "", keystoreDir); verifyErr != nil || exitCode != 0 {
		t.Errorf("signed partial summary verification = (%d, %v), want (0, nil)", exitCode, verifyErr)
	}
}

func TestProjectToSummary_CapReason(t *testing.T) {
	a := minimalAssessment(assessGradeD, 85)
	a.GradeCap = assessGradeD
	a.CapReasons = []CapReason{
		{Cap: assessGradeC, Reason: "unprotected server", Source: sourceDiscover},
		{Cap: assessGradeD, Reason: "0% detection in DLP", Source: sourceSimulate},
	}

	summary := projectToSummary(*a)
	if summary.CapReason != "0% detection in DLP" {
		t.Errorf("summary.CapReason = %q, want effective D reason", summary.CapReason)
	}
}

func TestProjectToSummary_NoCapReason(t *testing.T) {
	a := minimalAssessment(assessGradeA, 95)
	summary := projectToSummary(*a)
	if summary.CapReason != "" {
		t.Errorf("summary.CapReason should be empty when no cap, got %q", summary.CapReason)
	}
}

// TestAssessFinalize_RecordsSignerIdentity asserts the signed manifest names
// the key that signed it. Without this, verification only establishes that the
// bundle matches whatever key the verifier happens to hold under the agent
// name, which on a copied bundle is a different key or no key at all.
func TestAssessFinalize_RecordsSignerIdentity(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")

	if err := runAssessFinalize(runDir, assessFinalizeOpts{KeystoreDir: keystoreDir}); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	var manifest AssessManifest
	readJSONFile(t, filepath.Join(runDir, "manifest.json"), &manifest)

	if manifest.SignerAgent != assessDefaultSigningAgent {
		t.Errorf("SignerAgent = %q, want %q", manifest.SignerAgent, assessDefaultSigningAgent)
	}
	pub, err := signing.NewKeystore(keystoreDir).ResolvePublicKey(assessDefaultSigningAgent)
	if err != nil {
		t.Fatalf("resolving generated public key: %v", err)
	}
	if want := attestation.KeyFingerprint(pub); manifest.SignerKeyFingerprint != want {
		t.Errorf("SignerKeyFingerprint = %q, want %q", manifest.SignerKeyFingerprint, want)
	}
}

// TestAssessFinalize_UnsignedRecordsNoSigner keeps the negative honest: an
// --unsigned bundle must not name a signer it does not have.
func TestAssessFinalize_UnsignedRecordsNoSigner(t *testing.T) {
	runDir := setupCompletedRun(t)
	keystoreDir := filepath.Join(t.TempDir(), "keystore")

	opts := assessFinalizeOpts{Unsigned: true, KeystoreDir: keystoreDir}
	if err := runAssessFinalize(runDir, opts); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	var manifest AssessManifest
	readJSONFile(t, filepath.Join(runDir, "manifest.json"), &manifest)

	if manifest.SignerAgent != "" || manifest.SignerKeyFingerprint != "" {
		t.Errorf("unsigned manifest named a signer: agent=%q fingerprint=%q",
			manifest.SignerAgent, manifest.SignerKeyFingerprint)
	}
}

// TestAssessVerify_RejectsSubstitutedSignerKey is the reason the fingerprint is
// recorded. A bundle is copied to a machine that already holds a DIFFERENT key
// under the same agent name. Verification must refuse and say so, rather than
// failing with an opaque signature error or, worse, succeeding if the attacker
// also re-signs under the substituted key.
func TestAssessVerify_RejectsSubstitutedSignerKey(t *testing.T) {
	runDir := setupCompletedRun(t)
	originalKeystore := filepath.Join(t.TempDir(), "keystore")

	if err := runAssessFinalize(runDir, assessFinalizeOpts{KeystoreDir: originalKeystore}); err != nil {
		t.Fatalf("runAssessFinalize: %v", err)
	}

	// A different machine: same agent name, different key material.
	otherKeystore := filepath.Join(t.TempDir(), "other-keystore")
	if _, err := signing.NewKeystore(otherKeystore).GenerateAgent(assessDefaultSigningAgent); err != nil {
		t.Fatalf("generating substitute identity: %v", err)
	}

	exitCode, err := runAssessVerify(runDir, "", otherKeystore)
	if err == nil {
		t.Fatal("verification succeeded against a substituted signer key")
	}
	if exitCode != verifyExitBadSignature {
		t.Errorf("exit code = %d, want %d", exitCode, verifyExitBadSignature)
	}
	if !strings.Contains(err.Error(), "signer key mismatch") {
		t.Errorf("error = %q, want it to name the signer key mismatch", err)
	}
}
