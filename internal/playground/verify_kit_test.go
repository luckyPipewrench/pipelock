// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTempVerifier writes a stand-in verifier binary and returns its path.
func writeTempVerifier(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pipelock-verifier")
	if err := os.WriteFile(p, []byte("verifier"), 0o600); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	return p
}

// buildKitSession builds a gzip+tar session bundle for verify-kit tests. Each
// key in files is placed under the download archive prefix. withDirEntry adds a
// directory header (a non-regular entry the extractor must skip); withForeign
// adds a regular file outside the prefix (also skipped).
func buildKitSession(t *testing.T, files map[string]string, withDirEntry, withForeign bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	writeOne := func(name, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body))}); err != nil {
			t.Fatalf("header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if withDirEntry {
		if err := tw.WriteHeader(&tar.Header{Name: downloadArchivePrefix + "/packet/", Typeflag: tar.TypeDir, Mode: 0o750}); err != nil {
			t.Fatalf("dir header: %v", err)
		}
	}
	if withForeign {
		writeOne("some-other-root/ignored.txt", "ignored")
	}
	for name, body := range files {
		writeOne(downloadArchivePrefix+"/"+name, body)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// readZipEntry returns the contents of one named entry in a zip archive.
func readZipEntry(t *testing.T, zipBytes []byte, name string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		var b bytes.Buffer
		_, readErr := b.ReadFrom(rc)
		_ = rc.Close()
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		return b.String()
	}
	t.Fatalf("zip entry %q not found", name)
	return ""
}

// fullKitSessionFiles returns the minimal set of files for a valid kit session
// that includes all required run artifacts.
func fullKitSessionFiles() map[string]string {
	return map[string]string{
		"packet/packet.json":       `{"receipt_count":1}`,
		"packet/manifest.json":     `{"v":1}`,
		"packet/evidence.jsonl":    "{}\n",
		launchManifestFile:         `{"run_nonce":"n1"}`,
		witnessFile:                `{"observed_count":0}`,
		redWitnessFile:             `{"red":true}`,
		hostContainmentWitnessFile: `{"contained":true}`,
	}
}

func TestBuildLiveVerifyKit_IncludesAllRunArtifactsAndVerifier(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, true) // with containment witness
	session, err := ArchiveRunForDownload(dir, PublishedOrchestratorPubKeyHex)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	verifierPath := filepath.Join(t.TempDir(), "pipelock-verifier")
	if err := os.WriteFile(verifierPath, []byte("real verifier bytes"), 0o600); err != nil {
		t.Fatalf("write verifier: %v", err)
	}

	kit, filename, err := BuildLiveVerifyKit(VerifyKitOSLinux, verifierPath, session)
	if err != nil {
		t.Fatalf("BuildLiveVerifyKit: %v", err)
	}
	if filename != "pipelock-live-verify-linux.zip" {
		t.Fatalf("filename = %q", filename)
	}
	const kitRoot = "pipelock-live-verify-linux"

	zr, err := zip.NewReader(bytes.NewReader(kit), int64(len(kit)))
	if err != nil {
		t.Fatalf("zip reader: %v", err)
	}
	files := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip file %s: %v", f.Name, err)
		}
		var b bytes.Buffer
		if _, err := b.ReadFrom(rc); err != nil {
			_ = rc.Close()
			t.Fatalf("read zip file %s: %v", f.Name, err)
		}
		_ = rc.Close()
		files[f.Name] = b.String()
	}

	// Must include ALL run artifacts, not just the packet subset.
	for _, want := range []string{
		kitRoot + "/README.txt",
		kitRoot + "/verify.sh",
		kitRoot + "/app/pipelock-verifier",
		kitRoot + "/app/run/packet/packet.json",
		kitRoot + "/app/run/packet/manifest.json",
		kitRoot + "/app/run/packet/evidence.jsonl",
		kitRoot + "/app/run/" + launchManifestFile,
		kitRoot + "/app/run/" + witnessFile,
		kitRoot + "/app/run/" + redWitnessFile,
		kitRoot + "/app/run/" + hostContainmentWitnessFile,
		kitRoot + "/app/run/verifier.txt",
	} {
		if _, ok := files[want]; !ok {
			t.Fatalf("kit missing %q (have %v)", want, keysOf(files))
		}
	}
	if files[kitRoot+"/app/pipelock-verifier"] != "real verifier bytes" {
		t.Fatal("kit did not include the configured verifier binary bytes")
	}
	// The script must use the PUBLISHED key and the full verify-run command.
	script := files[kitRoot+"/verify.sh"]
	if !strings.Contains(script, "verify-run run --orchestrator-key "+PublishedOrchestratorPubKeyHex) {
		t.Fatalf("verify script missing full verify-run command with published key:\n%s", script)
	}
}

func TestBuildLiveVerifyKit_AlwaysUsesPublishedKey(t *testing.T) {
	t.Parallel()
	// Even when the bundle carries a different key, the kit must use the
	// published key. There is no fallback or extraction path.
	session := buildKitSession(t, fullKitSessionFiles(), false, false)

	kit, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session)
	if err != nil {
		t.Fatalf("BuildLiveVerifyKit: %v", err)
	}
	script := readZipEntry(t, kit, "pipelock-live-verify-linux/verify.sh")
	if !strings.Contains(script, PublishedOrchestratorPubKeyHex) {
		t.Fatalf("verify script does not contain the published key:\n%s", script)
	}
	verifierTxt := readZipEntry(t, kit, "pipelock-live-verify-linux/app/run/verifier.txt")
	if !strings.Contains(verifierTxt, PublishedOrchestratorPubKeyHex) {
		t.Fatalf("verifier.txt does not contain the published key:\n%s", verifierTxt)
	}
}

func TestBuildLiveVerifyKit_FailsClosedWithoutVerifier(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, "", []byte("not-used")); err == nil {
		t.Fatal("missing verifier path should fail closed")
	}
}

func TestPublishedKeyIsValid32ByteHex(t *testing.T) {
	t.Parallel()
	// Verify the published key constant is a valid 32-byte hex string.
	if len(PublishedOrchestratorPubKeyHex) != 64 {
		t.Fatalf("PublishedOrchestratorPubKeyHex length = %d, want 64", len(PublishedOrchestratorPubKeyHex))
	}
	for _, c := range PublishedOrchestratorPubKeyHex {
		isDigit := c >= '0' && c <= '9'
		isHexLower := c >= 'a' && c <= 'f'
		if !isDigit && !isHexLower {
			t.Fatalf("PublishedOrchestratorPubKeyHex contains non-hex char %q", c)
		}
	}
}

func TestParseVerifyKitOS(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"linux", "mac", "darwin", "windows", "win"} {
		if _, err := ParseVerifyKitOS(raw); err != nil {
			t.Fatalf("ParseVerifyKitOS(%q): %v", raw, err)
		}
	}
	if _, err := ParseVerifyKitOS("plan9"); err == nil {
		t.Fatal("unsupported OS should error")
	}
}

func TestVerifyKitBinaries_Path(t *testing.T) {
	t.Parallel()
	b := VerifyKitBinaries{Linux: "l", MacOS: "m", Windows: "w"}
	for os, want := range map[VerifyKitOS]string{
		VerifyKitOSLinux:   "l",
		VerifyKitOSMacOS:   "m",
		VerifyKitOSWindows: "w",
		VerifyKitOS("x86"): "",
	} {
		if got := b.Path(os); got != want {
			t.Fatalf("Path(%q) = %q, want %q", os, got, want)
		}
	}
}

func TestLiveKitReadmeAndScript_PerOS(t *testing.T) {
	t.Parallel()
	orchKey := PublishedOrchestratorPubKeyHex
	for _, osName := range []VerifyKitOS{VerifyKitOSLinux, VerifyKitOSMacOS, VerifyKitOSWindows} {
		t.Run(string(osName), func(t *testing.T) {
			if readme := liveKitReadme(osName); !strings.Contains(readme, "Pipelock") {
				t.Fatalf("readme(%q) missing brand: %q", osName, readme)
			}
			name, body, err := liveKitScript(osName, orchKey)
			if err != nil {
				t.Fatalf("liveKitScript(%q): %v", osName, err)
			}
			if name == "" || !strings.Contains(body, orchKey) {
				t.Fatalf("script(%q) name=%q missing key in body", osName, name)
			}
			if !strings.Contains(body, "verify-run") {
				t.Fatalf("script(%q) missing verify-run command: %s", osName, body)
			}
		})
	}
	if r := liveKitReadme(VerifyKitOS("x86")); !strings.Contains(r, "Linux") {
		t.Fatalf("default readme should fall back to Linux text: %q", r)
	}
	if _, _, err := liveKitScript(VerifyKitOS("x86"), orchKey); err == nil {
		t.Fatal("liveKitScript with unsupported OS should error")
	}
}

func TestBuildLiveVerifyKit_ReadVerifierError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	session, err := ArchiveRunForDownload(dir, PublishedOrchestratorPubKeyHex)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-verifier")
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, missing, session); err == nil {
		t.Fatal("unreadable verifier path should fail closed")
	}
}

func TestBuildLiveVerifyKit_WindowsAndMacOS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	session, err := ArchiveRunForDownload(dir, PublishedOrchestratorPubKeyHex)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	verifierPath := filepath.Join(t.TempDir(), "pipelock-verifier")
	if err := os.WriteFile(verifierPath, []byte("v"), 0o600); err != nil {
		t.Fatalf("write verifier: %v", err)
	}
	for _, tc := range []struct {
		osName   VerifyKitOS
		wantBin  string
		wantFile string
	}{
		{VerifyKitOSWindows, "pipelock-live-verify-windows/app/pipelock-verifier.exe", "pipelock-live-verify-windows.zip"},
		{VerifyKitOSMacOS, "pipelock-live-verify-macos/app/pipelock-verifier", "pipelock-live-verify-macos.zip"},
	} {
		t.Run(string(tc.osName), func(t *testing.T) {
			kit, filename, err := BuildLiveVerifyKit(tc.osName, verifierPath, session)
			if err != nil {
				t.Fatalf("BuildLiveVerifyKit(%q): %v", tc.osName, err)
			}
			if filename != tc.wantFile {
				t.Fatalf("filename(%q) = %q, want %q", tc.osName, filename, tc.wantFile)
			}
			zr, err := zip.NewReader(bytes.NewReader(kit), int64(len(kit)))
			if err != nil {
				t.Fatalf("zip reader(%q): %v", tc.osName, err)
			}
			found := false
			for _, f := range zr.File {
				if f.Name == tc.wantBin {
					found = true
				}
			}
			if !found {
				t.Fatalf("kit(%q) missing %q", tc.osName, tc.wantBin)
			}
		})
	}
}

func TestBuildLiveVerifyKit_RejectsGarbageSession(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), []byte("not a gzip stream")); err == nil {
		t.Fatal("non-gzip session bytes should fail closed")
	}
}

func TestBuildLiveVerifyKit_MissingRequiredFileFailsClosed(t *testing.T) {
	t.Parallel()
	// Missing launch-manifest.json: the kit must not ship a bundle that cannot
	// verify the full trust chain.
	incomplete := map[string]string{
		"packet/packet.json":    `{"receipt_count":1}`,
		"packet/manifest.json":  `{"v":1}`,
		"packet/evidence.jsonl": "{}\n",
		witnessFile:             `{"observed_count":0}`,
		redWitnessFile:          `{"red":true}`,
		// launchManifestFile is deliberately missing.
	}
	session := buildKitSession(t, incomplete, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session); err == nil {
		t.Fatal("missing launch-manifest.json should fail closed")
	}
}

func TestBuildLiveVerifyKit_MissingPacketFileFailsClosed(t *testing.T) {
	t.Parallel()
	// Missing packet/packet.json.
	incomplete := fullKitSessionFiles()
	delete(incomplete, "packet/packet.json")
	session := buildKitSession(t, incomplete, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session); err == nil {
		t.Fatal("missing packet file should fail closed")
	}
}

func TestBuildLiveVerifyKit_MissingWitnessFailsClosed(t *testing.T) {
	t.Parallel()
	incomplete := fullKitSessionFiles()
	delete(incomplete, witnessFile)
	session := buildKitSession(t, incomplete, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session); err == nil {
		t.Fatal("missing witness.json should fail closed")
	}
}

func TestBuildLiveVerifyKit_MissingRedWitnessFailsClosed(t *testing.T) {
	t.Parallel()
	incomplete := fullKitSessionFiles()
	delete(incomplete, redWitnessFile)
	session := buildKitSession(t, incomplete, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session); err == nil {
		t.Fatal("missing red-witness.json should fail closed")
	}
}

func TestBuildLiveVerifyKit_OptionalContainmentWitnessOK(t *testing.T) {
	t.Parallel()
	files := fullKitSessionFiles()
	delete(files, hostContainmentWitnessFile)
	session := buildKitSession(t, files, false, false)
	// Should succeed -- containment witness is optional.
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session); err != nil {
		t.Fatalf("missing optional containment witness should not fail: %v", err)
	}
}

func TestBuildLiveVerifyKit_ScriptRunsVerifyRunNotAuditPacket(t *testing.T) {
	t.Parallel()
	session := buildKitSession(t, fullKitSessionFiles(), true, true)
	kit, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session)
	if err != nil {
		t.Fatalf("BuildLiveVerifyKit: %v", err)
	}
	script := readZipEntry(t, kit, "pipelock-live-verify-linux/verify.sh")
	if strings.Contains(script, "audit-packet") {
		t.Fatalf("verify script should NOT use audit-packet (partial check):\n%s", script)
	}
	if !strings.Contains(script, "verify-run") {
		t.Fatalf("verify script should use verify-run (full chain):\n%s", script)
	}
}
