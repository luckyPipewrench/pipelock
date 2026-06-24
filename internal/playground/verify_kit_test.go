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

const validKitKey64 = "65c1e83850fe24c986f44bdd3a95360602d2f4f198f1c95e2d500d2b9495aaaf"

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

func TestBuildLiveVerifyKit_IncludesSessionPacketAndVerifier(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	const key = "65c1e83850fe24c986f44bdd3a95360602d2f4f198f1c95e2d500d2b9495aaaf"
	session, err := ArchiveRunForDownload(dir, key)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	verifierPath := filepath.Join(t.TempDir(), "pipelock-verifier")
	if err := os.WriteFile(verifierPath, []byte("real verifier bytes"), 0o600); err != nil {
		t.Fatalf("write verifier: %v", err)
	}

	kit, filename, err := BuildLiveVerifyKit(VerifyKitOSLinux, verifierPath, session, key)
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

	for _, want := range []string{
		kitRoot + "/README.txt",
		kitRoot + "/verify.sh",
		kitRoot + "/app/pipelock-verifier",
		kitRoot + "/app/packet/packet.json",
		kitRoot + "/app/packet/manifest.json",
		kitRoot + "/app/packet/evidence.jsonl",
		kitRoot + "/app/packet/verifier.txt",
		kitRoot + "/app/SESSION-VERIFY.txt",
	} {
		if _, ok := files[want]; !ok {
			t.Fatalf("kit missing %q (have %v)", want, keysOf(files))
		}
	}
	if files[kitRoot+"/app/pipelock-verifier"] != "real verifier bytes" {
		t.Fatal("kit did not include the configured verifier binary bytes")
	}
	script := files[kitRoot+"/verify.sh"]
	if !strings.Contains(script, "./pipelock-verifier audit-packet packet --key "+key) {
		t.Fatalf("verify script missing command/key:\n%s", script)
	}
}

func TestBuildLiveVerifyKit_FailsClosedWithoutVerifier(t *testing.T) {
	t.Parallel()
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, "", []byte("not-used"), "key"); err == nil {
		t.Fatal("missing verifier path should fail closed")
	}
}

func TestValidateLiveKitTrustKeyRejectsUnsafeKey(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"", "not-a-hex-key; touch /tmp/pwned", strings.Repeat("0", 62), strings.Repeat("0", 66)} {
		if _, err := validateLiveKitTrustKey(key); err == nil {
			t.Fatalf("validateLiveKitTrustKey(%q) succeeded, want error", key)
		}
	}
	if got, err := validateLiveKitTrustKey(strings.Repeat("0", 64)); err != nil || got != strings.Repeat("0", 64) {
		t.Fatalf("valid key = %q, %v; want pass", got, err)
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
	const key = "65c1e83850fe24c986f44bdd3a95360602d2f4f198f1c95e2d500d2b9495aaaf"
	for _, osName := range []VerifyKitOS{VerifyKitOSLinux, VerifyKitOSMacOS, VerifyKitOSWindows} {
		t.Run(string(osName), func(t *testing.T) {
			if readme := liveKitReadme(osName); !strings.Contains(readme, "Pipelock") {
				t.Fatalf("readme(%q) missing brand: %q", osName, readme)
			}
			name, body, err := liveKitScript(osName, key)
			if err != nil {
				t.Fatalf("liveKitScript(%q): %v", osName, err)
			}
			if name == "" || !strings.Contains(body, key) {
				t.Fatalf("script(%q) name=%q missing key in body", osName, name)
			}
		})
	}
	if r := liveKitReadme(VerifyKitOS("x86")); !strings.Contains(r, "Linux") {
		t.Fatalf("default readme should fall back to Linux text: %q", r)
	}
	if _, _, err := liveKitScript(VerifyKitOS("x86"), key); err == nil {
		t.Fatal("liveKitScript with unsupported OS should error")
	}
}

func TestBuildLiveVerifyKit_ReadVerifierError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	const key = "65c1e83850fe24c986f44bdd3a95360602d2f4f198f1c95e2d500d2b9495aaaf"
	session, err := ArchiveRunForDownload(dir, key)
	if err != nil {
		t.Fatalf("ArchiveRunForDownload: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-verifier")
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, missing, session, key); err == nil {
		t.Fatal("unreadable verifier path should fail closed")
	}
}

func TestBuildLiveVerifyKit_WindowsAndMacOS(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeRunArtifacts(t, dir, false)
	const key = "65c1e83850fe24c986f44bdd3a95360602d2f4f198f1c95e2d500d2b9495aaaf"
	session, err := ArchiveRunForDownload(dir, key)
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
			kit, filename, err := BuildLiveVerifyKit(tc.osName, verifierPath, session, key)
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
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), []byte("not a gzip stream"), validKitKey64); err == nil {
		t.Fatal("non-gzip session bytes should fail closed")
	}
}

func TestBuildLiveVerifyKit_MissingPacketFileFailsClosed(t *testing.T) {
	t.Parallel()
	// Valid gzip+tar, but packet/packet.json is absent: the kit must not ship a
	// bundle that cannot verify.
	session := buildKitSession(t, map[string]string{
		"packet/manifest.json":  `{"v":1}`,
		"packet/evidence.jsonl": "{}\n",
	}, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session, validKitKey64); err == nil {
		t.Fatal("missing packet file should fail closed")
	}
}

func TestBuildLiveVerifyKit_InvalidInBundleTrustKeyFailsClosed(t *testing.T) {
	t.Parallel()
	// The bundle's own packet.json carries a non-hex signer key; it is preferred
	// over the fallback and must be rejected.
	session := buildKitSession(t, map[string]string{
		"packet/packet.json":    `{"verifier":{"signer_key":"not-hex"}}`,
		"packet/manifest.json":  `{"v":1}`,
		"packet/evidence.jsonl": "{}\n",
	}, false, false)
	if _, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session, validKitKey64); err == nil {
		t.Fatal("invalid in-bundle trust key should fail closed")
	}
}

func TestBuildLiveVerifyKit_TrustKeySource(t *testing.T) {
	t.Parallel()
	keyA := strings.Repeat("1", 64)
	keyB := strings.Repeat("2", 64)
	fallback := validKitKey64

	cases := []struct {
		name    string
		files   map[string]string
		wantKey string
	}{
		{
			name: "from packet.json",
			files: map[string]string{
				"packet/packet.json":    `{"verifier":{"signer_key":"` + keyA + `"}}`,
				"packet/manifest.json":  `{"signer_key":"` + keyB + `"}`,
				"packet/evidence.jsonl": "{}\n",
			},
			wantKey: keyA,
		},
		{
			name: "from manifest.json when packet lacks it",
			files: map[string]string{
				"packet/packet.json":    `{"receipt_count":1}`,
				"packet/manifest.json":  `{"signer_key":"` + keyB + `"}`,
				"packet/evidence.jsonl": "{}\n",
			},
			wantKey: keyB,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// withDirEntry + withForeign also exercise the extraction skip paths.
			session := buildKitSession(t, tc.files, true, true)
			kit, _, err := BuildLiveVerifyKit(VerifyKitOSLinux, writeTempVerifier(t), session, fallback)
			if err != nil {
				t.Fatalf("BuildLiveVerifyKit: %v", err)
			}
			script := readZipEntry(t, kit, "pipelock-live-verify-linux/verify.sh")
			if !strings.Contains(script, tc.wantKey) {
				t.Fatalf("verify script did not use the in-bundle trust key %s", tc.wantKey)
			}
			if strings.Contains(script, fallback) {
				t.Fatalf("verify script used the fallback key instead of the in-bundle key %s", tc.wantKey)
			}
		})
	}
}
