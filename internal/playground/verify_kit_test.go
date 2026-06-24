// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
