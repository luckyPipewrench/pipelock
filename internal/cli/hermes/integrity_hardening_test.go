// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package hermes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBaseline(t *testing.T, ws string, b anchorBaseline) {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ws, defaultAnchorBaselineName), data, 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}
}

func loadBaselineForTest(t *testing.T, ws string) *anchorBaseline {
	t.Helper()
	b, err := loadAnchorBaseline(filepath.Join(ws, defaultAnchorBaselineName))
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	return b
}

func TestAnchors_InvalidSignatureHex(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := loadBaselineForTest(t, e.ws)
	b.Signature = "nothex!!" // digest set intact, so the set check passes first
	writeBaseline(t, e.ws, *b)
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "signature is invalid") {
		t.Fatalf("verify err = %v, want invalid-signature-hex", err)
	}
}

// TestAnchors_TamperedDigestFailsSignature: altering a digest without the
// private key leaves a stale signature that no longer verifies.
func TestAnchors_TamperedDigestFailsSignature(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := loadBaselineForTest(t, e.ws)
	b.Digests["SOUL.md"] = strings.Repeat("0", 64) // same key set, changed value
	writeBaseline(t, e.ws, *b)                     // signature NOT recomputed
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("verify err = %v, want signature failure", err)
	}
}

func TestAnchors_BadBaselineVersion(t *testing.T) {
	e := newAnchorEnv(t)
	writeBaseline(t, e.ws, anchorBaseline{
		Version:            99,
		DigestAlgorithm:    anchorDigestAlgorithm,
		SignatureAlgorithm: anchorSignatureAlgorithm,
		Digests:            map[string]string{"SOUL.md": strings.Repeat("0", 64)},
		Signature:          "00",
	})
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "unsupported version") {
		t.Fatalf("verify err = %v, want unsupported-version", err)
	}
}

func TestAnchors_BaselineTraversalKeyRejected(t *testing.T) {
	e := newAnchorEnv(t)
	writeBaseline(t, e.ws, anchorBaseline{
		Version:            anchorBaselineVersion,
		DigestAlgorithm:    anchorDigestAlgorithm,
		SignatureAlgorithm: anchorSignatureAlgorithm,
		Digests:            map[string]string{"../escape": strings.Repeat("0", 64)},
		Signature:          "00",
	})
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "clean relative path") {
		t.Fatalf("verify err = %v, want traversal rejection", err)
	}
}

// TestAnchors_VerifyRejectsReducedBaseline: an attacker drops SOUL.md from the
// baseline so verify never checks it. Even re-signed with the private key
// (worst case: key compromise), the expected-set check still rejects it.
func TestAnchors_VerifyRejectsReducedBaseline(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := loadBaselineForTest(t, e.ws)
	delete(b.Digests, "SOUL.md")
	e.reSign(t, b) // valid signature over the reduced set
	writeBaseline(t, e.ws, *b)
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "anchor set") {
		t.Fatalf("verify err = %v, want anchor-set rejection", err)
	}
}

// TestAnchors_VerifyRejectsRenamedAnchorSet: same count, different member, with
// a valid signature; the set-equality check must still reject it.
func TestAnchors_VerifyRejectsRenamedAnchorSet(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	b := loadBaselineForTest(t, e.ws)
	digest := b.Digests["AGENTS.md"]
	delete(b.Digests, "AGENTS.md")
	b.Digests["CHARTER.md"] = digest
	e.reSign(t, b)
	writeBaseline(t, e.ws, *b)
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "anchor set") {
		t.Fatalf("verify err = %v, want anchor-set rejection", err)
	}
}

func TestAnchors_AbsoluteAnchorRejected(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t, "--anchor", "/etc/passwd"); err == nil ||
		!strings.Contains(err.Error(), "clean relative path") {
		t.Fatalf("seal err = %v, want absolute-anchor rejection", err)
	}
}

// TestAnchors_SigningKeySymlinkIntoWorkspaceRejected covers the symlink branch
// of rejectKeyInsideWorkspace: a signing-key path outside the workspace that is
// a symlink pointing back inside it must be rejected.
func TestAnchors_SigningKeySymlinkIntoWorkspaceRejected(t *testing.T) {
	e := newAnchorEnv(t)
	realKey := filepath.Join(e.ws, "secret.key")
	if err := copyFileForTest(t, e.privPath, realKey); err != nil {
		t.Fatalf("copy key into ws: %v", err)
	}
	link := filepath.Join(t.TempDir(), "key-link")
	if err := os.Symlink(realKey, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, _, err := runAnchors(t, "seal", "--workspace", e.ws, "--signing-key", link)
	if err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("seal err = %v, want key-resolves-under-workspace rejection", err)
	}
}

func copyFileForTest(t *testing.T, src, dst string) error {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

func TestAnchors_BaselineUnsupportedDigestAlgorithm(t *testing.T) {
	e := newAnchorEnv(t)
	writeBaseline(t, e.ws, anchorBaseline{
		Version:            anchorBaselineVersion,
		DigestAlgorithm:    "md5",
		SignatureAlgorithm: anchorSignatureAlgorithm,
		Digests:            map[string]string{"SOUL.md": strings.Repeat("0", 64)},
		Signature:          "00",
	})
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "unsupported digest algorithm") {
		t.Fatalf("verify err = %v, want unsupported-digest-algorithm", err)
	}
}

func TestAnchors_BaselineUnsupportedSignatureAlgorithm(t *testing.T) {
	e := newAnchorEnv(t)
	writeBaseline(t, e.ws, anchorBaseline{
		Version:            anchorBaselineVersion,
		DigestAlgorithm:    anchorDigestAlgorithm,
		SignatureAlgorithm: "rsa",
		Digests:            map[string]string{"SOUL.md": strings.Repeat("0", 64)},
		Signature:          "00",
	})
	_, _, err := e.verify(t)
	if err == nil || !strings.Contains(err.Error(), "unsupported signature algorithm") {
		t.Fatalf("verify err = %v, want unsupported-signature-algorithm", err)
	}
}

// TestAnchors_PublicKeyUnderWorkspaceRejected: a public key read from the
// agent-writable workspace could be swapped with a baseline signed by the
// attacker's own key, so verify must refuse it.
func TestAnchors_PublicKeyUnderWorkspaceRejected(t *testing.T) {
	e := newAnchorEnv(t)
	if _, _, err := e.seal(t); err != nil {
		t.Fatalf("seal: %v", err)
	}
	pubInWS := filepath.Join(e.ws, "anchor.pub")
	if err := copyFileForTest(t, e.pubPath, pubInWS); err != nil {
		t.Fatalf("copy pub into ws: %v", err)
	}
	_, _, err := runAnchors(t, "verify", "--workspace", e.ws, "--public-key", pubInWS)
	if err == nil || !strings.Contains(err.Error(), "workspace") {
		t.Fatalf("verify err = %v, want public-key-under-workspace rejection", err)
	}
}

func TestValidateAnchorNames(t *testing.T) {
	t.Parallel()
	if err := validateAnchorNames(nil); err == nil {
		t.Error("empty anchor list must be rejected")
	}
	bad := []string{"/abs", "..", "../up", "a/../b", ".", "dir/"}
	for _, name := range bad {
		if err := validateAnchorNames([]string{name}); err == nil {
			t.Errorf("anchor %q must be rejected", name)
		}
	}
	if err := validateAnchorNames([]string{"SOUL.md", "sub/IDENTITY.md"}); err != nil {
		t.Errorf("clean relative anchors rejected: %v", err)
	}
	if err := validateAnchorNames([]string{"X.md", "X.md"}); err == nil {
		t.Error("duplicate anchor must be rejected")
	}
}
