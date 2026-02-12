package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestKeygenCmd_Basic(t *testing.T) {
	dir := t.TempDir()

	cmd := rootCmd()
	cmd.SetArgs([]string{"keygen", "alice", "--keystore", dir})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("keygen error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "alice") {
		t.Errorf("output should mention agent name, got: %s", output)
	}

	// Verify key files exist.
	privPath := filepath.Join(dir, "agents", "alice", "id_ed25519")
	if _, err := os.Stat(privPath); err != nil {
		t.Errorf("private key not created: %v", err)
	}
}

func TestKeygenCmd_AlreadyExists(t *testing.T) {
	dir := t.TempDir()

	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"keygen", "alice", "--keystore", dir})
	cmd1.SetOut(&strings.Builder{})
	if err := cmd1.Execute(); err != nil {
		t.Fatal(err)
	}

	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"keygen", "alice", "--keystore", dir})
	cmd2.SetOut(&strings.Builder{})
	if err := cmd2.Execute(); err == nil {
		t.Fatal("expected error for duplicate keygen")
	}
}

func TestKeygenCmd_Force(t *testing.T) {
	dir := t.TempDir()

	cmd1 := rootCmd()
	cmd1.SetArgs([]string{"keygen", "alice", "--keystore", dir})
	cmd1.SetOut(&strings.Builder{})
	if err := cmd1.Execute(); err != nil {
		t.Fatal(err)
	}

	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"keygen", "alice", "--keystore", dir, "--force"})
	buf := &strings.Builder{}
	cmd2.SetOut(buf)
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("keygen --force error: %v", err)
	}
	if !strings.Contains(buf.String(), "alice") {
		t.Errorf("expected output mentioning alice, got: %s", buf.String())
	}
}

func TestKeygenCmd_NoArgs(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"keygen"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing agent name")
	}
}

func TestSignCmd_Basic(t *testing.T) {
	dir := t.TempDir()

	// Generate key.
	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	// Create a file to sign.
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("hello world\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", testFile, "--agent", "alice", "--keystore", dir})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Signed") {
		t.Errorf("expected 'Signed' in output, got: %s", output)
	}

	// Verify .sig file was created.
	sigPath := testFile + ".sig"
	if _, err := os.Stat(sigPath); err != nil {
		t.Errorf("signature file not created: %v", err)
	}
}

func TestSignCmd_NoAgent(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Ensure env is not set.
	t.Setenv("PIPELOCK_AGENT", "")

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", testFile})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no agent specified")
	}
}

func TestSignCmd_EnvAgent(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("envbot"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("env test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_AGENT", "envbot")

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", testFile, "--keystore", dir})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sign with env agent error: %v", err)
	}
	if !strings.Contains(buf.String(), "envbot") {
		t.Errorf("expected 'envbot' in output, got: %s", buf.String())
	}
}

func TestVerifyCmd_Valid(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("verified content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign.
	signC := rootCmd()
	signC.SetArgs([]string{"sign", testFile, "--agent", "alice", "--keystore", dir})
	signC.SetOut(&strings.Builder{})
	if err := signC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Verify.
	verifyC := rootCmd()
	verifyC.SetArgs([]string{"verify", testFile, "--agent", "alice", "--keystore", dir})
	buf := &strings.Builder{}
	verifyC.SetOut(buf)

	if err := verifyC.Execute(); err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected 'OK' in output, got: %s", buf.String())
	}
}

func TestVerifyCmd_TamperedFile(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign.
	signC := rootCmd()
	signC.SetArgs([]string{"sign", testFile, "--agent", "alice", "--keystore", dir})
	signC.SetOut(&strings.Builder{})
	if err := signC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Tamper.
	if err := os.WriteFile(testFile, []byte("tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Verify should fail.
	verifyC := rootCmd()
	verifyC.SetArgs([]string{"verify", testFile, "--agent", "alice", "--keystore", dir})
	buf := &strings.Builder{}
	verifyC.SetOut(buf)

	if err := verifyC.Execute(); err == nil {
		t.Fatal("expected error for tampered file")
	}
	if !strings.Contains(buf.String(), "FAILED") {
		t.Errorf("expected 'FAILED' in output, got: %s", buf.String())
	}
}

func TestVerifyCmd_MissingSig(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "nosig.txt")
	if err := os.WriteFile(testFile, []byte("no sig\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"verify", testFile, "--agent", "alice", "--keystore", dir})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestVerifyCmd_WrongAgent(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.GenerateAgent("bob"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("alice signed this\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign as alice.
	signC := rootCmd()
	signC.SetArgs([]string{"sign", testFile, "--agent", "alice", "--keystore", dir})
	signC.SetOut(&strings.Builder{})
	if err := signC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Verify as bob should fail.
	verifyC := rootCmd()
	verifyC.SetArgs([]string{"verify", testFile, "--agent", "bob", "--keystore", dir})
	verifyC.SetOut(&strings.Builder{})

	if err := verifyC.Execute(); err == nil {
		t.Fatal("expected error when verifying with wrong agent's key")
	}
}

func TestTrustCmd_Basic(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("remote"); err != nil {
		t.Fatal(err)
	}
	pubKeyPath := ks.PublicKeyPath("remote")

	cmd := rootCmd()
	cmd.SetArgs([]string{"trust", "remote", pubKeyPath, "--keystore", dir})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("trust error: %v", err)
	}
	if !strings.Contains(buf.String(), "Trusted") {
		t.Errorf("expected 'Trusted' in output, got: %s", buf.String())
	}

	// Verify trusted key can be loaded.
	_, err := ks.LoadTrustedKey("remote")
	if err != nil {
		t.Fatalf("trusted key not loadable: %v", err)
	}
}

func TestTrustCmd_InvalidKeyFile(t *testing.T) {
	dir := t.TempDir()
	badFile := filepath.Join(t.TempDir(), "bad.pub")
	if err := os.WriteFile(badFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"trust", "bad-agent", badFile, "--keystore", dir})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid key file")
	}
}

func TestSignVerify_EndToEnd(t *testing.T) {
	ksDir := t.TempDir()
	workspace := t.TempDir()

	// Generate key pair.
	keygenC := rootCmd()
	keygenC.SetArgs([]string{"keygen", "test-agent", "--keystore", ksDir})
	keygenC.SetOut(&strings.Builder{})
	if err := keygenC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Create workspace file.
	testFile := filepath.Join(workspace, "config.yaml")
	if err := os.WriteFile(testFile, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign.
	signC := rootCmd()
	signC.SetArgs([]string{"sign", testFile, "--agent", "test-agent", "--keystore", ksDir})
	signC.SetOut(&strings.Builder{})
	if err := signC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Verify (should pass).
	verifyC := rootCmd()
	verifyC.SetArgs([]string{"verify", testFile, "--agent", "test-agent", "--keystore", ksDir})
	verifyBuf := &strings.Builder{}
	verifyC.SetOut(verifyBuf)
	if err := verifyC.Execute(); err != nil {
		t.Fatalf("end-to-end verify failed: %v", err)
	}
	if !strings.Contains(verifyBuf.String(), "OK") {
		t.Errorf("expected OK, got: %s", verifyBuf.String())
	}

	// Tamper and re-verify (should fail).
	if err := os.WriteFile(testFile, []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyC2 := rootCmd()
	verifyC2.SetArgs([]string{"verify", testFile, "--agent", "test-agent", "--keystore", ksDir})
	verifyC2.SetOut(&strings.Builder{})
	if err := verifyC2.Execute(); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}

func TestVerifyCmd_CustomSigPath(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("custom sig path\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sign (creates test.txt.sig next to the file).
	signC := rootCmd()
	signC.SetArgs([]string{"sign", testFile, "--agent", "alice", "--keystore", dir})
	signC.SetOut(&strings.Builder{})
	if err := signC.Execute(); err != nil {
		t.Fatal(err)
	}

	// Move sig to a custom location.
	customSig := filepath.Join(t.TempDir(), "custom.sig")
	data, err := os.ReadFile(testFile + ".sig") //nolint:gosec // test path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customSig, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Remove the default .sig so verify must use --sig.
	if err := os.Remove(testFile + ".sig"); err != nil {
		t.Fatal(err)
	}

	// Verify with --sig flag.
	verifyC := rootCmd()
	verifyC.SetArgs([]string{"verify", testFile, "--agent", "alice", "--keystore", dir, "--sig", customSig})
	buf := &strings.Builder{}
	verifyC.SetOut(buf)

	if err := verifyC.Execute(); err != nil {
		t.Fatalf("verify with --sig flag error: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Errorf("expected OK, got: %s", buf.String())
	}
}

func TestSignCmd_NonexistentFile(t *testing.T) {
	dir := t.TempDir()

	ks := signing.NewKeystore(dir)
	if _, err := ks.GenerateAgent("alice"); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", "/nonexistent/file.txt", "--agent", "alice", "--keystore", dir})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSignCmd_BadAgent(t *testing.T) {
	dir := t.TempDir()

	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("content\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", testFile, "--agent", "nonexistent-agent", "--keystore", dir})
	cmd.SetOut(&strings.Builder{})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for nonexistent agent")
	}
}

func TestVerifyCmd_NoAgent(t *testing.T) {
	testFile := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(testFile, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PIPELOCK_AGENT", "")

	cmd := rootCmd()
	cmd.SetArgs([]string{"verify", testFile})
	cmd.SetOut(&strings.Builder{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error when no agent specified for verify")
	}
}

func TestTrustCmd_NoArgs(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"trust"})
	cmd.SetOut(&strings.Builder{})
	cmd.SetErr(&strings.Builder{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for missing args on trust")
	}
}

func TestKeygenCmd_RegisteredInHelp(t *testing.T) {
	cmd := rootCmd()
	cmd.SetArgs([]string{"--help"})
	buf := &strings.Builder{}
	cmd.SetOut(buf)

	_ = cmd.Execute()
	output := buf.String()

	for _, sub := range []string{"keygen", "sign", "verify", "trust"} {
		if !strings.Contains(output, sub) {
			t.Errorf("root help should list %q command", sub)
		}
	}
}

func TestSignCmd_SaveSignatureError(t *testing.T) {
	// Sign succeeds but saving the .sig file fails (read-only target dir).
	base := t.TempDir()
	ks := signing.NewKeystore(base)
	_, err := ks.GenerateAgent("saver")
	if err != nil {
		t.Fatal(err)
	}

	// Create a file to sign in a read-only directory.
	targetDir := t.TempDir()
	filePath := filepath.Join(targetDir, "data.txt")
	if err := os.WriteFile(filePath, []byte("sign me"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Make target dir read-only so .sig file can't be written.
	if err := os.Chmod(targetDir, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(targetDir, 0o700) }) //nolint:gosec // restore

	cmd := rootCmd()
	cmd.SetArgs([]string{"sign", filePath, "--agent", "saver", "--keystore", base})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error when saving signature")
	}
}

func TestVerifyCmd_MissingPublicKey(t *testing.T) {
	// Verify should fail when the agent's public key doesn't exist.
	base := t.TempDir()

	// Create a dummy file and signature.
	filePath := filepath.Join(base, "data.txt")
	if err := os.WriteFile(filePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	sigPath := filePath + ".sig"
	if err := os.WriteFile(sigPath, []byte("fakesig"), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := rootCmd()
	cmd.SetArgs([]string{"verify", filePath, "--agent", "nonexistent", "--keystore", base})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing public key")
	}
	if !strings.Contains(err.Error(), "loading key") {
		t.Errorf("expected 'loading key' error, got: %v", err)
	}
}

func TestTrustCmd_BadKeystoreDir(t *testing.T) {
	// Trust should fail when keystore can't write.
	base := t.TempDir()
	ks := signing.NewKeystore(base)

	// Generate a key pair to have a valid pubkey file.
	_, err := ks.GenerateAgent("trusted")
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(base, "agents", "trusted", "public.key")

	// Use an empty keystore dir that's read-only.
	badStore := t.TempDir()
	if err := os.Chmod(badStore, 0o500); err != nil { //nolint:gosec // intentionally restrictive for test
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(badStore, 0o700) }) //nolint:gosec // restore

	cmd := rootCmd()
	cmd.SetArgs([]string{"trust", "trusted", pubPath, "--keystore", badStore})
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error for read-only keystore dir")
	}
}
