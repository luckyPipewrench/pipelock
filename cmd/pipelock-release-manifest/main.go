// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// pipelock-release-manifest generates release.json for "pipelock update" and
// signs an existing manifest in offline mode. It is intentionally a small
// stdlib-only release-engineering tool so self-update does not depend on cosign
// or sigstore libraries at runtime.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	releasetrust "github.com/luckyPipewrench/pipelock/internal/release"
)

var pipelockArchiveRE = regexp.MustCompile(`^pipelock_([^_]+)_([^_]+)_([^_]+)\.(tar\.gz|zip)$`)

const maxReleaseMetadataBytes int64 = 8 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pipelock-release-manifest: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	return runWithInput(args, os.Stdin, stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pipelock-release-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", "dist", "GoReleaser dist directory")
	tag := fs.String("tag", "", "release tag, e.g. v3.1.0")
	commit := fs.String("commit", "", "release commit SHA")
	keyHex := fs.String("private-key-hex", "", "hex Ed25519 private key or 32-byte seed; required only with --sign-only")
	keyStdin := fs.Bool("private-key-stdin", false, "read the hex Ed25519 private key or seed from stdin for --sign-only")
	signerKeyID := fs.String("signer-key-id", firstReleaseKey(os.Getenv("RELEASE_KEYRING_HEX")), "hex Ed25519 public key expected to sign release.json")
	signOnly := fs.Bool("sign-only", false, "sign an existing release.json without regenerating it")
	manifestPath := fs.String("manifest", "", "release.json path for --sign-only; defaults to <dist>/release.json")
	genKey := fs.Bool("gen-key", false, "generate a fresh Ed25519 release-signing keypair and print private_hex + public_hex (private -> offline key safe; public -> RELEASE_KEYRING_HEX)")
	verify := fs.Bool("verify", false, "verify an existing release.json against its release.json.sig and the release keyring; exits non-zero when the signature is missing or does not verify")
	keyringHex := fs.String("keyring-hex", os.Getenv("RELEASE_KEYRING_HEX"), "hex Ed25519 public keys accepted as release signers; defaults to RELEASE_KEYRING_HEX")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keyHexSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "private-key-hex" {
			keyHexSet = true
		}
	})
	if *verify {
		return runVerify(*dist, *manifestPath, *keyringHex, stdout)
	}
	if *genKey {
		privHex, pubHex, err := generateReleaseKeypair()
		if err != nil {
			return err
		}
		// Public half is safe to display; private half is the offline signer and
		// must go ONLY to the operator's key safe, never into CI.
		_, _ = fmt.Fprintf(stderr, "WARNING: private_hex is the offline release signer. Store it ONLY in the offline key safe; put public_hex into the RELEASE_KEYRING_HEX secret.\n")
		if _, err := fmt.Fprintf(stdout, "private_hex=%s\npublic_hex=%s\n", privHex, pubHex); err != nil {
			return fmt.Errorf("write generated release keypair: %w", err)
		}
		return nil
	}
	if *signOnly {
		privateKeyHex, err := signingKeyHex(*keyHex, keyHexSet, *keyStdin, stdin)
		if err != nil {
			return err
		}
		return runSignOnly(*dist, *manifestPath, privateKeyHex)
	}
	if strings.TrimSpace(*tag) == "" {
		return errors.New("--tag is required")
	}
	if strings.TrimSpace(*commit) == "" {
		return errors.New("--commit is required")
	}
	if strings.TrimSpace(*signerKeyID) == "" {
		return errors.New("--signer-key-id or RELEASE_KEYRING_HEX is required")
	}
	if !isPublicKeyHex(*signerKeyID) {
		return errors.New("--signer-key-id must be a 32-byte Ed25519 public key encoded as 64 hex characters")
	}
	checksumsPath := filepath.Join(*dist, "checksums.txt")
	checksums, err := readReleaseMetadata(checksumsPath)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	entries, err := parseChecksumFile(checksums)
	if err != nil {
		return err
	}
	assets, err := manifestAssets(*dist, entries)
	if err != nil {
		return err
	}
	manifest := releasetrust.Manifest{
		Schema:             "pipelock-release-v1",
		Repo:               "github.com/luckyPipewrench/pipelock",
		Tag:                *tag,
		Commit:             *commit,
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		ChecksumFileSHA256: sha256Hex(checksums),
		Assets:             assets,
		SignerKeyID:        strings.ToLower(strings.TrimSpace(*signerKeyID)),
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release manifest: %w", err)
	}
	data = append(data, '\n')
	if err := releasetrust.ValidateManifest(manifest); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dist, releasetrust.ManifestFile), data, 0o600); err != nil {
		return fmt.Errorf("write release.json: %w", err)
	}
	return nil
}

func signingKeyHex(flagValue string, flagSet, fromStdin bool, stdin io.Reader) (string, error) {
	if flagSet && fromStdin {
		return "", errors.New("--private-key-hex and --private-key-stdin are mutually exclusive")
	}
	if !fromStdin {
		return flagValue, nil
	}
	const maxPrivateKeyHexBytes = 256
	value, err := io.ReadAll(io.LimitReader(stdin, maxPrivateKeyHexBytes+1))
	if err != nil {
		return "", fmt.Errorf("read release private key from stdin: %w", err)
	}
	if len(value) > maxPrivateKeyHexBytes {
		return "", errors.New("release private key from stdin exceeds 256 bytes")
	}
	return strings.TrimSpace(string(value)), nil
}

// runVerify checks that a release manifest carries a signature that verifies
// against the release keyring.
//
// Signing happens offline, so no CI job can produce release.json.sig and no
// test before the tag can prove it exists. What CI can do is refuse to publish
// without it. `pipelock update` reads that signature to decide whether an update
// is genuine, so a release that ships the manifest and not the signature leaves
// self-update unable to verify anything, which is how v3.1.0 shipped.
//
// A missing signature file and a signature that does not verify are both
// failures here. Treating absence as "nothing to check" is the fail-open
// direction and is exactly the state this guard exists to catch.
func runVerify(dist, manifestPath, keyringHex string, stdout io.Writer) error {
	if strings.TrimSpace(keyringHex) == "" {
		return errors.New("--keyring-hex or RELEASE_KEYRING_HEX is required to verify a release manifest")
	}
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = filepath.Join(dist, releasetrust.ManifestFile)
	}
	data, err := readReleaseMetadata(manifestPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", releasetrust.ManifestFile, err)
	}
	sigPath := filepath.Join(filepath.Dir(manifestPath), releasetrust.ManifestSigFile)
	sig, err := readReleaseMetadata(sigPath)
	if err != nil {
		return fmt.Errorf("read %s (sign the manifest offline with --sign-only before publishing): %w", releasetrust.ManifestSigFile, err)
	}
	verification, err := releasetrust.VerifyManifest(data, sig, keyringHex)
	if err != nil {
		return fmt.Errorf("verify %s: %w", releasetrust.ManifestFile, err)
	}
	if _, err := fmt.Fprintf(stdout, "release manifest signature verified by %s (keyring index %d)\n", verification.SignerKeyHex, verification.SignerKeyIndex); err != nil {
		return fmt.Errorf("write verification result: %w", err)
	}
	return nil
}

func runSignOnly(dist, manifestPath, keyHex string) error {
	priv, err := parsePrivateKey(keyHex)
	if err != nil {
		return err
	}
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = filepath.Join(dist, releasetrust.ManifestFile)
	}
	data, err := readReleaseMetadata(manifestPath)
	if err != nil {
		return fmt.Errorf("read release.json: %w", err)
	}
	manifest, err := releasetrust.ParseManifest(data)
	if err != nil {
		return err
	}
	pub := publicKeyHex(priv.Public().(ed25519.PublicKey))
	if !strings.EqualFold(manifest.SignerKeyID, pub) {
		return fmt.Errorf("offline signing key %s does not match release.json signer_key_id %s", pub, manifest.SignerKeyID)
	}
	sig := releasetrust.SignManifest(data, priv)
	if err := os.WriteFile(filepath.Join(filepath.Dir(manifestPath), releasetrust.ManifestSigFile), []byte(sig+"\n"), 0o600); err != nil {
		return fmt.Errorf("write release.json.sig: %w", err)
	}
	return nil
}

func parsePrivateKey(value string) (ed25519.PrivateKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("a private key is required for --sign-only")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("release private key must be hex: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("release private key must be %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// generateReleaseKeypair creates a fresh Ed25519 release-signing keypair and
// returns the private seed and public key as hex. The private seed feeds
// --private-key-hex for offline -sign-only; the public hex is what goes into
// the RELEASE_KEYRING_HEX build secret and becomes the manifest signer_key_id.
func generateReleaseKeypair() (privHex, pubHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate release keypair: %w", err)
	}
	return hex.EncodeToString(priv.Seed()), publicKeyHex(pub), nil
}

func firstReleaseKey(keyring string) string {
	keyring = strings.TrimSpace(keyring)
	if keyring == "" {
		return ""
	}
	parts := strings.Split(keyring, ",")
	return strings.TrimSpace(parts[0])
}

func isPublicKeyHex(value string) bool {
	raw, err := hex.DecodeString(strings.TrimSpace(value))
	return err == nil && len(raw) == ed25519.PublicKeySize
}

func parseChecksumFile(data []byte) (map[string]string, error) {
	entries := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		if _, err := hex.DecodeString(fields[0]); err != nil || len(fields[0]) != 64 {
			return nil, fmt.Errorf("invalid checksum for %s", fields[1])
		}
		entries[fields[1]] = strings.ToLower(fields[0])
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan checksums.txt: %w", err)
	}
	return entries, nil
}

func manifestAssets(dist string, entries map[string]string) ([]releasetrust.Asset, error) {
	assets := make([]releasetrust.Asset, 0, 6)
	for name, checksum := range entries {
		match := pipelockArchiveRE.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		archivePath := filepath.Join(dist, name)
		got, err := sha256FileHex(archivePath)
		if err != nil {
			return nil, fmt.Errorf("read archive %s: %w", name, err)
		}
		if got != checksum {
			return nil, fmt.Errorf("archive %s checksum mismatch: got %s want %s", name, got, checksum)
		}
		goos := match[2]
		asset := releasetrust.Asset{
			Name:   name,
			SHA256: checksum,
			GOOS:   goos,
			GOARCH: match[3],
			Binary: archiveBinaryName(goos),
		}
		assets = append(assets, asset)
	}
	if len(assets) == 0 {
		return nil, errors.New("no pipelock archives found in checksums.txt")
	}
	return assets, nil
}

func readReleaseMetadata(path string) ([]byte, error) {
	file, err := openReleaseInput(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("release metadata must be a regular file")
	}
	if info.Size() > maxReleaseMetadataBytes {
		return nil, fmt.Errorf("release metadata exceeds %d bytes", maxReleaseMetadataBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReleaseMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxReleaseMetadataBytes {
		return nil, fmt.Errorf("release metadata exceeds %d bytes", maxReleaseMetadataBytes)
	}
	return data, nil
}

func sha256FileHex(path string) (string, error) {
	file, err := openReleaseInput(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func openReleaseInput(path string) (*os.File, error) {
	clean := filepath.Clean(path)
	root, err := os.OpenRoot(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	file, err := root.Open(filepath.Base(clean))
	closeErr := root.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		_ = file.Close()
		return nil, closeErr
	}
	return file, nil
}

func archiveBinaryName(goos string) string {
	if goos == "windows" {
		return "pipelock.exe"
	}
	return "pipelock"
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func publicKeyHex(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub)
}
