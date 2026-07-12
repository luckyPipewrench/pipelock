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

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pipelock-release-manifest: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pipelock-release-manifest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dist := fs.String("dist", "dist", "GoReleaser dist directory")
	tag := fs.String("tag", "", "release tag, e.g. v3.1.0")
	commit := fs.String("commit", "", "release commit SHA")
	keyHex := fs.String("private-key-hex", "", "hex Ed25519 private key or 32-byte seed; required only with --sign-only")
	signerKeyID := fs.String("signer-key-id", firstReleaseKey(os.Getenv("RELEASE_KEYRING_HEX")), "hex Ed25519 public key expected to sign release.json")
	signOnly := fs.Bool("sign-only", false, "sign an existing release.json without regenerating it")
	manifestPath := fs.String("manifest", "", "release.json path for --sign-only; defaults to <dist>/release.json")
	genKey := fs.Bool("gen-key", false, "generate a fresh Ed25519 release-signing keypair and print private_hex + public_hex (private -> offline key safe; public -> RELEASE_KEYRING_HEX)")
	if err := fs.Parse(args); err != nil {
		return err
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
		return runSignOnly(*dist, *manifestPath, *keyHex)
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
	checksums, err := os.ReadFile(checksumsPath) // #nosec G304 -- release tool reads caller-supplied dist dir
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

func runSignOnly(dist, manifestPath, keyHex string) error {
	priv, err := parsePrivateKey(keyHex)
	if err != nil {
		return err
	}
	if strings.TrimSpace(manifestPath) == "" {
		manifestPath = filepath.Join(dist, releasetrust.ManifestFile)
	}
	data, err := os.ReadFile(filepath.Clean(manifestPath)) // #nosec G304 -- release owner supplies manifest path
	if err != nil {
		return fmt.Errorf("read release.json: %w", err)
	}
	var manifest releasetrust.Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return fmt.Errorf("parse release.json: %w", err)
	}
	if err := releasetrust.ValidateManifest(manifest); err != nil {
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
		return nil, errors.New("--private-key-hex is required for --sign-only")
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
		archive, err := os.ReadFile(archivePath) // #nosec G304 -- release tool reads caller-supplied dist dir
		if err != nil {
			return nil, fmt.Errorf("read archive %s: %w", name, err)
		}
		if got := sha256Hex(archive); got != checksum {
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
