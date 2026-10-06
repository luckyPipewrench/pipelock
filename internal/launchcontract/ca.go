// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// ValidateCA accepts only PEM CA certificates that are valid now. Non-CA
// certificates, keys, malformed PEM, and mixed/trailing garbage are rejected.
func ValidateCA(data []byte, now time.Time) error {
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("expected a PEM CA certificate, not a key or other data")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || bytes.Count(data[:len(data)-len(rest)], []byte("-----BEGIN ")) != 1 {
			return errors.New("invalid PEM CA certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA certificate: %w", err)
		}
		if !cert.IsCA || !cert.BasicConstraintsValid || (cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0) {
			return errors.New("certificate is not a signing CA")
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return errors.New("CA certificate is expired or not yet valid; renew the Pipelock CA")
		}
		count++
		data = rest
	}
	if count == 0 {
		return errors.New("CA file contains no certificates")
	}
	return nil
}

// CombinedBundle concatenates the system roots and Pipelock CA, as contain
// install does. Failing to read usable system roots never silently produces a
// Pipelock-only replacement trust store.
func CombinedBundle(systemRoots, ca []byte) ([]byte, error) {
	if !x509.NewCertPool().AppendCertsFromPEM(systemRoots) {
		return nil, errors.New("system CA bundle contains no certificates; install or repair the system CA store")
	}
	result := append([]byte{}, systemRoots...)
	if result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return append(result, ca...), nil
}

// WriteBundle creates a private, persistent bundle named by its content hash.
// The same bytes reuse one file, so repeated launches don't fill the cache.
// Unix exec can't run a deferred cleanup, and print-env must remain usable
// after exit. A distinct bundle gets its own path, so a child still reading
// the previous file keeps it. A symlink is never followed or replaced.
func WriteBundle(cacheDir string, data []byte) (string, error) {
	parent := filepath.Join(cacheDir, "pipelock")
	dir := filepath.Join(parent, "exec-ca")
	if err := requireCacheRoot(cacheDir); err != nil {
		return "", err
	}
	if err := rejectSymlink(parent); err != nil {
		return "", err
	}
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return "", fmt.Errorf("create CA cache directory: %w", err)
	}
	if err := rejectSymlink(parent); err != nil {
		return "", err
	}
	if err := requirePrivate(parent); err != nil {
		return "", err
	}
	if err := rejectSymlink(dir); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("create CA cache directory: %w", err)
	}
	if err := rejectSymlink(dir); err != nil {
		return "", err
	}
	if err := requirePrivate(dir); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".pem")
	if existing, err := readRegularFile(path); err == nil {
		if !bytes.Equal(existing, data) {
			return "", errors.New("combined CA bundle path does not match its content")
		}
		if err := requirePrivate(path); err != nil {
			return "", err
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := installBundle(dir, path, data); err != nil {
		if existing, readErr := readRegularFile(path); readErr == nil && bytes.Equal(existing, data) {
			return path, nil
		}
		return "", err
	}
	return path, nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	// A missing path is fine. A file where a directory is required is not a
	// symlink; the following mkdir reports that to the operator.
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect CA cache directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("CA cache directory must be a real directory, not a symlink")
	}
	return nil
}

func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("combined CA bundle path is not a regular file")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is the content-hash file under the exec CA cache, and Lstat already required a regular file.
	if err != nil {
		return nil, fmt.Errorf("read combined CA bundle: %w", err)
	}
	return data, nil
}

func installBundle(dir, path string, data []byte) error {
	f, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return fmt.Errorf("create combined CA bundle: %w", err)
	}
	tmp := f.Name()
	remove := true
	defer func() {
		if remove {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write combined CA bundle: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close combined CA bundle: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("install combined CA bundle: %w", err)
	}
	remove = false
	return nil
}
