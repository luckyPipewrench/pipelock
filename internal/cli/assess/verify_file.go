// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package assess

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const maxAssessVerifyFileBytes int64 = 8 << 20

func openAssessVerifyFile(path string) (*os.File, error) {
	pre, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if !pre.Mode().IsRegular() {
		return nil, fmt.Errorf("input must be a regular file")
	}
	file, err := securefile.OpenRegularNonblocking(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(pre, info) {
		_ = file.Close()
		return nil, fmt.Errorf("input must remain a regular file")
	}
	if info.Size() > maxAssessVerifyFileBytes {
		_ = file.Close()
		return nil, fmt.Errorf("input exceeds %d bytes", maxAssessVerifyFileBytes)
	}
	return file, nil
}

func loadAssessVerifySignature(path string) ([]byte, error) {
	data, err := readAssessVerifyFile(path)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decoding signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("invalid signature length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}

func readAssessVerifyFile(path string) ([]byte, error) {
	file, err := openAssessVerifyFile(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxAssessVerifyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxAssessVerifyFileBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxAssessVerifyFileBytes)
	}
	return data, nil
}

func hashAssessVerifyFile(path string) (string, error) {
	file, err := openAssessVerifyFile(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxAssessVerifyFileBytes+1))
	if err != nil {
		return "", err
	}
	if n > maxAssessVerifyFileBytes {
		return "", fmt.Errorf("input exceeds %d bytes", maxAssessVerifyFileBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
