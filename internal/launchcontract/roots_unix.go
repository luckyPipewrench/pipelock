// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package launchcontract

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
)

// SystemRoots reads the platform's PEM root bundle. These are the same distro
// locations used by contain's platform detection, plus macOS's OpenSSL bundle.
// Ambient SSL_CERT_FILE is deliberately ignored: it is an inherited override,
// not the platform store. Systems without a PEM store fail with a remedy.
func SystemRoots() ([]byte, error) {
	return systemRootsFromFiles([]string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
		"/var/lib/ca-certificates/ca-bundle.pem",
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/ssl/cert.pem",
	})
}

func systemRootsFromFiles(paths []string) ([]byte, error) {
	for _, path := range paths {
		data, err := os.ReadFile(filepath.Clean(path))
		if err == nil && x509.NewCertPool().AppendCertsFromPEM(data) {
			return data, nil
		}
	}
	return nil, errors.New("cannot read system CA roots; install the operating system's ca-certificates PEM bundle")
}
