// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package tlsfile loads X.509 certificate/private-key pairs through a bounded,
// permission-checked filesystem boundary before handing them to crypto/tls.
package tlsfile

import (
	"crypto/tls"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

const maxPEMBytes = 1 << 20

// LoadX509KeyPair is the hardened equivalent of tls.LoadX509KeyPair. It accepts
// Kubernetes Secret-volume symlinks only when they resolve inside the mounted
// directory, rejects non-regular and oversized inputs, and requires private-key
// permissions no broader than owner read/write plus optional group read.
func LoadX509KeyPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := securefile.Read(certFile, securefile.Options{MaxBytes: maxPEMBytes})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS certificate: %w", err)
	}
	keyPEM, err := securefile.Read(keyFile, securefile.Options{MaxBytes: maxPEMBytes, DisallowedPerms: 0o037})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load TLS private key: %w", err)
	}
	defer clear(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}
