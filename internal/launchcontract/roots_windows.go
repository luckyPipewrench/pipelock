// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"encoding/pem"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SystemRoots exports the Windows ROOT store as PEM for clients which replace
// their native trust store when SSL_CERT_FILE or an equivalent is set.
func SystemRoots() ([]byte, error) {
	name, err := windows.UTF16PtrFromString("ROOT")
	if err != nil {
		return nil, err
	}
	store, err := windows.CertOpenSystemStore(0, name)
	if err != nil {
		return nil, fmt.Errorf("open Windows ROOT certificate store: %w", err)
	}
	defer func() { _ = windows.CertCloseStore(store, 0) }()
	var result []byte
	var prev *windows.CertContext
	for {
		cert, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil {
			if errors.Is(err, syscall.Errno(windows.CRYPT_E_NOT_FOUND)) {
				break
			}
			return nil, fmt.Errorf("enumerate Windows ROOT certificates: %w", err)
		}
		prev = cert
		der := unsafe.Slice(cert.EncodedCert, cert.Length) // #nosec G103 -- Windows owns this certificate buffer until the next enumeration; PEM encoding copies it first
		result = append(result, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if len(result) == 0 {
		return nil, errors.New("windows ROOT certificate store is empty; install system root certificates")
	}
	return result, nil
}
