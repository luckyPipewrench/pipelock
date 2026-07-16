// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package coveragecertverify contains the shared CLI verification flow for
// offline coverage certificates.
package coveragecertverify

import (
	"errors"
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/coveragecert"
	"github.com/luckyPipewrench/pipelock/internal/securefile"
	"github.com/luckyPipewrench/pipelock/internal/signingflag"
)

const maxCertificateBytes int64 = 1 << 20

const noTrustedSignerSetError = "no trusted-signer set supplied; refusing to report the certificate as verified — pass --trusted-signer to check trust, or --allow-unpinned for an explicit structural-only check."

type noTrustedSignerSetSuppliedError struct{}

func (noTrustedSignerSetSuppliedError) Error() string {
	return noTrustedSignerSetError
}

// Options configures one offline certificate verification run.
type Options struct {
	CertFile       string
	TrustedSigners []string
	AllowUnpinned  bool
	Out            io.Writer
}

// Run reads and verifies a coverage certificate, prints bounded verification
// lines, and fails closed on invalid signatures or aggregate mismatches.
func Run(opts Options) error {
	data, err := securefile.Read(opts.CertFile, securefile.Options{MaxBytes: maxCertificateBytes})
	if err != nil {
		return fmt.Errorf("--cert: %w", err)
	}

	cert, err := coveragecert.Unmarshal(data)
	if err != nil {
		return err
	}

	trusted, err := signingflag.ParseTrustedSigners(opts.TrustedSigners)
	if err != nil {
		return err
	}

	var trustedKeySet map[string]struct{}
	if len(trusted) > 0 {
		trustedKeySet = make(map[string]struct{}, len(trusted))
		for keyHex := range trusted {
			trustedKeySet[keyHex] = struct{}{}
		}
	}

	out := opts.Out
	if out == nil {
		out = io.Discard
	}

	result, err := coveragecert.Verify(cert, trustedKeySet)
	for _, line := range result.Lines {
		_, _ = fmt.Fprintln(out, line)
	}
	if err != nil {
		return err
	}

	if !result.SignatureValid {
		return errors.New("coverage certificate signature is INVALID")
	}
	if !result.AggregateValid {
		return errors.New("coverage certificate aggregate counts do not match sessions")
	}
	if !result.SignerTrusted && len(trustedKeySet) > 0 {
		// Fail closed: the caller pinned a trusted-signer set and the certificate
		// signer is not in it. A cryptographically valid signature from an
		// untrusted key must not verify, or an operator scripting on exit code
		// would accept a certificate signed by an unrecognized key.
		return errors.New("coverage certificate signer is not in the trusted-signer set")
	}
	if len(trustedKeySet) == 0 {
		if !opts.AllowUnpinned {
			return noTrustedSignerSetSuppliedError{}
		}
		_, _ = fmt.Fprintln(out, "STRUCTURAL ONLY — signer NOT trusted")
	}
	return nil
}
