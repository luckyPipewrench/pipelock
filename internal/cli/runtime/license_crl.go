// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
)

const licenseRuntimeCheckInterval = time.Minute

func (s *Server) startLicenseCRLWatcher(ctx context.Context) {
	if s.refreshLicenseCRLOnce() {
		return
	}
	ticker := time.NewTicker(licenseRuntimeCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if s.refreshLicenseCRLOnce() {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (s *Server) refreshLicenseCRLOnce() bool {
	failClosed, err := s.checkLicenseCRL()
	if err != nil {
		s.logger.LogError(auditLicenseCRLContext(), err)
		_, _ = fmt.Fprintf(s.opts.Stderr, "pipelock: license CRL refresh failed closed: %v\n", err)
	}
	if failClosed {
		s.proxy.ShutdownAgentServers()
		// Parity with agent listeners: a revoked or expired license must also
		// stop the follower-side Conductor runtime (Enterprise fleet feature),
		// not just agent listeners. No-op when Conductor is not running.
		s.teardownConductor("revoked or expired (CRL)")
		return true
	}
	return false
}

func (s *Server) checkLicenseCRL() (bool, error) {
	if s == nil || s.proxy == nil {
		return false, nil
	}
	cfg := s.proxy.CurrentConfig()
	if cfg == nil || cfg.LicenseCRLFile == "" || cfg.LicenseKey == "" {
		return false, nil
	}
	pubKey, err := runtimeLicensePublicKey(cfg)
	if err != nil {
		return true, err
	}
	crl, err := license.LoadAndVerifyCRLMonotonic(cfg.LicenseCRLFile, pubKey, time.Now())
	if err != nil {
		return true, err
	}
	_, err = license.VerifyTokenWithOptionalIntermediate(cfg.LicenseKey, cfg.LicenseIntermediateCert, pubKey, &crl, time.Now())
	if err == nil {
		return false, nil
	}
	if errors.Is(err, license.ErrLicenseRevoked) || errors.Is(err, license.ErrLicenseExpired) {
		return true, err
	}
	return true, err
}

func runtimeLicensePublicKey(cfg *config.Config) (ed25519.PublicKey, error) {
	if key := license.EmbeddedPublicKey(); key != nil {
		return key, nil
	}
	if cfg.LicensePublicKey == "" {
		return nil, errors.New("no license public key available")
	}
	keyBytes, err := hex.DecodeString(cfg.LicensePublicKey)
	if err != nil || len(keyBytes) != ed25519.PublicKeySize {
		return nil, errors.New("invalid license public key")
	}
	return ed25519.PublicKey(keyBytes), nil
}

func auditLicenseCRLContext() audit.LogContext {
	return audit.NewMethodLogContext("LICENSE_CRL")
}
