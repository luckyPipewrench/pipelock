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
	crl, err := license.LoadAndVerifyCRL(cfg.LicenseCRLFile, pubKey, time.Now())
	if err != nil {
		return true, err
	}
	// Rollback rejection: a signature-valid, unexpired CRL is necessary but not
	// sufficient. An attacker who can write the CRL file could swap in an OLDER
	// (still-unexpired) signed CRL that omits a revocation. We hold a durable
	// high-water mark of the highest generation accepted and refuse any CRL
	// below it, failing closed. The high-water is persisted to disk so a process
	// restart cannot reset it to 0 and re-accept a rolled-back CRL.
	highWater, found, err := readCRLHighWater(cfg.LicenseCRLFile)
	if err != nil {
		// The high-water file EXISTS but is unreadable/corrupt. We cannot prove
		// this CRL is not a rollback, so fail closed rather than trust it.
		return true, fmt.Errorf("license CRL high-water unreadable, cannot verify rollback: %w", err)
	}
	if found && crl.Payload.Generation < highWater {
		return true, fmt.Errorf("license CRL rollback rejected: generation %d below accepted %d", crl.Payload.Generation, highWater)
	}
	if !found || crl.Payload.Generation > highWater {
		// Advance the durable high-water BEFORE honoring the CRL. If we cannot
		// persist the new mark, fail closed: a non-persisted acceptance would
		// re-open the rollback window on the next restart.
		if err := writeCRLHighWater(cfg.LicenseCRLFile, crl.Payload.Generation); err != nil {
			return true, fmt.Errorf("persist license CRL high-water: %w", err)
		}
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
