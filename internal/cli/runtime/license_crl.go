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
	if cfg == nil || cfg.LicenseKey == "" {
		return false, nil
	}
	require := cfg.LicenseRequireIntermediateResolved
	// Empty-CRL early return: when require-intermediate is OFF this preserves the
	// legacy behaviour (no CRL configured = nothing to enforce here; the startup
	// gate already verified the token). When require is ON, a CRL is mandatory —
	// it is the revocation floor — so a missing CRL must fail closed and tear the
	// paid surface down.
	if cfg.LicenseCRLFile == "" {
		if require {
			return true, errors.New("license_require_intermediate is on but no license_crl_file is configured; a signed CRL is required as the revocation floor")
		}
		return false, nil
	}
	pubKey, err := runtimeLicensePublicKey(cfg)
	if err != nil {
		return true, err
	}
	opts, err := license.ResolveVerifyOptions(license.ResolveInputs{
		RootPub:          pubKey,
		CRLFile:          cfg.LicenseCRLFile,
		IntermediateCert: cfg.LicenseIntermediateCert,
		IntermediateFile: cfg.LicenseIntermediateFile,
		RequireSet:       true,
		Require:          require,
		MaxAge:           cfg.LicenseCRLMaxAgeResolved,
	})
	if err != nil {
		return true, err
	}
	_, err = license.VerifyTokenWithOptions(cfg.LicenseKey, opts)
	if err == nil {
		return false, nil
	}
	// Revoked / expired / intermediate-revoked / require-not-satisfied all fail
	// closed and tear the surface down.
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
