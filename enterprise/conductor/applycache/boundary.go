//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

type ConfigLoader func(path string) (*config.Config, error)

type ReloadFunc func(*config.Config) error

// RestoreFunc returns the live runtime to the policy that was effective before
// a candidate reload. The runtime supplies it while holding its reload lock so
// an operator reload cannot interleave with compensation.
type RestoreFunc func() error

// ConsistencyFunc receives nil once the runtime and durable active pointer are
// known to agree. A non-nil error means neither a durable outcome nor rollback
// could be established and the runtime must deny admission and omit any claim
// that it knows which policy is live.
type ConsistencyFunc func(error)

type Boundary struct {
	Cache        *Cache
	Identity     Identity
	Resolver     conductor.SignatureKeyResolver
	LocalVersion string
	// LoadConfig is a trusted compatibility hook. With no hook, configuration
	// is parsed directly from the verified signed payload. A hook must return
	// configuration loaded from those same bytes; its raw hash is checked before
	// reload so replacing the cache path cannot substitute another policy.
	LoadConfig ConfigLoader
	Reload     ReloadFunc
	// ReloadChanged reports whether a failed reload published a live config.
	// A caller that can fail after publication must provide this check so the
	// boundary compensates rather than assuming every error left policy alone.
	ReloadChanged func() bool
	Restore       RestoreFunc
	Consistency   ConsistencyFunc
	Now           func() time.Time
	// StillEntitled, when non-nil, is consulted immediately before the
	// live-config Reload (the security-relevant commit point). It lets the
	// caller abort an apply whose fleet entitlement was revoked/expired
	// mid-flight: teardownConductor runs lock-free against the apply mutex, so a
	// bundle already past the caller's pre-apply entitlement check could
	// otherwise complete its Reload and activate one last policy after the fleet
	// was torn down. Returning false here aborts with ErrEntitlementLost before
	// anything reaches the running proxy. nil disables the check.
	StillEntitled func() bool
}

type ApplyOptions struct {
	Rollback      *conductor.RollbackAuthorization
	AllowRollback bool
}

type AppliedBundle struct {
	VerifiedBundle
	ReloadedConfigHash string
}

var ErrLivePolicyUncertain = errors.New("conductor policy apply outcome is uncertain")

func (b Boundary) Apply(bundle conductor.PolicyBundle, opts ApplyOptions) (AppliedBundle, error) {
	if b.Cache == nil {
		return AppliedBundle{}, ErrCacheRequired
	}
	if b.Reload == nil {
		return AppliedBundle{}, errors.New("conductor apply boundary reload function required")
	}
	verified, err := b.Cache.stageVerified(bundle, verifyOptions{
		Identity:      b.Identity,
		Resolver:      b.Resolver,
		Rollback:      opts.Rollback,
		LocalVersion:  b.LocalVersion,
		Now:           b.Now,
		AllowRollback: opts.AllowRollback,
	})
	if err != nil {
		return AppliedBundle{}, err
	}
	cfg, err := b.loadVerifiedConfig(verified)
	if err != nil {
		return AppliedBundle{}, fmt.Errorf("loading verified conductor policy bundle config: %w", err)
	}
	// Last gate before the live-config swap: if the fleet entitlement was torn
	// down while this bundle was staging/loading, abort now. Staging only wrote
	// to the cache's staging area (not yet active), so returning here leaves the
	// running proxy and the durable last-known-good pointer untouched.
	if b.StillEntitled != nil && !b.StillEntitled() {
		return AppliedBundle{}, ErrEntitlementLost
	}
	if err := b.Reload(cfg); err != nil {
		reloadErr := fmt.Errorf("reloading verified conductor policy bundle config: %w", err)
		if b.ReloadChanged != nil && b.ReloadChanged() {
			return AppliedBundle{}, b.restoreOrDeny(reloadErr)
		}
		return AppliedBundle{}, reloadErr
	}
	if err := b.Cache.activate(verified); err != nil {
		activationErr := fmt.Errorf("activating verified conductor policy bundle: %w", err)
		active, activeErr := b.Cache.Active()
		if activeErr == nil && strings.EqualFold(active.BundleHash, verified.BundleHash) {
			// The first activation may have renamed the pointer before fsync failed.
			// A second successful write establishes the candidate durably; a second
			// failure remains ambiguous and must fail closed below.
			if retryErr := b.Cache.activate(verified); retryErr == nil {
				b.markConsistent()
				return AppliedBundle{VerifiedBundle: verified, ReloadedConfigHash: cfg.Hash()}, nil
			} else {
				activationErr = fmt.Errorf("%w; retrying active-pointer durability: %w", activationErr, retryErr)
			}
			return AppliedBundle{}, b.deny(activationErr)
		}
		if activeErr != nil && !errors.Is(activeErr, ErrNoValidBundle) {
			return AppliedBundle{}, b.deny(fmt.Errorf("%w; reading durable active policy: %w", activationErr, activeErr))
		}
		if (activeErr == nil && !strings.EqualFold(active.BundleHash, verified.baseHash)) ||
			(errors.Is(activeErr, ErrNoValidBundle) && verified.baseHash != "") {
			return AppliedBundle{}, b.deny(fmt.Errorf("%w; prior active policy changed during apply", activationErr))
		}
		return AppliedBundle{}, b.restoreOrDeny(activationErr)
	}
	b.markConsistent()
	return AppliedBundle{
		VerifiedBundle:     verified,
		ReloadedConfigHash: cfg.Hash(),
	}, nil
}

func (b Boundary) restoreOrDeny(cause error) error {
	if b.Restore != nil {
		if err := b.Restore(); err == nil {
			b.markConsistent()
			return cause
		} else {
			cause = fmt.Errorf("%w; restoring prior live policy: %w", cause, err)
		}
	}
	return b.deny(cause)
}

func (b Boundary) deny(cause error) error {
	uncertain := fmt.Errorf("%w: %w", ErrLivePolicyUncertain, cause)
	if b.Consistency != nil {
		b.Consistency(uncertain)
	}
	return uncertain
}

func (b Boundary) markConsistent() {
	if b.Consistency != nil {
		b.Consistency(nil)
	}
}

// RecoverActive re-verifies and reloads the durable active bundle into the
// current runtime. The active record is last-known-good disk state, not proof
// that this process can enforce it: a restarted follower must re-establish the
// signature, audience, not-before, and local-version gates before serving the
// cached policy. The stale enforcer owns expiry, grace, and admission after
// recovery. Recovery deliberately does not stage or activate anything;
// a failed verification must leave the durable last-good record untouched.
func (b Boundary) RecoverActive() (AppliedBundle, error) {
	if b.Cache == nil {
		return AppliedBundle{}, ErrCacheRequired
	}
	if b.Reload == nil {
		return AppliedBundle{}, errors.New("conductor apply boundary reload function required")
	}
	active, err := b.Cache.Active()
	if err != nil {
		return AppliedBundle{}, err
	}
	if err := verifyBundle(b.Cache.nowUTC(verifyOptions{Now: b.Now}), active.Bundle, verifyOptions{
		Identity:      b.Identity,
		Resolver:      b.Resolver,
		LocalVersion:  b.LocalVersion,
		Now:           b.Now,
		RecoverActive: true,
	}); err != nil {
		return AppliedBundle{}, err
	}
	cfg, err := b.loadVerifiedConfig(active)
	if err != nil {
		return AppliedBundle{}, fmt.Errorf("loading verified cached conductor policy bundle config: %w", err)
	}
	if b.StillEntitled != nil && !b.StillEntitled() {
		return AppliedBundle{}, ErrEntitlementLost
	}
	// Reload may publish before returning an error. Recovery owns the same
	// admission state as apply until the cached policy is fully installed.
	if b.Consistency != nil {
		b.Consistency(ErrLivePolicyUncertain)
	}
	if err := b.Reload(cfg); err != nil {
		return AppliedBundle{}, b.deny(fmt.Errorf("reloading verified cached conductor policy bundle config: %w", err))
	}
	b.markConsistent()
	return AppliedBundle{
		VerifiedBundle:     active,
		ReloadedConfigHash: cfg.Hash(),
	}, nil
}

// loadVerifiedConfig keeps parsing bound to the bytes whose signature was
// checked. Reopening ConfigPath would introduce a second, unverified input.
func (b Boundary) loadVerifiedConfig(verified VerifiedBundle) (*config.Config, error) {
	payload := []byte(verified.Bundle.Payload.ConfigYAML)
	if b.LoadConfig == nil {
		return config.LoadPolicyBundleBytes(payload)
	}
	cfg, err := b.LoadConfig(verified.ConfigPath)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	if cfg == nil || cfg.Hash() != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("%w: loaded config does not match signed bundle payload", ErrInvalidActiveRecord)
	}
	return cfg, nil
}
