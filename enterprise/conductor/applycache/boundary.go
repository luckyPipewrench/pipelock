//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package applycache

import (
	"errors"
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

type ConfigLoader func(path string) (*config.Config, error)

type ReloadFunc func(*config.Config) error

type Boundary struct {
	Cache        *Cache
	Identity     Identity
	Resolver     conductor.SignatureKeyResolver
	LocalVersion string
	LoadConfig   ConfigLoader
	Reload       ReloadFunc
	Now          func() time.Time
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

func (b Boundary) Apply(bundle conductor.PolicyBundle, opts ApplyOptions) (AppliedBundle, error) {
	if b.Cache == nil {
		return AppliedBundle{}, ErrCacheRequired
	}
	if b.Reload == nil {
		return AppliedBundle{}, errors.New("conductor apply boundary reload function required")
	}
	loadConfig := b.LoadConfig
	if loadConfig == nil {
		loadConfig = config.Load
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
	cfg, err := loadConfig(verified.ConfigPath)
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
		return AppliedBundle{}, fmt.Errorf("reloading verified conductor policy bundle config: %w", err)
	}
	if err := b.Cache.activate(verified); err != nil {
		return AppliedBundle{}, fmt.Errorf("activating verified conductor policy bundle: %w", err)
	}
	return AppliedBundle{
		VerifiedBundle:     verified,
		ReloadedConfigHash: cfg.Hash(),
	}, nil
}
