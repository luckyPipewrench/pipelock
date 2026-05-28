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
