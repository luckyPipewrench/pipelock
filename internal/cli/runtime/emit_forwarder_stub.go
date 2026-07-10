// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !enterprise

package runtime

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func appendEnterpriseEmitSinks(cfg *config.Config, sinks []emit.Sink, _ emitDeliveryObserver) ([]emit.Sink, error) {
	if cfg.Emit.Forwarder.URL != "" {
		return sinks, errors.New("emit.forwarder requires an enterprise build")
	}
	return sinks, nil
}
