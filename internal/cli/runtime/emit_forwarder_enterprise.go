//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"fmt"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/siemforward"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func appendEnterpriseEmitSinks(cfg *config.Config, sinks []emit.Sink, observer emitDeliveryObserver) ([]emit.Sink, error) {
	forwardCfg := cfg.Emit.Forwarder
	if forwardCfg.URL == "" {
		return sinks, nil
	}
	// The forwarder's SSRF floor must not inherit `internal: null`, which is a
	// deliberate escape hatch for the main request scanner. Forwarding always
	// denies the immutable default ranges plus any operator-added ranges.
	ssrfCfg := cfg.WithSIEMForwarderSSRFFloor()
	ssrfScanner := scanner.New(ssrfCfg)
	forwarder, err := siemforward.New(siemforward.Config{
		URL:               forwardCfg.URL,
		AllowedHosts:      forwardCfg.DestinationAllowlist,
		SpoolFile:         forwardCfg.SpoolFile,
		CursorFile:        forwardCfg.CursorFile,
		AuthToken:         forwardCfg.AuthToken,
		QueueSize:         forwardCfg.QueueSize,
		Timeout:           time.Duration(forwardCfg.TimeoutSeconds) * time.Second,
		MinSeverity:       emit.ParseSeverity(forwardCfg.MinSeverity),
		MaxSpoolBytes:     forwardCfg.MaxSpoolBytes,
		AllowInsecureHTTP: forwardCfg.AllowInsecureHTTP,
	}, siemforward.Options{
		Resolver:      ssrfScanner.HostResolver(),
		IsInternalIP:  ssrfScanner.IsInternalIP,
		Close:         ssrfScanner.Close,
		Observer:      observer,
		DeferredStart: true,
	})
	if err != nil {
		ssrfScanner.Close()
		return sinks, fmt.Errorf("creating durable SIEM forwarder: %w", err)
	}
	return append(sinks, forwarder), nil
}
