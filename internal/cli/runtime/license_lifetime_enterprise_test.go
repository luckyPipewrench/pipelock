//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

func TestLicenseExpiryWatchdogClosesCIDRGeneration(t *testing.T) {
	oldFactory := edition.NewEditionFunc
	edition.NewEditionFunc = enterprise.NewEdition
	t.Cleanup(func() { edition.NewEditionFunc = oldFactory })
	token, pub := realValidAgentsLicense(t)
	path := writeServerTestConfig(t, "mode: balanced\nlicense_require_intermediate: false\nlicense_key: "+token+"\nlicense_public_key: "+pub+"\nagents:\n  client:\n    source_cidrs: [192.0.2.0/24]\n")
	s, _ := newTestServer(t, func(o *ServerOpts) {
		o.ConfigFile = path
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
	})
	if len(s.proxy.Ports()) != 0 || s.proxy.CurrentConfig().Conductor.Enabled {
		t.Fatal("positive control must have no dedicated listener or Conductor")
	}
	// Set the already-verified entitlement's runtime deadline before serving.
	s.cfg.LicenseExpiresAt = time.Now().Add(2 * time.Second).Unix()
	ra, ok := s.proxy.Edition().LookupProfile("client")
	if !ok || ra.LicenseRevoked == nil {
		t.Fatal("positive control: paid profile missing")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	waitForServerCancel(t, s)
	select {
	case <-ra.LicenseRevoked:
	case <-time.After(5 * time.Second):
		t.Fatal("CIDR-only expiry did not end the generation")
	}
	if _, ok := s.proxy.Edition().LookupProfile("client"); ok {
		t.Fatal("expiry retained named resolution")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not stop")
	}
}
