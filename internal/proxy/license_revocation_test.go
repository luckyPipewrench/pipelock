// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
)

type revocationTestEdition struct {
	edition.Edition
	revoked bool
}

func (e *revocationTestEdition) SetLicenseRevoked(revoked bool) { e.revoked = revoked }

func TestLicenseRevocationRejectsStaleConfiguration(t *testing.T) {
	t.Parallel()
	old := config.Defaults()
	next := old.Clone()
	p := &Proxy{}
	p.cfgPtr.Store(old)
	ed := &revocationTestEdition{}
	p.editionPtr.Store(&editionSnapshot{Edition: ed})
	if !p.SetLicenseRevoked(old, true) || !ed.revoked {
		t.Fatal("current configuration did not revoke")
	}
	p.cfgPtr.Store(next)
	if p.SetLicenseRevoked(old, false) || !ed.revoked {
		t.Fatal("stale recovery cleared current revocation")
	}
	if !p.SetLicenseRevoked(next, false) || ed.revoked {
		t.Fatal("current recovery failed")
	}
	if p.SetLicenseRevoked(old, true) || ed.revoked {
		t.Fatal("stale failure revoked new configuration")
	}
	p.editionPtr.Store(&editionSnapshot{})
	if !p.SetLicenseRevoked(next, true) {
		t.Fatal("edition without revocation receiver rejected current configuration")
	}
}
