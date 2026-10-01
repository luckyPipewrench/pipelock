// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package egress binds candidate secret-egress decisions to explicit registry
// manifests. It does not declare production coverage or authorize release.
package egress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/egressevidence"
)

// RegistryManifestVersion versions the complete-site registry digest recipe.
const RegistryManifestVersion = 1

// RegistryManifest returns the repository's JCS-profile canonical bytes of
// {"manifest_kind":"secret_egress_registry","manifest_version":1,"sites":[...]}.
// Sites are ordered by ascending ASCII ID; each complete Site contributes the
// lowercase keys id, plane, transport, location, view, boundary. JCS sorts
// object keys, so canonical site key order is boundary,id,location,plane,
// transport,view. The manifest describes obligations, not instrumentation.
func RegistryManifest(registry *egressevidence.Registry) ([]byte, error) {
	sites := registry.All()
	if len(sites) == 0 {
		return nil, fmt.Errorf("secret egress registry is empty")
	}
	entries := make([]any, 0, len(sites))
	for _, site := range sites {
		entries = append(entries, map[string]any{
			"id": string(site.ID), "plane": string(site.Plane),
			"transport": string(site.Transport), "location": string(site.Location),
			"view": string(site.View), "boundary": string(site.Boundary),
		})
	}
	// Registry construction has already validated these bounded ASCII strings;
	// this tree contains only the integer/string/container types accepted by
	// the existing signing canonicalizer, with no JSON parser reinterpretation.
	return contract.Canonicalize(map[string]any{
		"manifest_kind":    "secret_egress_registry",
		"manifest_version": RegistryManifestVersion,
		"sites":            entries,
	})
}

// RegistryHash hashes RegistryManifest bytes as sha256:<64 lowercase hex>.
// Offline receipt validation checks only this grammar; binding the digest to
// a trusted registry and establishing signed coverage are separate operations.
func RegistryHash(registry *egressevidence.Registry) (string, error) {
	manifest, err := RegistryManifest(registry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(manifest)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
