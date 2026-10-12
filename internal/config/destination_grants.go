// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// DestinationGrant authorizes one exact TCP destination. It does not disable
// content scanning or the non-overridable address floor.
type DestinationGrant struct {
	Protocol string `yaml:"protocol"`
	Host     string `yaml:"host"`
	Port     uint16 `yaml:"port"`
}

// DestinationGrantSet validates and compiles the complete operator grant list.
// Scanner construction also calls this boundary, so unvalidated callers cannot
// install a partial or malformed authorization set.
func (c *Config) DestinationGrantSet() (destination.GrantSet, error) {
	grants := make([]destination.Grant, 0, len(c.DestinationGrants))
	for i, entry := range c.DestinationGrants {
		label := fmt.Sprintf("destination_grants[%d]", i)
		if entry.Protocol != destination.NetworkTCP.String() {
			return destination.GrantSet{}, fmt.Errorf("%s: protocol must be tcp", label)
		}
		if strings.Contains(entry.Host, "*") {
			return destination.GrantSet{}, fmt.Errorf("%s: host must be exact", label)
		}
		grant, err := destination.NewGrant(destination.NetworkTCP, entry.Host, entry.Port)
		if err != nil {
			return destination.GrantSet{}, fmt.Errorf("%s: %w", label, err)
		}
		if err := ValidateHostMatchList([]string{grant.Destination().Host}, label+".host"); err != nil {
			return destination.GrantSet{}, err
		}
		grants = append(grants, grant)
	}
	return destination.NewGrantSet(grants...)
}

// canonicalDestinationGrants mirrors the compiled set without mutating config.
func canonicalDestinationGrants(entries []DestinationGrant) []DestinationGrant {
	if len(entries) == 0 {
		return nil
	}
	out := make([]DestinationGrant, 0, len(entries))
	seen := make(map[DestinationGrant]bool, len(entries))
	for _, entry := range entries {
		if dest, err := destination.New(destination.Network(entry.Protocol), entry.Host, entry.Port); err == nil {
			entry.Host = dest.Host
		}
		if !seen[entry] {
			seen[entry] = true
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Port < b.Port
	})
	return out
}

func destinationGrantsAdded(old, updated []DestinationGrant) bool {
	seen := make(map[DestinationGrant]bool, len(old))
	for _, entry := range canonicalDestinationGrants(old) {
		seen[entry] = true
	}
	for _, entry := range canonicalDestinationGrants(updated) {
		if !seen[entry] {
			return true
		}
	}
	return false
}
