// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package filesentry

type noopLineage struct{}

// NewLineage returns a no-op lineage tracker on non-Linux platforms.
func NewLineage() Lineage { return &noopLineage{} }

func (n *noopLineage) EnableSubreaper() error    { return nil }
func (n *noopLineage) TrackPID(_ int)            {}
func (n *noopLineage) IsDescendant(_ int) bool   { return false }
func (n *noopLineage) HasFileOpen(_ string) bool { return false }
