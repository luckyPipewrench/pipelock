// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

func SetChildSubreaper() error { return nil }
func ReapOrphans()             {}
