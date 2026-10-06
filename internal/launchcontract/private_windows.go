// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

// Windows protects the per-user cache with ACLs rather than mode bits; the
// user profile directory is private by default.
func requirePrivate(string) error { return nil }

func requireCacheRoot(string) error { return nil }
