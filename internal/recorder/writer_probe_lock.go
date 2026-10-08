// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !(js && wasm)

package recorder

import "os"

// snapshotWriterGone is unhandled where a platform lock exists or is refused;
// EvidenceWriterGone then uses the exclusive-lock probe.
func snapshotWriterGone(_ *os.File) (bool, bool, error) { return false, false, nil }
