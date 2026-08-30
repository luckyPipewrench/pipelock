// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint returns a deterministic digest of the complete emit
// configuration. The canonical bytes may contain sink credentials, so callers
// receive only the digest and must not log the serialized representation.
func (c EmitConfig) Fingerprint() string {
	canonical := fmt.Sprintf("%#v", c)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}
