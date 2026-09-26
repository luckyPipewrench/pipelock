// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"crypto/ed25519"
	"encoding/hex"
	"slices"
	"sync"
)

// heldReceiptKeys records, per evidence directory, every key a test fixture
// has signed receipts with. A fixture that appends under a new key is the
// legitimate rotation case, one process that held each key in turn, so it
// passes the keys held before as the emitter's PriorSignerKeys.
var (
	heldReceiptKeysMu sync.Mutex
	heldReceiptKeys   = map[string][]string{}
)

// priorKeysFor returns the keys previously used in dir and records priv's.
func priorKeysFor(dir string, priv ed25519.PrivateKey) []string {
	own := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	heldReceiptKeysMu.Lock()
	defer heldReceiptKeysMu.Unlock()
	prior := slices.Clone(heldReceiptKeys[dir])
	if !slices.Contains(prior, own) {
		heldReceiptKeys[dir] = append(heldReceiptKeys[dir], own)
	}
	return prior
}
