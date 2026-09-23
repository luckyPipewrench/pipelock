// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package anchor

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// TestAnchorStateMarkerIsRecorderOwned ties the marker name this package
// writes to the recorder's definition of the files it owns in an evidence
// directory. The recorder cannot import this package, so this test is what
// fails if the two names drift apart and the marker becomes overwritable.
func TestAnchorStateMarkerIsRecorderOwned(t *testing.T) {
	t.Parallel()
	if !recorder.IsRecorderOwnedFile(legacyStateMarker) {
		t.Fatalf("recorder.IsRecorderOwnedFile(%q) = false; the anchor-state marker would be unprotected", legacyStateMarker)
	}
}
