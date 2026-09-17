// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import "time"

// farFutureExpiry returns a containment metrics-exposure expiry far enough
// ahead that a fixture using it cannot age into an expired policy.
//
// It is computed rather than pinned because the policy's expiry is compared
// against the clock at runtime. A literal date makes the test's result depend
// on when it runs, so every such literal eventually turns the suite red on a
// calendar date with no commit involved.
func farFutureExpiry() string {
	return time.Now().UTC().AddDate(10, 0, 0).Format(time.RFC3339)
}
