//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"os"
	"testing"
)

func writePrivateTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
