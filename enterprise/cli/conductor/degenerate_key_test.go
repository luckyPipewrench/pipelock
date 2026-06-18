//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"crypto/ed25519"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestLoadFleetReportSigningKey_RejectsDegenerate proves the conductor signing
// key loader inherits the seed->stored-pub consistency check: a JSON keyfile
// whose private AND public halves are both all-zero passes the loader's
// stored-pub-vs-declared-pub agreement check (both zero), so only the
// derivation check rejects it. This is a representative parallel path for the
// other direct JSON signing-key loaders, which apply the same consistency check.
func TestLoadFleetReportSigningKey_RejectsDegenerate(t *testing.T) {
	dir := t.TempDir()

	zero := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize))
	zeroPath := writeFleetReportKeyFile(t, dir, "zero.key", "zero-1", signing.PurposeFleetReportSigning, zero)
	if _, _, err := loadFleetReportSigningKey(zeroPath); err == nil {
		t.Fatal("loadFleetReportSigningKey accepted an all-zero degenerate key (fail-open)")
	}

	_, realKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	realPath := writeFleetReportKeyFile(t, dir, "real.key", "real-1", signing.PurposeFleetReportSigning, realKey)
	id, got, err := loadFleetReportSigningKey(realPath)
	if err != nil {
		t.Fatalf("loadFleetReportSigningKey rejected a real key: %v", err)
	}
	if id != "real-1" || !got.Equal(realKey) {
		t.Fatalf("unexpected load result: id=%q keyMatches=%v", id, got.Equal(realKey))
	}
}
