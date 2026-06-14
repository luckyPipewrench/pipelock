// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/license"
)

// crlRollbackFixture holds the shared material for the rollback tests: a key
// pair, an active license token, and the on-disk CRL path that the consumer is
// configured to read. The high-water sidecar lives at crlPath + ".highwater".
type crlRollbackFixture struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	token   string
	crlPath string
	cfgPath string
}

func newCRLRollbackFixture(t *testing.T) *crlRollbackFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lic := license.License{
		ID:        "lic_rollback_active",
		Email:     "runtime@example.com",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(),
		Features:  []string{license.FeatureAgents},
	}
	token, err := license.Issue(lic, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	crlPath := filepath.Join(dir, "crl.json")
	cfgPath := writeServerTestConfig(t, "mode: balanced\nlicense_key: "+token+"\nlicense_public_key: "+hex.EncodeToString(pub)+"\nlicense_crl_file: "+crlPath+"\n")
	return &crlRollbackFixture{pub: pub, priv: priv, token: token, crlPath: crlPath, cfgPath: cfgPath}
}

// writeCRL signs a CRL at the given generation (revoking some unrelated id so it
// is a structurally valid, non-empty CRL) and writes it to the configured path.
func (f *crlRollbackFixture) writeCRL(t *testing.T, generation uint64) {
	t.Helper()
	now := time.Now().UTC()
	crl, err := license.SignCRL(license.CRLPayload{
		Version:    license.CRLVersion,
		Generation: generation,
		IssuedAt:   now.Add(-time.Hour).Unix(),
		ExpiresAt:  now.Add(24 * time.Hour).Unix(),
		Revoked: []license.RevokedLicense{{
			ID:        "lic_unrelated",
			RevokedAt: now.Add(-time.Hour).Unix(),
		}},
	}, f.priv)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(crl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.crlPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// newServer builds a fresh Server pointed at the fixture config. Building a new
// Server is how the tests simulate a process restart: any high-water state must
// come from disk, not from a prior Server's memory.
func (f *crlRollbackFixture) newServer(t *testing.T) *Server {
	t.Helper()
	s, _ := newTestServer(t, func(opts *ServerOpts) {
		opts.ConfigFile = f.cfgPath
	})
	return s
}

func mustCheck(t *testing.T, s *Server) (bool, error) {
	t.Helper()
	return s.checkLicenseCRL()
}

// TestCRLRollbackRejection drives the generation state machine: legacy/gen-0,
// advance, idempotent equal reload, and a rejected lower generation.
func TestCRLRollbackRejection(t *testing.T) {
	t.Run("legacy-gen-0-accepted", func(t *testing.T) {
		f := newCRLRollbackFixture(t)
		f.writeCRL(t, 0) // legacy / no generation field
		failClosed, err := mustCheck(t, f.newServer(t))
		if err != nil {
			t.Fatalf("gen 0 should be accepted: %v", err)
		}
		if failClosed {
			t.Fatal("gen 0 (legacy) must not fail closed")
		}
		gen, found, err := license.ReadCRLHighWater(f.crlPath)
		if err != nil {
			t.Fatalf("ReadCRLHighWater: %v", err)
		}
		if !found || gen != 0 {
			t.Fatalf("high-water = (%d, %v), want (0, true)", gen, found)
		}
	})

	t.Run("higher-generation-advances-high-water", func(t *testing.T) {
		f := newCRLRollbackFixture(t)
		f.writeCRL(t, 5)
		if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
			t.Fatalf("gen 5 should be accepted: failClosed=%v err=%v", failClosed, err)
		}
		gen, _, err := license.ReadCRLHighWater(f.crlPath)
		if err != nil || gen != 5 {
			t.Fatalf("high-water = %d (err %v), want 5", gen, err)
		}
		// A strictly higher generation advances it again.
		f.writeCRL(t, 9)
		if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
			t.Fatalf("gen 9 should be accepted: failClosed=%v err=%v", failClosed, err)
		}
		gen, _, _ = license.ReadCRLHighWater(f.crlPath)
		if gen != 9 {
			t.Fatalf("high-water = %d, want 9", gen)
		}
	})

	t.Run("equal-generation-idempotent", func(t *testing.T) {
		f := newCRLRollbackFixture(t)
		f.writeCRL(t, 7)
		if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
			t.Fatalf("first gen 7: failClosed=%v err=%v", failClosed, err)
		}
		// Re-loading the SAME generation must be accepted (idempotent).
		if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
			t.Fatalf("equal gen 7 reload should be accepted: failClosed=%v err=%v", failClosed, err)
		}
		gen, _, _ := license.ReadCRLHighWater(f.crlPath)
		if gen != 7 {
			t.Fatalf("high-water = %d, want 7 (unchanged)", gen)
		}
	})

	t.Run("lower-generation-rejected-fail-closed", func(t *testing.T) {
		f := newCRLRollbackFixture(t)
		f.writeCRL(t, 10)
		if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
			t.Fatalf("gen 10 should be accepted: failClosed=%v err=%v", failClosed, err)
		}
		// Attacker swaps in an OLDER signed CRL.
		f.writeCRL(t, 3)
		failClosed, err := mustCheck(t, f.newServer(t))
		if err == nil {
			t.Fatal("rolled-back gen 3 must error")
		}
		if !failClosed {
			t.Fatal("rolled-back CRL must fail closed")
		}
		if !strings.Contains(err.Error(), "rollback rejected") {
			t.Fatalf("error = %q, want rollback-rejected message", err)
		}
		// The high-water must NOT have regressed.
		gen, _, _ := license.ReadCRLHighWater(f.crlPath)
		if gen != 10 {
			t.Fatalf("high-water regressed to %d, want 10", gen)
		}
	})
}

// TestCRLRollbackSurvivesRestart is the load-bearing test: it proves the
// high-water is durable. After accepting a high generation, a brand-new Server
// instance (the "restart") presented with a lower-generation CRL must still
// reject it. If the high-water were in-memory only, the restart would reset to
// 0 and re-accept the rolled-back CRL.
func TestCRLRollbackSurvivesRestart(t *testing.T) {
	f := newCRLRollbackFixture(t)

	// First boot: accept a high generation, persisting the high-water.
	f.writeCRL(t, 42)
	if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
		t.Fatalf("gen 42 should be accepted on first boot: failClosed=%v err=%v", failClosed, err)
	}

	// Simulate a restart: a new Server reading the same on-disk state. Attacker
	// has swapped in an older, signature-valid, unexpired CRL.
	f.writeCRL(t, 11)
	restarted := f.newServer(t)
	failClosed, err := mustCheck(t, restarted)
	if err == nil {
		t.Fatal("post-restart rolled-back CRL must error (high-water did not survive restart)")
	}
	if !failClosed {
		t.Fatal("post-restart rolled-back CRL must fail closed")
	}
	if !strings.Contains(err.Error(), "rollback rejected") {
		t.Fatalf("error = %q, want rollback-rejected message", err)
	}
}

// TestCRLRollbackGen0AfterHigherRejected proves a generation-0 (legacy-shaped)
// CRL is rejected once a higher generation has been accepted. gen 0 only wins on
// a genuine first run; it must not be a downgrade path that drops revocations.
func TestCRLRollbackGen0AfterHigherRejected(t *testing.T) {
	f := newCRLRollbackFixture(t)
	f.writeCRL(t, 8)
	if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
		t.Fatalf("gen 8 should be accepted: failClosed=%v err=%v", failClosed, err)
	}
	f.writeCRL(t, 0)
	failClosed, err := mustCheck(t, f.newServer(t))
	if err == nil || !failClosed || !strings.Contains(err.Error(), "rollback rejected") {
		t.Fatalf("gen 0 after gen 8 must be rejected: failClosed=%v err=%v", failClosed, err)
	}
}

// TestCRLRollbackSidecarDeletionResidual documents the KNOWN residual: deleting
// the high-water sidecar makes "absent" look like a first run, so a subsequent
// lower-generation CRL is accepted. The control defends against CRL-file swaps,
// not against deletion of the sidecar (same write-trust boundary). This test
// pins the documented behavior so a future change that closes the gap is a
// deliberate, visible decision rather than a silent surprise.
func TestCRLRollbackSidecarDeletionResidual(t *testing.T) {
	f := newCRLRollbackFixture(t)
	f.writeCRL(t, 50)
	if failClosed, err := mustCheck(t, f.newServer(t)); err != nil || failClosed {
		t.Fatalf("gen 50 should be accepted: failClosed=%v err=%v", failClosed, err)
	}
	// Attacker deletes the sidecar and rolls the CRL back.
	if err := os.Remove(license.CRLHighWaterPath(f.crlPath)); err != nil {
		t.Fatal(err)
	}
	f.writeCRL(t, 2)
	failClosed, err := mustCheck(t, f.newServer(t))
	// Documented residual: this is currently ACCEPTED (treated as first run).
	if err != nil || failClosed {
		t.Fatalf("documented residual changed: sidecar-deletion rollback now blocked "+
			"(failClosed=%v err=%v); update the residual docs in license_crl_highwater.go", failClosed, err)
	}
}

// TestCRLRollbackConcurrentAcceptNoCorruption races several concurrent checks
// against the same files; the atomic high-water write must not corrupt the file
// or regress below the highest accepted generation.
func TestCRLRollbackConcurrentAcceptNoCorruption(t *testing.T) {
	f := newCRLRollbackFixture(t)
	f.writeCRL(t, 20)
	const workers = 8
	// Build servers on the test goroutine (t.Cleanup/t.Fatalf are not safe to
	// call from spawned goroutines); race only the checkLicenseCRL calls, which
	// is the path that reads and atomically rewrites the shared high-water file.
	servers := make([]*Server, workers)
	for i := range servers {
		servers[i] = f.newServer(t)
	}
	type checkResult struct {
		failClosed bool
		err        error
	}
	done := make(chan struct{})
	results := make(chan checkResult, workers)
	for _, s := range servers {
		go func(srv *Server) {
			defer func() { done <- struct{}{} }()
			failClosed, err := srv.checkLicenseCRL()
			results <- checkResult{failClosed: failClosed, err: err}
		}(s)
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	// Every concurrent check must accept the gen-20 CRL: the blocking
	// high-water lock serializes the read-compare-write, so none should fail
	// closed or error under contention.
	close(results)
	for r := range results {
		if r.err != nil || r.failClosed {
			t.Fatalf("concurrent check failed: failClosed=%v err=%v", r.failClosed, r.err)
		}
	}
	gen, found, err := license.ReadCRLHighWater(f.crlPath)
	if err != nil || !found || gen != 20 {
		t.Fatalf("after concurrent accepts high-water = (%d, %v, %v), want (20, true, nil)", gen, found, err)
	}
}

// TestCRLHighWaterCorruptFailsClosed proves an EXISTING but unreadable/corrupt
// high-water file fails closed rather than silently resetting to 0 (which would
// re-open the rollback window).
func TestCRLHighWaterCorruptFailsClosed(t *testing.T) {
	f := newCRLRollbackFixture(t)
	f.writeCRL(t, 4)
	// Corrupt the high-water sidecar: it EXISTS but is not valid JSON.
	if err := os.WriteFile(license.CRLHighWaterPath(f.crlPath), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	failClosed, err := mustCheck(t, f.newServer(t))
	if err == nil {
		t.Fatal("corrupt high-water must error")
	}
	if !failClosed {
		t.Fatal("corrupt high-water must fail closed")
	}
}

// TestCRLHighWaterStore exercises the store helper directly: absent file, write,
// read-back, oversized, and not-a-regular-file edges.
func TestCRLHighWaterStore(t *testing.T) {
	dir := t.TempDir()
	crlFile := filepath.Join(dir, "crl.json")

	// Absent: (0, false, nil) — first run, not an error.
	gen, found, err := license.ReadCRLHighWater(crlFile)
	if err != nil || found || gen != 0 {
		t.Fatalf("absent high-water = (%d, %v, %v), want (0, false, nil)", gen, found, err)
	}

	// Write then read back.
	if _, err := license.AdvanceCRLHighWater(crlFile, 17); err != nil {
		t.Fatalf("AdvanceCRLHighWater: %v", err)
	}
	gen, found, err = license.ReadCRLHighWater(crlFile)
	if err != nil || !found || gen != 17 {
		t.Fatalf("read-back = (%d, %v, %v), want (17, true, nil)", gen, found, err)
	}

	// Mode is 0o600 (no group/other access).
	info, err := os.Stat(license.CRLHighWaterPath(crlFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("high-water mode = %v, want 0o600", info.Mode().Perm())
	}

	// Oversized existing file fails closed.
	big := make([]byte, 4*1024+1)
	if err := os.WriteFile(license.CRLHighWaterPath(crlFile), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := license.ReadCRLHighWater(crlFile); err == nil {
		t.Fatal("oversized high-water must error")
	}

	// A directory at the high-water path (not a regular file) fails closed.
	dirCRL := filepath.Join(dir, "dircrl.json")
	if err := os.Mkdir(license.CRLHighWaterPath(dirCRL), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, _, err := license.ReadCRLHighWater(dirCRL); err == nil {
		t.Fatal("non-regular high-water must error")
	}
}

func TestCRLHighWaterAdvanceNeverRegresses(t *testing.T) {
	crlFile := filepath.Join(t.TempDir(), "crl.json")
	if _, err := license.AdvanceCRLHighWater(crlFile, 20); err != nil {
		t.Fatalf("advance to 20: %v", err)
	}
	if _, err := license.AdvanceCRLHighWater(crlFile, 10); err == nil {
		t.Fatal("advance to lower generation must fail closed")
	}
	gen, found, err := license.ReadCRLHighWater(crlFile)
	if err != nil || !found || gen != 20 {
		t.Fatalf("high-water after lower advance = (%d, %v, %v), want (20, true, nil)", gen, found, err)
	}
}
