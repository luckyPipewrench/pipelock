//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

func freshMaterial(t *testing.T) (Layout, Options, controlplane.FollowerIdentity, *materialSet) {
	t.Helper()
	dir := privateFleetDir(t)
	opts := Options{Dir: dir}
	normalize(&opts)
	layout, err := newLayout(opts.Dir)
	if err != nil {
		t.Fatalf("newLayout: %v", err)
	}
	id := controlplane.FollowerIdentity{OrgID: opts.OrgID, FleetID: opts.FleetID, InstanceID: opts.InstanceID, Environment: opts.Environment}
	m, err := generateMaterial(layout, opts, id)
	if err != nil {
		t.Fatalf("generateMaterial: %v", err)
	}
	return layout, opts, id, m
}

// TestStartConductor_FailsClosed covers the fail-closed branches: a missing
// operator token or trust domain must abort startup rather than serve an
// unauthenticated or unidentifiable control plane.
func TestStartConductor_FailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(*Options, *materialSet)
	}{
		{"empty publisher token", func(_ *Options, m *materialSet) { m.publisherToken = "" }},
		{"empty auditor token", func(_ *Options, m *materialSet) { m.auditorToken = "" }},
		{"empty admin token", func(_ *Options, m *materialSet) { m.adminToken = "" }},
		{"empty trust domain", func(o *Options, _ *materialSet) { o.TrustDomain = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			layout, opts, _, m := freshMaterial(t)
			c.tamper(&opts, m)
			scratch, err := os.MkdirTemp(layout.Dir, ".proof-")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := startConductor(context.Background(), filepath.Join(scratch, "conductor"), opts, m); err == nil {
				t.Fatalf("startConductor (%s) should fail closed", c.name)
			}
		})
	}
}

// TestProduceSignedBatch_FailsOnUnwritableQueue: a queue directory path that is
// actually a file makes the durable queue open fail; production must surface
// the error rather than silently drop audit evidence.
func TestProduceSignedBatch_FailsOnUnwritableQueue(t *testing.T) {
	_, opts, id, _ := freshMaterial(t)
	dir := opts.Dir
	qfile := filepath.Join(dir, "queue-is-a-file")
	if err := os.WriteFile(qfile, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := produceSignedBatch(context.Background(), qfile, filepath.Join(dir, "r"), opts, id, priv, pub); err == nil {
		t.Fatal("produceSignedBatch with an unusable queue dir should error")
	}
}

// TestProduceSignedBatch_HonorsCancelledContext: a cancelled bootstrap must not
// produce or persist audit material (fail-closed on context cancellation).
func TestProduceSignedBatch_HonorsCancelledContext(t *testing.T) {
	_, opts, id, _ := freshMaterial(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := produceSignedBatch(ctx, filepath.Join(opts.Dir, "q"), filepath.Join(opts.Dir, "r"), opts, id, priv, pub); err == nil {
		t.Fatal("produceSignedBatch with a cancelled context should fail closed")
	}
}

// TestVerifyBatchOffline_RejectsWrongKey: the offline verifier must reject a
// batch when checked against the wrong audit public key.
func TestVerifyBatchOffline_RejectsWrongKey(t *testing.T) {
	h := newHarness(t)
	batch := h.signedBatch(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyBatchOffline(batch.Envelope, otherPub); err == nil {
		t.Fatal("offline verification accepted a batch against the wrong key")
	}
	// Sanity: the right key still verifies.
	if err := verifyBatchOffline(batch.Envelope, h.auditPub); err != nil {
		t.Fatalf("offline verification rejected a valid batch: %v", err)
	}
}
