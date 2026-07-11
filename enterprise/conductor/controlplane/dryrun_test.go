//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// --- store spies: count mutation calls so a dry-run's ZERO-write invariant is
// provable by call count, not just by inspecting on-disk bytes. ---

type spyBundleStore struct {
	*FileBundleStore
	publishCalls       int
	applyRollbackCalls int
}

func (s *spyBundleStore) Publish(ctx context.Context, b conductor.PolicyBundle, opts PublishOptions) (PublishedBundle, bool, error) {
	s.publishCalls++
	return s.FileBundleStore.Publish(ctx, b, opts)
}

func (s *spyBundleStore) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	s.applyRollbackCalls++
	return s.FileBundleStore.ApplyRollbackHead(ctx, auth, now)
}

type spyEmergencyStore struct {
	*FileEmergencyStore
	publishKillCalls     int
	publishRollbackCalls int
}

func (s *spyEmergencyStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	s.publishKillCalls++
	return s.FileEmergencyStore.PublishRemoteKill(ctx, msg, now)
}

func (s *spyEmergencyStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	s.publishRollbackCalls++
	return s.FileEmergencyStore.PublishRollbackAuthorization(ctx, auth, now)
}

type spyHandler struct {
	handler      *Handler
	bundle       *spyBundleStore
	emergency    *spyEmergencyStore
	bundleDir    string
	emergencyDir string
}

var errDryRunTestStore = errors.New("dry-run test store failure")

type bundleStoreNoPreview struct {
	inner BundleStore
}

func (s bundleStoreNoPreview) Publish(ctx context.Context, bundle conductor.PolicyBundle, opts PublishOptions) (PublishedBundle, bool, error) {
	return s.inner.Publish(ctx, bundle, opts)
}

func (s bundleStoreNoPreview) Latest(ctx context.Context, follower FollowerIdentity, now time.Time) (PublishedBundle, error) {
	return s.inner.Latest(ctx, follower, now)
}

func (s bundleStoreNoPreview) BundleByIDVersion(ctx context.Context, bundleID string, version uint64) (PublishedBundle, error) {
	return s.inner.BundleByIDVersion(ctx, bundleID, version)
}

func (s bundleStoreNoPreview) ApplyRollbackHead(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) error {
	return s.inner.ApplyRollbackHead(ctx, auth, now)
}

func (s bundleStoreNoPreview) StreamOverview(ctx context.Context, q StreamStatusQuery) ([]StreamSummary, error) {
	return s.inner.StreamOverview(ctx, q)
}

type publishPreviewErrorStore struct {
	BundleStore
	err error
}

func (s publishPreviewErrorStore) PreviewPublish(context.Context, conductor.PolicyBundle, PublishOptions) (PublishPreview, error) {
	return PublishPreview{}, s.err
}

type bundleLookupErrorStore struct {
	BundleStore
	err error
}

func (s bundleLookupErrorStore) BundleByIDVersion(context.Context, string, uint64) (PublishedBundle, error) {
	return PublishedBundle{}, s.err
}

func (s bundleLookupErrorStore) PreviewPublish(ctx context.Context, bundle conductor.PolicyBundle, opts PublishOptions) (PublishPreview, error) {
	previewer := s.BundleStore.(publishPreviewer)
	return previewer.PreviewPublish(ctx, bundle, opts)
}

type rollbackHeadPreviewErrorStore struct {
	BundleStore
	err error
}

func (s rollbackHeadPreviewErrorStore) PreviewRollbackHead(context.Context, conductor.RollbackAuthorization) (RollbackHeadPreview, error) {
	return RollbackHeadPreview{}, s.err
}

type emergencyStoreNoPreview struct {
	inner EmergencyStore
}

func (s emergencyStoreNoPreview) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	return s.inner.PublishRemoteKill(ctx, msg, now)
}

func (s emergencyStoreNoPreview) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	return s.inner.LatestRemoteKill(ctx, follower, now)
}

func (s emergencyStoreNoPreview) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (s emergencyStoreNoPreview) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	return s.inner.LatestRollbackAuthorization(ctx, follower, lookup, now)
}

func (s emergencyStoreNoPreview) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.ActiveRollbackForFollower(ctx, follower, now)
}

type remoteKillPreviewErrorStore struct {
	inner EmergencyStore
	err   error
}

func (s remoteKillPreviewErrorStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	return s.inner.PublishRemoteKill(ctx, msg, now)
}

func (s remoteKillPreviewErrorStore) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	return s.inner.LatestRemoteKill(ctx, follower, now)
}

func (s remoteKillPreviewErrorStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (s remoteKillPreviewErrorStore) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	return s.inner.LatestRollbackAuthorization(ctx, follower, lookup, now)
}

func (s remoteKillPreviewErrorStore) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.ActiveRollbackForFollower(ctx, follower, now)
}

func (s remoteKillPreviewErrorStore) PreviewRemoteKill(context.Context, conductor.RemoteKillMessage, time.Time) (RemoteKillPreview, error) {
	return RemoteKillPreview{}, s.err
}

type remoteKillEnumeratorErrorStore struct {
	inner EmergencyStore
	err   error
}

func (s remoteKillEnumeratorErrorStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	return s.inner.PublishRemoteKill(ctx, msg, now)
}

func (s remoteKillEnumeratorErrorStore) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	return s.inner.LatestRemoteKill(ctx, follower, now)
}

func (s remoteKillEnumeratorErrorStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (s remoteKillEnumeratorErrorStore) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	return s.inner.LatestRollbackAuthorization(ctx, follower, lookup, now)
}

func (s remoteKillEnumeratorErrorStore) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.ActiveRollbackForFollower(ctx, follower, now)
}

func (s remoteKillEnumeratorErrorStore) PreviewRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (RemoteKillPreview, error) {
	previewer := s.inner.(remoteKillPreviewer)
	return previewer.PreviewRemoteKill(ctx, msg, now)
}

func (s remoteKillEnumeratorErrorStore) RemoteKills(context.Context) ([]StoredRemoteKill, error) {
	return nil, s.err
}

type rollbackAuthPreviewErrorStore struct {
	inner EmergencyStore
	err   error
}

func (s rollbackAuthPreviewErrorStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	return s.inner.PublishRemoteKill(ctx, msg, now)
}

func (s rollbackAuthPreviewErrorStore) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	return s.inner.LatestRemoteKill(ctx, follower, now)
}

func (s rollbackAuthPreviewErrorStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (s rollbackAuthPreviewErrorStore) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	return s.inner.LatestRollbackAuthorization(ctx, follower, lookup, now)
}

func (s rollbackAuthPreviewErrorStore) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.ActiveRollbackForFollower(ctx, follower, now)
}

func (s rollbackAuthPreviewErrorStore) PreviewRollbackAuthorization(context.Context, conductor.RollbackAuthorization, time.Time) (RollbackAuthPreview, error) {
	return RollbackAuthPreview{}, s.err
}

func (s rollbackAuthPreviewErrorStore) RollbackAuthorizations(ctx context.Context) ([]StoredRollbackAuthorization, error) {
	switch lister := s.inner.(type) {
	case rollbackAuthorizationEnumerator:
		return lister.RollbackAuthorizations(ctx)
	case rawRollbackEnumerator:
		return lister.enumerateRollbacks(ctx)
	default:
		return nil, nil
	}
}

type rollbackAuthorizationEnumeratorErrorStore struct {
	inner EmergencyStore
	err   error
}

func (s rollbackAuthorizationEnumeratorErrorStore) PublishRemoteKill(ctx context.Context, msg conductor.RemoteKillMessage, now time.Time) (StoredRemoteKill, bool, error) {
	return s.inner.PublishRemoteKill(ctx, msg, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) LatestRemoteKill(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRemoteKill, error) {
	return s.inner.LatestRemoteKill(ctx, follower, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) PublishRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.PublishRollbackAuthorization(ctx, auth, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) LatestRollbackAuthorization(ctx context.Context, follower FollowerIdentity, lookup RollbackLookup, now time.Time) (StoredRollbackAuthorization, error) {
	return s.inner.LatestRollbackAuthorization(ctx, follower, lookup, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) ActiveRollbackForFollower(ctx context.Context, follower FollowerIdentity, now time.Time) (StoredRollbackAuthorization, bool, error) {
	return s.inner.ActiveRollbackForFollower(ctx, follower, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) PreviewRollbackAuthorization(ctx context.Context, auth conductor.RollbackAuthorization, now time.Time) (RollbackAuthPreview, error) {
	previewer := s.inner.(rollbackAuthPreviewer)
	return previewer.PreviewRollbackAuthorization(ctx, auth, now)
}

func (s rollbackAuthorizationEnumeratorErrorStore) RollbackAuthorizations(context.Context) ([]StoredRollbackAuthorization, error) {
	return nil, s.err
}

// newSpyHandler builds a handler whose bundle + emergency stores are spies over
// real file stores, so tests can assert both "no mutation method was called" and
// "the on-disk bytes are identical" across a dry-run.
func newSpyHandler(t *testing.T, emergencyKeys conductor.SignatureKeyResolver) spyHandler {
	t.Helper()
	bundleDir := t.TempDir()
	fileStore, err := OpenFileBundleStore(bundleDir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	emergencyDir := t.TempDir()
	fileEmergency, err := OpenFileEmergencyStore(emergencyDir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore() error = %v", err)
	}
	bundleSpy := &spyBundleStore{FileBundleStore: fileStore}
	emergencySpy := &spyEmergencyStore{FileEmergencyStore: fileEmergency}
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	publisher := func(r *http.Request) error {
		if r.Header.Get("X-Pipelock-Publisher") != "ok" {
			return ErrPublisherForbidden
		}
		return nil
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              bundleSpy,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: publisher,
		AuthorizeBundle:    func(r *http.Request, _ conductor.PolicyBundle) error { return publisher(r) },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("X-Pipelock-Admin") != "ok" {
				return ErrPublisherForbidden
			}
			return nil
		},
		EmergencyControls: emergencySpy,
		EmergencyKeys:     emergencyKeys,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return spyHandler{handler: handler, bundle: bundleSpy, emergency: emergencySpy, bundleDir: bundleDir, emergencyDir: emergencyDir}
}

func newDryRunTestHandler(t *testing.T, store BundleStore, emergency EmergencyStore, emergencyKeys conductor.SignatureKeyResolver) *Handler {
	t.Helper()
	if store == nil {
		store = mustStore(t)
	}
	publisher := func(r *http.Request) error {
		if r.Header.Get("X-Pipelock-Publisher") != "ok" {
			return ErrPublisherForbidden
		}
		return nil
	}
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              store,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: publisher,
		AuthorizeBundle:    func(r *http.Request, _ conductor.PolicyBundle) error { return publisher(r) },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("X-Pipelock-Admin") != "ok" {
				return ErrPublisherForbidden
			}
			return nil
		},
		EmergencyControls: emergency,
		EmergencyKeys:     emergencyKeys,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func seedRollbackReplayBundles(t *testing.T, store *FileBundleStore, prefix string) (conductor.PolicyBundle, conductor.PolicyBundle) {
	t.Helper()
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	target := signedControlBundle(t, signer, bundleSpec{
		id:       prefix + "-target",
		version:  1,
		audience: audience,
	})
	targetRec, _, err := store.Publish(context.Background(), target, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(%s target) error = %v", prefix, err)
	}
	current := signedControlBundle(t, signer, bundleSpec{
		id:           prefix + "-current",
		version:      2,
		previousHash: targetRec.BundleHash,
		audience:     audience,
		configYAML:   "mode: strict\napi_allowlist:\n  - " + prefix + ".example.com\n",
	})
	if _, _, err := store.Publish(context.Background(), current, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(%s current) error = %v", prefix, err)
	}
	return current, target
}

func dirDigest(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	// Collect regular-file paths first, then read them after the walk returns, so
	// no filesystem read happens inside the WalkDir callback (gosec G122).
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("dirDigest(%s) walk error = %v", dir, err)
	}
	out := make(map[string][32]byte, len(paths))
	for _, path := range paths {
		data, readErr := os.ReadFile(filepath.Clean(path))
		if readErr != nil {
			t.Fatalf("dirDigest(%s) read %s error = %v", dir, path, readErr)
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			t.Fatalf("dirDigest(%s) rel error = %v", dir, relErr)
		}
		out[rel] = sha256.Sum256(data)
	}
	return out
}

func assertDirUnchanged(t *testing.T, dir string, before map[string][32]byte) {
	t.Helper()
	after := dirDigest(t, dir)
	if len(after) != len(before) {
		t.Fatalf("dir %s file count changed: before=%d after=%d", dir, len(before), len(after))
	}
	for rel, sum := range before {
		got, ok := after[rel]
		if !ok {
			t.Fatalf("dir %s lost file %s after dry-run", dir, rel)
		}
		if got != sum {
			t.Fatalf("dir %s file %s bytes changed after dry-run", dir, rel)
		}
	}
}

// publishJSON marshals a publish request and serves it, returning the recorder.
func publishJSON(t *testing.T, handler *Handler, req publishPolicyBundleRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal publish request: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	r.Header.Set("X-Pipelock-Publisher", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func decodePublishEvaluation(t *testing.T, w *httptest.ResponseRecorder) PublishEvaluation {
	t.Helper()
	var eval PublishEvaluation
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode publish evaluation: %v (body=%s)", err, w.Body.String())
	}
	return eval
}

func TestEmergencyConflictCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "stale_counter",
			err:  fmt.Errorf("wrapped: %w", ErrEmergencyStaleCounter),
			want: EmergencyConflictStaleCounter,
		},
		{
			name: "id_conflict",
			err:  fmt.Errorf("wrapped: %w", ErrEmergencyConflict),
			want: EmergencyConflictIDConflict,
		},
		{
			name: "default",
			err:  errors.New("other conflict"),
			want: EmergencyConflictIDConflict,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := emergencyConflictCode(tc.err); got != tc.want {
				t.Fatalf("emergencyConflictCode(%v)=%q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestPublishDryRun_ValidWouldCreate_NoWrite proves invariant 2 (ZERO writes) and
// the create half of invariant 1 (dry-run says would-create; the real apply then
// creates).
func TestPublishDryRun_ValidWouldCreate_NoWrite(t *testing.T) {
	sh := newSpyHandler(t, nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-dry-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	before := dirDigest(t, sh.bundleDir)
	w := publishJSON(t, sh.handler, publishPolicyBundleRequest{Bundle: bundle, DryRun: true})
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run publish code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	eval := decodePublishEvaluation(t, w)
	if !eval.DryRun || !eval.Valid || !eval.WouldCreate || eval.ResultVersion != 1 {
		t.Fatalf("dry-run publish eval=%+v, want dry_run+valid+would_create version 1", eval)
	}
	if sh.bundle.publishCalls != 0 {
		t.Fatalf("dry-run called Publish %d times, want 0", sh.bundle.publishCalls)
	}
	assertDirUnchanged(t, sh.bundleDir, before)

	// Real apply on identical input now creates (parity with the dry-run verdict).
	w = publishJSON(t, sh.handler, publishPolicyBundleRequest{Bundle: bundle})
	if w.Code != http.StatusCreated {
		t.Fatalf("real publish code=%d body=%s, want 201", w.Code, w.Body.String())
	}
	if sh.bundle.publishCalls != 1 {
		t.Fatalf("real publish called Publish %d times, want 1", sh.bundle.publishCalls)
	}
}

// TestPublishDryRunApplyParity proves invariant 1: for the same inputs and state,
// a dry-run's conflict verdict carries the SAME machine-readable code the real
// apply's 409 carries — no divergence.
func TestPublishDryRunApplyParity(t *testing.T) {
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}

	setup := func(t *testing.T) (*Handler, PublishedBundle) {
		handler := newTestHandler(t, mustStore(t), nil)
		v1 := signedControlBundle(t, signer, bundleSpec{id: "bundle-parity-1", version: 1, audience: audience})
		if w := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: v1}); w.Code != http.StatusCreated {
			t.Fatalf("seed v1 code=%d body=%s", w.Code, w.Body.String())
		}
		r1, err := handler.store.BundleByIDVersion(context.Background(), "bundle-parity-1", 1)
		if err != nil {
			t.Fatalf("BundleByIDVersion(v1) error = %v", err)
		}
		return handler, r1
	}

	cases := []struct {
		name     string
		bundle   func(handler *Handler, r1 PublishedBundle) conductor.PolicyBundle
		wantCode string
	}{
		{
			name: "id_version_conflict",
			bundle: func(_ *Handler, _ PublishedBundle) conductor.PolicyBundle {
				// Same id/version, different config -> different hash -> generic conflict.
				return signedControlBundle(t, signer, bundleSpec{
					id: "bundle-parity-1", version: 1, audience: audience,
					configYAML: "mode: strict\napi_allowlist:\n  - other.example.com\n",
				})
			},
			wantCode: PublishConflictOther,
		},
		{
			name: "version_below_stream_max",
			bundle: func(handler *Handler, r1 PublishedBundle) conductor.PolicyBundle {
				// Publish v2 to raise the stream max, then attempt a fresh id at v2.
				v2 := signedControlBundle(t, signer, bundleSpec{
					id: "bundle-parity-2", version: 2, previousHash: r1.BundleHash, audience: audience,
					configYAML: "mode: strict\napi_allowlist:\n  - v2.example.com\n",
				})
				if w := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: v2}); w.Code != http.StatusCreated {
					t.Fatalf("seed v2 code=%d body=%s", w.Code, w.Body.String())
				}
				return signedControlBundle(t, signer, bundleSpec{
					id: "bundle-parity-below", version: 2, audience: audience,
					configYAML: "mode: strict\napi_allowlist:\n  - below.example.com\n",
				})
			},
			wantCode: PublishConflictVersionBelowStreamMax,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, r1 := setup(t)
			bundle := tc.bundle(handler, r1)

			// Dry-run: HTTP 200 + valid=false + conflict code.
			dry := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: bundle, DryRun: true})
			if dry.Code != http.StatusOK {
				t.Fatalf("dry-run conflict code=%d body=%s, want 200", dry.Code, dry.Body.String())
			}
			eval := decodePublishEvaluation(t, dry)
			if eval.Valid || eval.Conflict != tc.wantCode {
				t.Fatalf("dry-run eval=%+v, want valid=false conflict=%q", eval, tc.wantCode)
			}

			// Real apply on identical input: HTTP 409 + the SAME code.
			realResp := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: bundle})
			if realResp.Code != http.StatusConflict {
				t.Fatalf("real publish code=%d body=%s, want 409", realResp.Code, realResp.Body.String())
			}
			var body struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(realResp.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode real conflict body: %v", err)
			}
			if body.Code != tc.wantCode {
				t.Fatalf("real conflict code=%q, want %q (dry-run reported %q)", body.Code, tc.wantCode, eval.Conflict)
			}
		})
	}
}

// TestPublishDryRun_Unauthorized proves invariant 3: a dry-run is gated by the
// SAME authorizer as a real publish and is rejected with the same 403.
func TestPublishDryRun_Unauthorized(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-unauth-1", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle, DryRun: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// No X-Pipelock-Publisher header.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("unauthorized dry-run code=%d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestPublishDryRun_ErrorBranches(t *testing.T) {
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-dry-errors", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	cases := []struct {
		name  string
		store BundleStore
	}{
		{
			name:  "previewer_unsupported",
			store: bundleStoreNoPreview{inner: mustStore(t)},
		},
		{
			name:  "preview_store_error",
			store: publishPreviewErrorStore{BundleStore: mustStore(t), err: errDryRunTestStore},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newDryRunTestHandler(t, tc.store, nil, nil)
			w := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: bundle, DryRun: true})
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("publish dry-run %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// TestPublishDryRun_FleetSkewBlockedParity proves the fleet-skew preflight blocks
// a dry-run exactly as it blocks a real apply (same reason), using the live
// enrollment + runtime-status path.
func TestPublishDryRun_FleetSkewBlockedParity(t *testing.T) {
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	identity := defaultFollowerIdentity()
	mustEnrollFollower(t, enrollments, "tok-skew-1", identity, "audit-key-skew-1")
	// A follower on a below-minimum pipelock version is "unsupported" -> skew block.
	status := runtimeStatus(identity, "0.9.0", strings.Repeat("a", 64))
	if _, err := enrollments.UpsertFollowerRuntimeStatus(context.Background(), status); err != nil {
		t.Fatalf("UpsertFollowerRuntimeStatus() error = %v", err)
	}
	handler := newRuntimeStatusTestHandler(t, enrollments, identity)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-skew-1", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})

	serve := func(dryRun bool) *httptest.ResponseRecorder {
		body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle, DryRun: dryRun})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, bytes.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+followerAdminToken)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}

	dry := serve(true)
	if dry.Code != http.StatusOK {
		t.Fatalf("dry-run skew code=%d body=%s, want 200", dry.Code, dry.Body.String())
	}
	eval := decodePublishEvaluation(t, dry)
	if eval.Valid || eval.Conflict != PublishConflictFleetSkew {
		t.Fatalf("dry-run skew eval=%+v, want valid=false conflict=fleet_skew", eval)
	}
	if eval.Preflight.Unsupported != 1 {
		t.Fatalf("dry-run skew preflight=%+v, want unsupported=1", eval.Preflight)
	}

	realResp := serve(false)
	if realResp.Code != http.StatusConflict {
		t.Fatalf("real skew code=%d body=%s, want 409", realResp.Code, realResp.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(realResp.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode real skew body: %v", err)
	}
	if body.Code != PublishConflictFleetSkew {
		t.Fatalf("real skew code=%q, want fleet_skew", body.Code)
	}
}

// --- remote-kill dry-run ---

func remoteKillJSON(t *testing.T, handler *Handler, req publishRemoteKillRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal remote kill request: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, RemoteKillPath, bytes.NewReader(body))
	r.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestRemoteKillDryRun_Valid_NoWrite(t *testing.T) {
	msg, resolver := signedRemoteKillMessageWithResolver(t, "kill-dry-1", 1, conductor.KillSwitchActive, testNow)
	sh := newSpyHandler(t, resolver)
	before := dirDigest(t, sh.emergencyDir)
	w := remoteKillJSON(t, sh.handler, publishRemoteKillRequest{Message: msg, DryRun: true})
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run kill code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var eval RemoteKillEvaluation
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode kill eval: %v", err)
	}
	if !eval.DryRun || !eval.Valid || !eval.WouldCreate || eval.Counter != 1 {
		t.Fatalf("dry-run kill eval=%+v, want dry_run+valid+would_create counter 1", eval)
	}
	if sh.emergency.publishKillCalls != 0 {
		t.Fatalf("dry-run called PublishRemoteKill %d times, want 0", sh.emergency.publishKillCalls)
	}
	assertDirUnchanged(t, sh.emergencyDir, before)
}

// TestPreviewRemoteKill_StaleCounterParity proves the remote-kill preview and the
// real publish reach the SAME stale-counter verdict and the preview writes
// nothing (invariants 1 + 2 at the store's shared decision core).
func TestPreviewRemoteKill_StaleCounterParity(t *testing.T) {
	store := mustEmergencyStore(t)
	ctx := context.Background()
	high := signedRemoteKillMessage(t, "kill-high", 5, conductor.KillSwitchActive, testNow)
	if _, created, err := store.PublishRemoteKill(ctx, high, testNow); err != nil || !created {
		t.Fatalf("seed high kill created=%v err=%v, want created", created, err)
	}
	stale := signedRemoteKillMessage(t, "kill-stale", 3, conductor.KillSwitchActive, testNow)

	preview, err := store.PreviewRemoteKill(ctx, stale, testNow)
	if !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PreviewRemoteKill(stale) err=%v preview=%+v, want ErrEmergencyStaleCounter", err, preview)
	}
	// Preview wrote nothing: enumerate still shows exactly the one seeded record.
	kills, err := store.enumerateRemoteKills(ctx)
	if err != nil {
		t.Fatalf("enumerateRemoteKills() error = %v", err)
	}
	if len(kills) != 1 {
		t.Fatalf("after preview stored kills=%d, want 1 (no write)", len(kills))
	}
	// Real publish reaches the identical verdict.
	if _, _, err := store.PublishRemoteKill(ctx, stale, testNow); !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PublishRemoteKill(stale) err=%v, want ErrEmergencyStaleCounter (parity with preview)", err)
	}
}

func TestRemoteKillDryRun_ExpiredNoWrite(t *testing.T) {
	msg, resolver := signedRemoteKillMessageWithTTL(t, "kill-expired", 1, conductor.KillSwitchActive, testNow.Add(-2*time.Hour), time.Hour)
	sh := newSpyHandler(t, resolver)
	before := dirDigest(t, sh.emergencyDir)
	w := remoteKillJSON(t, sh.handler, publishRemoteKillRequest{Message: msg, DryRun: true})
	// Expired window is rejected before the preview branch, same as the real path.
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("dry-run expired kill code=%d body=%s, want 422", w.Code, w.Body.String())
	}
	if sh.emergency.publishKillCalls != 0 {
		t.Fatalf("expired dry-run called PublishRemoteKill %d times, want 0", sh.emergency.publishKillCalls)
	}
	assertDirUnchanged(t, sh.emergencyDir, before)
}

func TestRemoteKillDryRun_StaleCounterConflict(t *testing.T) {
	high := signedRemoteKillMessage(t, "kill-dry-high", 5, conductor.KillSwitchActive, testNow)
	stale, resolver := signedRemoteKillMessageWithResolver(t, "kill-dry-stale", 3, conductor.KillSwitchActive, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRemoteKill(context.Background(), high, testNow); err != nil || !created {
		t.Fatalf("seed high kill created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, nil, emergency, resolver)

	w := remoteKillJSON(t, handler, publishRemoteKillRequest{Message: stale, DryRun: true})
	if w.Code != http.StatusOK {
		t.Fatalf("stale kill dry-run code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var eval RemoteKillEvaluation
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode stale kill eval: %v", err)
	}
	if eval.Valid || eval.Conflict != EmergencyConflictStaleCounter || eval.Counter != stale.Counter {
		t.Fatalf("stale kill eval=%+v, want valid=false conflict=stale_counter counter=%d", eval, stale.Counter)
	}
}

func TestRemoteKillDryRun_ErrorBranches(t *testing.T) {
	cases := []struct {
		name      string
		emergency EmergencyStore
	}{
		{
			name:      "previewer_unsupported",
			emergency: emergencyStoreNoPreview{inner: mustEmergencyStore(t)},
		},
		{
			name:      "preview_store_error",
			emergency: remoteKillPreviewErrorStore{inner: mustEmergencyStore(t), err: errDryRunTestStore},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, resolver := signedRemoteKillMessageWithResolver(t, "kill-dry-error-"+strings.ReplaceAll(tc.name, "_", "-"), 1, conductor.KillSwitchActive, testNow)
			handler := newDryRunTestHandler(t, nil, tc.emergency, resolver)
			w := remoteKillJSON(t, handler, publishRemoteKillRequest{Message: msg, DryRun: true})
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("remote-kill dry-run %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// --- rollback dry-run ---

func rollbackJSON(t *testing.T, handler *Handler, req publishRollbackAuthorizationRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal rollback request: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, RollbackAuthorizationsPath, bytes.NewReader(body))
	r.Header.Set("X-Pipelock-Admin", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestRollbackDryRun_Valid_NoWrite(t *testing.T) {
	// Pre-seed the chain via a plain file store, then hand the SAME dir to a spy
	// handler so the rollback preview sees the published target/current.
	dir := t.TempDir()
	seedStore, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	audience := conductor.Audience{InstanceIDs: []string{"*"}}
	target := signedControlBundle(t, signer, bundleSpec{id: "rb-target", version: 1, audience: audience})
	targetRec, _, err := seedStore.Publish(context.Background(), target, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(target) error = %v", err)
	}
	current := signedControlBundle(t, signer, bundleSpec{
		id: "rb-current", version: 2, previousHash: targetRec.BundleHash, audience: audience,
		configYAML: "mode: strict\napi_allowlist:\n  - current.example.com\n",
	})
	if _, _, err := seedStore.Publish(context.Background(), current, PublishOptions{Now: testNow.Add(time.Minute)}); err != nil {
		t.Fatalf("Publish(current) error = %v", err)
	}
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-1", current, target, testNow)

	// Reopen the seeded dir under a spy handler.
	fileStore, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("reopen bundle store: %v", err)
	}
	bundleSpy := &spyBundleStore{FileBundleStore: fileStore}
	emergencyDir := t.TempDir()
	fileEmergency, err := OpenFileEmergencyStore(emergencyDir)
	if err != nil {
		t.Fatalf("OpenFileEmergencyStore() error = %v", err)
	}
	emergencySpy := &spyEmergencyStore{FileEmergencyStore: fileEmergency}
	enrollments, err := OpenFileEnrollmentStore(filepath.Join(t.TempDir(), "enrollments.json"))
	if err != nil {
		t.Fatalf("OpenFileEnrollmentStore() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:              bundleSpy,
		Capabilities:       DefaultCapabilities("conductor-test"),
		Now:                func() time.Time { return testNow },
		FollowerIdentity:   func(*http.Request) (FollowerIdentity, error) { return defaultFollowerIdentity(), nil },
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
		Enrollments:        enrollments,
		AuthorizeAdmin: func(r *http.Request) error {
			if r.Header.Get("X-Pipelock-Admin") != "ok" {
				return ErrPublisherForbidden
			}
			return nil
		},
		EmergencyControls: emergencySpy,
		EmergencyKeys:     resolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	bundleBefore := dirDigest(t, dir)
	emergencyBefore := dirDigest(t, emergencyDir)
	w := rollbackJSON(t, handler, publishRollbackAuthorizationRequest{Authorization: auth, DryRun: true})
	if w.Code != http.StatusOK {
		t.Fatalf("dry-run rollback code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var eval RollbackEvaluation
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode rollback eval: %v", err)
	}
	if !eval.DryRun || !eval.Valid || eval.WouldRollToVersion != 1 || eval.CurrentHeadVersion != 2 || eval.Noop {
		t.Fatalf("dry-run rollback eval=%+v, want valid+would_roll_to 1+head 2+not noop", eval)
	}
	if bundleSpy.applyRollbackCalls != 0 || emergencySpy.publishRollbackCalls != 0 {
		t.Fatalf("dry-run rollback mutated: applyRollback=%d publishRollback=%d, want 0/0",
			bundleSpy.applyRollbackCalls, emergencySpy.publishRollbackCalls)
	}
	assertDirUnchanged(t, dir, bundleBefore)
	assertDirUnchanged(t, emergencyDir, emergencyBefore)
}

func TestRollbackDryRun_ErrorBranches(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (*Handler, conductor.RollbackAuthorization)
	}{
		{
			name: "auth_previewer_unsupported",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-dry-auth-unsupported")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-auth-unsupported", current, target, testNow)
				handler := newDryRunTestHandler(t, store, emergencyStoreNoPreview{inner: mustEmergencyStore(t)}, resolver)
				return handler, auth
			},
		},
		{
			name: "head_previewer_unsupported",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-dry-head-unsupported")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-head-unsupported", current, target, testNow)
				handler := newDryRunTestHandler(t, bundleStoreNoPreview{inner: store}, mustEmergencyStore(t), resolver)
				return handler, auth
			},
		},
		{
			name: "auth_preview_store_error",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-dry-auth-error")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-auth-error", current, target, testNow)
				emergency := rollbackAuthPreviewErrorStore{inner: mustEmergencyStore(t), err: errDryRunTestStore}
				handler := newDryRunTestHandler(t, store, emergency, resolver)
				return handler, auth
			},
		},
		{
			name: "head_preview_store_error",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-dry-head-error")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-head-error", current, target, testNow)
				wrappedStore := rollbackHeadPreviewErrorStore{BundleStore: store, err: errDryRunTestStore}
				handler := newDryRunTestHandler(t, wrappedStore, mustEmergencyStore(t), resolver)
				return handler, auth
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, auth := tc.setup(t)
			w := rollbackJSON(t, handler, publishRollbackAuthorizationRequest{Authorization: auth, DryRun: true})
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("rollback dry-run %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestRollbackDryRun_StaleCounterConflict(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-dry-stale")
	stale, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-dry-stale", current, target, testNow)
	high := signedRollbackAuthorization(t, "rb-dry-stale-high", 5, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), high, testNow); err != nil || !created {
		t.Fatalf("seed high rollback created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, store, emergency, resolver)

	w := rollbackJSON(t, handler, publishRollbackAuthorizationRequest{Authorization: stale, DryRun: true})
	if w.Code != http.StatusOK {
		t.Fatalf("stale rollback dry-run code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	var eval RollbackEvaluation
	if err := json.Unmarshal(w.Body.Bytes(), &eval); err != nil {
		t.Fatalf("decode stale rollback eval: %v", err)
	}
	if eval.Valid || eval.Conflict != EmergencyConflictStaleCounter || eval.Counter != stale.Counter {
		t.Fatalf("stale rollback eval=%+v, want valid=false conflict=stale_counter counter=%d", eval, stale.Counter)
	}
}

// TestPreviewRollbackAuthorization_StaleCounterParity mirrors the remote-kill
// stale-counter parity test for the rollback authorization store: preview and
// real publish reach the same verdict and the preview writes nothing.
func TestPreviewRollbackAuthorization_StaleCounterParity(t *testing.T) {
	store := mustEmergencyStore(t)
	ctx := context.Background()
	high := signedRollbackAuthorization(t, "rb-high", 5, testNow)
	if _, created, err := store.PublishRollbackAuthorization(ctx, high, testNow); err != nil || !created {
		t.Fatalf("seed high rollback created=%v err=%v, want created", created, err)
	}
	stale := signedRollbackAuthorization(t, "rb-low", 3, testNow)

	preview, err := store.PreviewRollbackAuthorization(ctx, stale, testNow)
	if !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PreviewRollbackAuthorization(stale) err=%v preview=%+v, want ErrEmergencyStaleCounter", err, preview)
	}
	rollbacks, err := store.enumerateRollbacks(ctx)
	if err != nil {
		t.Fatalf("enumerateRollbacks() error = %v", err)
	}
	if len(rollbacks) != 1 {
		t.Fatalf("after preview stored rollbacks=%d, want 1 (no write)", len(rollbacks))
	}
	if _, _, err := store.PublishRollbackAuthorization(ctx, stale, testNow); !errors.Is(err, ErrEmergencyStaleCounter) {
		t.Fatalf("PublishRollbackAuthorization(stale) err=%v, want ErrEmergencyStaleCounter (parity)", err)
	}
}

// --- decision replay ---

func replayJSON(t *testing.T, handler *Handler, req decisionReplayRequest, admin, publisher bool) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal replay request: %v", err)
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, DecisionReplayPath, bytes.NewReader(body))
	if admin {
		r.Header.Set("X-Pipelock-Admin", "ok")
	}
	if publisher {
		r.Header.Set("X-Pipelock-Publisher", "ok")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func decodeReplay(t *testing.T, w *httptest.ResponseRecorder) DecisionReplayResult {
	t.Helper()
	var result DecisionReplayResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode replay result: %v (body=%s)", err, w.Body.String())
	}
	return result
}

func TestReplayPublish_RecordedMatchesRederived_NoDivergence(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-1", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if w := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: bundle}); w.Code != http.StatusCreated {
		t.Fatalf("seed publish code=%d body=%s", w.Code, w.Body.String())
	}
	w := replayJSON(t, handler, decisionReplayRequest{Bundle: &bundle}, false, true)
	if w.Code != http.StatusOK {
		t.Fatalf("replay code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.ActionKind != actionKindPublish {
		t.Fatalf("replay action_kind=%q, want publish", result.ActionKind)
	}
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("replay recorded=%+v, want present+accepted", result.Recorded)
	}
	if result.Divergence {
		t.Fatalf("replay divergence=true, want false (recorded matches re-derived)")
	}
	// Re-derived against current state: the identical bundle is already stored, so
	// the decision is idempotent (valid, would_create=false).
	if result.PublishEvaluation == nil || !result.PublishEvaluation.Valid || result.PublishEvaluation.WouldCreate {
		t.Fatalf("replay eval=%+v, want valid + idempotent (would_create=false)", result.PublishEvaluation)
	}
}

func TestReplayPublish_SnapshotDivergence(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-div", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if w := publishJSON(t, handler, publishPolicyBundleRequest{Bundle: bundle}); w.Code != http.StatusCreated {
		t.Fatalf("seed publish code=%d body=%s", w.Code, w.Body.String())
	}
	identity := defaultFollowerIdentity()
	// Snapshot with an unsupported follower -> re-derivation would fleet-skew-block,
	// but the record is accepted -> divergence.
	snapshot := &decisionReplaySnapshot{
		Followers: []FollowerSummary{{
			OrgID: identity.OrgID, FleetID: identity.FleetID, InstanceID: identity.InstanceID,
			Environment: identity.Environment, Active: true,
		}},
		RuntimeStatuses: []FollowerRuntimeStatus{{
			OrgID: identity.OrgID, FleetID: identity.FleetID, InstanceID: identity.InstanceID,
			Environment: identity.Environment, PipelockVersion: "0.9.0", LastSeenAt: testNow,
		}},
	}
	w := replayJSON(t, handler, decisionReplayRequest{Bundle: &bundle, Snapshot: snapshot}, false, true)
	if w.Code != http.StatusOK {
		t.Fatalf("replay snapshot code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if !result.UsedStateSnapshot {
		t.Fatalf("replay used_state_snapshot=false, want true")
	}
	if result.PublishEvaluation == nil || result.PublishEvaluation.Valid || result.PublishEvaluation.Conflict != PublishConflictFleetSkew {
		t.Fatalf("replay eval=%+v, want valid=false conflict=fleet_skew under snapshot", result.PublishEvaluation)
	}
	if !result.Divergence {
		t.Fatalf("replay divergence=false, want true (recorded accepted but re-derived blocked)")
	}
}

func TestReplayPublish_UnknownArtifact_EvaluationOnly(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-unknown", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	// Never published.
	w := replayJSON(t, handler, decisionReplayRequest{Bundle: &bundle}, false, true)
	if w.Code != http.StatusOK {
		t.Fatalf("replay unknown code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded != nil {
		t.Fatalf("replay unknown recorded=%+v, want nil (no recorded decision)", result.Recorded)
	}
	if result.Divergence {
		t.Fatalf("replay unknown divergence=true, want false")
	}
	if result.PublishEvaluation == nil || !result.PublishEvaluation.Valid || !result.PublishEvaluation.WouldCreate {
		t.Fatalf("replay unknown eval=%+v, want valid+would_create", result.PublishEvaluation)
	}
}

func TestReplayRollback_RecordedMatchesRederived_NoDivergence(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-match")
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-match", current, target, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("seed rollback created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, store, emergency, resolver)

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback replay code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.ActionKind != actionKindRollback {
		t.Fatalf("rollback replay action_kind=%q, want rollback", result.ActionKind)
	}
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("rollback replay recorded=%+v, want present+accepted", result.Recorded)
	}
	if result.Rollback == nil || !result.Rollback.Valid || result.Rollback.WouldRollToVersion != 1 {
		t.Fatalf("rollback replay eval=%+v, want valid+would_roll_to version 1", result.Rollback)
	}
	if result.Divergence {
		t.Fatalf("rollback replay divergence=true, want false")
	}
}

func TestReplayRollback_Divergence(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-div")
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-div", current, target, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("seed rollback created=%v err=%v, want created", created, err)
	}
	divergentEmergency := rollbackAuthPreviewErrorStore{
		inner: emergency,
		err:   fmt.Errorf("%w: forced replay divergence", ErrEmergencyStaleCounter),
	}
	handler := newDryRunTestHandler(t, store, divergentEmergency, resolver)

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback replay divergence code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("rollback replay divergence recorded=%+v, want present+accepted", result.Recorded)
	}
	if result.Rollback == nil || result.Rollback.Valid || result.Rollback.Conflict != EmergencyConflictStaleCounter {
		t.Fatalf("rollback replay divergence eval=%+v, want valid=false conflict=stale_counter", result.Rollback)
	}
	if !result.Divergence {
		t.Fatalf("rollback replay divergence=false, want true")
	}
}

func TestReplayRollback_HeadPreviewFailureReturnsStructuredDivergence(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-head-preview")
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-head-preview", current, target, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), auth, testNow); err != nil || !created {
		t.Fatalf("seed rollback created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, rollbackHeadPreviewErrorStore{BundleStore: store, err: errDryRunTestStore}, emergency, resolver)

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback replay head-preview code=%d body=%s, want 200 structured divergence", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("rollback replay head-preview recorded=%+v, want present+accepted", result.Recorded)
	}
	if result.Rollback == nil || result.Rollback.Valid || result.Rollback.Conflict != RollbackConflictHeadPreviewFailed {
		t.Fatalf("rollback replay head-preview eval=%+v, want valid=false conflict=head_preview_failed", result.Rollback)
	}
	if !result.Divergence || result.DivergenceReason == "" {
		t.Fatalf("rollback replay head-preview divergence=%v reason=%q, want structured divergence", result.Divergence, result.DivergenceReason)
	}
	// The raw backend store error must not leak into the caller-visible
	// response: it can carry paths, keys, or operational internals. The
	// DivergenceReason must be the stable canned string only.
	if strings.Contains(result.DivergenceReason, errDryRunTestStore.Error()) || strings.Contains(w.Body.String(), errDryRunTestStore.Error()) {
		t.Fatalf("raw store error leaked into replay response: reason=%q body=%s", result.DivergenceReason, w.Body.String())
	}
}

func TestReplayRollback_HistoricalRecordedDecisionSurvivesExpiredKey(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-historical-key")
	recordedAt := testNow.Add(-30 * time.Minute)
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-historical-key", current, target, recordedAt)
	expiringResolver := resolverWithKeyNotAfter(t, resolver, testNow.Add(-15*time.Minute))
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), auth, recordedAt); err != nil || !created {
		t.Fatalf("seed rollback created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, store, emergency, expiringResolver)

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback replay expired-key code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("rollback replay expired-key recorded=%+v, want present+accepted historical decision", result.Recorded)
	}
}

func TestReplayRollback_HistoricalRecordedDecisionRejectsRevokedKey(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-revoked-key")
	recordedAt := testNow.Add(-30 * time.Minute)
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-revoked-key", current, target, recordedAt)
	revokedResolver := resolverWithKeyRevokedAt(t, resolver, testNow.Add(-15*time.Minute))
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRollbackAuthorization(context.Background(), auth, recordedAt); err != nil || !created {
		t.Fatalf("seed rollback created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, store, emergency, revokedResolver)
	hash, err := auth.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(rollback): %v", err)
	}
	recorded, err := handler.recordedRollback(context.Background(), hash)
	if err != nil {
		t.Fatalf("recordedRollback(revoked): %v", err)
	}
	if recorded != nil {
		t.Fatalf("recordedRollback(revoked) = %+v, want nil because revocation overrides historical replay", recorded)
	}

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("rollback replay revoked-key code=%d body=%s, want 422", w.Code, w.Body.String())
	}
}

func TestReplayRollback_UnknownArtifact_EvaluationOnly(t *testing.T) {
	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-unknown")
	auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-unknown", current, target, testNow)
	handler := newDryRunTestHandler(t, store, mustEmergencyStore(t), resolver)

	w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("rollback replay unknown code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded != nil {
		t.Fatalf("rollback replay unknown recorded=%+v, want nil", result.Recorded)
	}
	if result.Rollback == nil || !result.Rollback.Valid || !result.Rollback.WouldCreate {
		t.Fatalf("rollback replay unknown eval=%+v, want valid+would_create", result.Rollback)
	}
	if result.Divergence {
		t.Fatalf("rollback replay unknown divergence=true, want false")
	}
}

func TestReplayRemoteKill_RecordedMatchesRederived_NoDivergence(t *testing.T) {
	msg, resolver := signedRemoteKillMessageWithResolver(t, "kill-replay-match", 1, conductor.KillSwitchActive, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRemoteKill(context.Background(), msg, testNow); err != nil || !created {
		t.Fatalf("seed remote kill created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, nil, emergency, resolver)

	w := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("remote-kill replay code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.ActionKind != actionKindRemoteKill {
		t.Fatalf("remote-kill replay action_kind=%q, want remote_kill", result.ActionKind)
	}
	if result.Recorded == nil || !result.Recorded.Accepted {
		t.Fatalf("remote-kill replay recorded=%+v, want present+accepted", result.Recorded)
	}
	if result.RemoteKill == nil || !result.RemoteKill.Valid || result.RemoteKill.WouldCreate {
		t.Fatalf("remote-kill replay eval=%+v, want valid + idempotent", result.RemoteKill)
	}
	if result.Divergence {
		t.Fatalf("remote-kill replay divergence=true, want false")
	}
}

func TestReplayRemoteKill_StaleCounterEvaluation(t *testing.T) {
	high := signedRemoteKillMessage(t, "kill-replay-high", 5, conductor.KillSwitchActive, testNow)
	stale, resolver := signedRemoteKillMessageWithResolver(t, "kill-replay-stale", 3, conductor.KillSwitchActive, testNow)
	emergency := mustEmergencyStore(t)
	if _, created, err := emergency.PublishRemoteKill(context.Background(), high, testNow); err != nil || !created {
		t.Fatalf("seed high remote kill created=%v err=%v, want created", created, err)
	}
	handler := newDryRunTestHandler(t, nil, emergency, resolver)

	w := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &stale}, true, false)
	if w.Code != http.StatusOK {
		t.Fatalf("remote-kill stale replay code=%d body=%s, want 200", w.Code, w.Body.String())
	}
	result := decodeReplay(t, w)
	if result.Recorded != nil {
		t.Fatalf("remote-kill stale replay recorded=%+v, want nil", result.Recorded)
	}
	if result.RemoteKill == nil || result.RemoteKill.Valid || result.RemoteKill.Conflict != EmergencyConflictStaleCounter {
		t.Fatalf("remote-kill stale replay eval=%+v, want valid=false conflict=stale_counter", result.RemoteKill)
	}
	if result.Divergence {
		t.Fatalf("remote-kill stale replay divergence=true, want false")
	}
}

func TestReplay_RequiresExactlyOneArtifact(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-count", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	msg := signedRemoteKillMessage(t, "kill-replay-count", 1, conductor.KillSwitchActive, testNow)
	cases := []struct {
		name string
		req  decisionReplayRequest
	}{
		{
			name: "none",
			req:  decisionReplayRequest{},
		},
		{
			name: "multiple",
			req:  decisionReplayRequest{Bundle: &bundle, RemoteKill: &msg},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := replayJSON(t, handler, tc.req, true, true)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("replay artifact count %s code=%d body=%s, want 400", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestReplayPublish_ErrorBranches(t *testing.T) {
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-errors", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	cases := []struct {
		name  string
		store BundleStore
	}{
		{
			name:  "previewer_unsupported",
			store: bundleStoreNoPreview{inner: mustStore(t)},
		},
		{
			name:  "preview_store_error",
			store: publishPreviewErrorStore{BundleStore: mustStore(t), err: errDryRunTestStore},
		},
		{
			name:  "recorded_lookup_error",
			store: bundleLookupErrorStore{BundleStore: mustStore(t), err: errDryRunTestStore},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := newDryRunTestHandler(t, tc.store, nil, nil)
			w := replayJSON(t, handler, decisionReplayRequest{Bundle: &bundle}, false, true)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("publish replay %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestReplayRemoteKill_ErrorBranches(t *testing.T) {
	cases := []struct {
		name      string
		emergency EmergencyStore
	}{
		{
			name:      "previewer_unsupported",
			emergency: emergencyStoreNoPreview{inner: mustEmergencyStore(t)},
		},
		{
			name:      "preview_store_error",
			emergency: remoteKillPreviewErrorStore{inner: mustEmergencyStore(t), err: errDryRunTestStore},
		},
		{
			name:      "recorded_enumerator_error",
			emergency: remoteKillEnumeratorErrorStore{inner: mustEmergencyStore(t), err: errDryRunTestStore},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg, resolver := signedRemoteKillMessageWithResolver(t, "kill-replay-error-"+strings.ReplaceAll(tc.name, "_", "-"), 1, conductor.KillSwitchActive, testNow)
			handler := newDryRunTestHandler(t, nil, tc.emergency, resolver)
			w := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg}, true, false)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("remote-kill replay %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestReplayRollback_ErrorBranches(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (*Handler, conductor.RollbackAuthorization)
	}{
		{
			name: "auth_previewer_unsupported",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-replay-auth-unsupported")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-auth-unsupported", current, target, testNow)
				handler := newDryRunTestHandler(t, store, emergencyStoreNoPreview{inner: mustEmergencyStore(t)}, resolver)
				return handler, auth
			},
		},
		{
			name: "head_previewer_unsupported",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-replay-head-unsupported")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-head-unsupported", current, target, testNow)
				handler := newDryRunTestHandler(t, bundleStoreNoPreview{inner: store}, mustEmergencyStore(t), resolver)
				return handler, auth
			},
		},
		{
			name: "auth_preview_store_error",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-replay-auth-error")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-auth-error", current, target, testNow)
				emergency := rollbackAuthPreviewErrorStore{inner: mustEmergencyStore(t), err: errDryRunTestStore}
				handler := newDryRunTestHandler(t, store, emergency, resolver)
				return handler, auth
			},
		},
		{
			name: "head_preview_store_error",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-replay-head-error")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-head-error", current, target, testNow)
				wrappedStore := rollbackHeadPreviewErrorStore{BundleStore: store, err: errDryRunTestStore}
				handler := newDryRunTestHandler(t, wrappedStore, mustEmergencyStore(t), resolver)
				return handler, auth
			},
		},
		{
			name: "recorded_enumerator_error",
			setup: func(t *testing.T) (*Handler, conductor.RollbackAuthorization) {
				store := mustStore(t)
				current, target := seedRollbackReplayBundles(t, store, "rb-replay-recorded-error")
				auth, resolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-recorded-error", current, target, testNow)
				emergency := mustEmergencyStore(t)
				handler := newDryRunTestHandler(t, store, emergency, resolver)
				handler.emergencyControls = newVerifiedEmergencyStore(
					rollbackAuthorizationEnumeratorErrorStore{inner: emergency, err: errDryRunTestStore},
					resolver,
					nil,
					nil,
				)
				return handler, auth
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, auth := tc.setup(t)
			w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("rollback replay %s code=%d body=%s, want 500", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestReplay_Unauthorized(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id: "bundle-replay-unauth", version: 1, audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	// No publisher header -> replay-publish must 403 (same authorizer as real publish).
	w := replayJSON(t, handler, decisionReplayRequest{Bundle: &bundle}, false, false)
	if w.Code != http.StatusForbidden {
		t.Fatalf("replay unauthorized code=%d body=%s, want 403", w.Code, w.Body.String())
	}
}

func TestReplayEmergency_RejectsSnapshotTimeOverride(t *testing.T) {
	msg, resolver := signedRemoteKillMessageWithTTL(t, "kill-replay-expired", 1, conductor.KillSwitchActive, testNow.Add(-2*time.Hour), time.Hour)
	handler := newTestHandlerWithOptions(t, mustStore(t), nil, resolver)
	snapshot := &decisionReplaySnapshot{Now: msg.NotBefore.Add(30 * time.Minute)}

	w := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg, Snapshot: snapshot}, true, false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay kill with snapshot code=%d body=%s, want 400", w.Code, w.Body.String())
	}

	w = replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg}, true, false)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replay expired kill code=%d body=%s, want 422", w.Code, w.Body.String())
	}

	store := mustStore(t)
	current, target := seedRollbackReplayBundles(t, store, "rb-replay-expired")
	auth, rollbackResolver := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-expired", current, target, testNow.Add(-2*time.Hour))
	rollbackHandler := newTestHandlerWithOptions(t, store, nil, rollbackResolver)
	snapshot = &decisionReplaySnapshot{Now: auth.CreatedAt.Add(30 * time.Minute)}

	w = replayJSON(t, rollbackHandler, decisionReplayRequest{Rollback: &auth, Snapshot: snapshot}, true, false)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("replay rollback with snapshot code=%d body=%s, want 400", w.Code, w.Body.String())
	}

	w = replayJSON(t, rollbackHandler, decisionReplayRequest{Rollback: &auth}, true, false)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("replay expired rollback code=%d body=%s, want 422", w.Code, w.Body.String())
	}
}

func TestReplayEmergency_EnforcesPublishValidation(t *testing.T) {
	t.Run("remote kill max validity", func(t *testing.T) {
		msg, resolver := signedRemoteKillMessageWithTTL(t, "kill-replay-long", 1, conductor.KillSwitchActive, testNow, DefaultRemoteKillMaxValidity+time.Minute)
		handler := newTestHandlerWithOptions(t, mustStore(t), nil, resolver)

		w := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg}, true, false)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("replay overlong remote kill code=%d body=%s, want 422", w.Code, w.Body.String())
		}
	})

	t.Run("rollback max validity", func(t *testing.T) {
		store := mustStore(t)
		current, target := seedRollbackReplayBundles(t, store, "rb-replay-long")
		auth, _ := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-long", current, target, testNow)
		auth.ExpiresAt = auth.CreatedAt.Add(DefaultRollbackMaxValidity + time.Minute)
		resolver := resignRollbackAuthorization(t, &auth)
		handler := newTestHandlerWithOptions(t, store, nil, resolver)

		w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("replay overlong rollback code=%d body=%s, want 422", w.Code, w.Body.String())
		}
	})

	t.Run("rollback audience", func(t *testing.T) {
		store := mustStore(t)
		current, target := seedRollbackReplayBundles(t, store, "rb-replay-audience")
		auth, _ := signedRollbackAuthorizationForBundlesWithResolver(t, "rb-replay-audience", current, target, testNow)
		auth.Audience = conductor.Audience{InstanceIDs: []string{"pl-prod-1"}}
		resolver := resignRollbackAuthorization(t, &auth)
		handler := newTestHandlerWithOptions(t, store, nil, resolver)

		w := replayJSON(t, handler, decisionReplayRequest{Rollback: &auth}, true, false)
		if w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("replay rollback with audience code=%d body=%s, want 422", w.Code, w.Body.String())
		}
	})
}

func resignRollbackAuthorization(t *testing.T, auth *conductor.RollbackAuthorization) conductor.SignatureKeyResolver {
	t.Helper()
	var resolver conductor.SignatureKeyResolver
	auth.Signatures, resolver = signConductorPreimage(t, auth.SignablePreimage, signing.PurposePolicyBundleRollback, "rollback-signer-1", "rollback-signer-2")
	if err := auth.VerifySignaturesAt(auth.CreatedAt, resolver); err != nil {
		t.Fatalf("rollback authorization VerifySignaturesAt() error = %v", err)
	}
	return resolver
}

func resolverWithKeyNotAfter(t *testing.T, inner conductor.SignatureKeyResolver, notAfter time.Time) conductor.SignatureKeyResolver {
	t.Helper()
	return func(keyID string) (conductor.SignatureKey, error) {
		key, err := inner(keyID)
		if err != nil {
			return conductor.SignatureKey{}, err
		}
		key.NotAfter = notAfter.UTC()
		return key, nil
	}
}

func resolverWithKeyRevokedAt(t *testing.T, inner conductor.SignatureKeyResolver, revokedAt time.Time) conductor.SignatureKeyResolver {
	t.Helper()
	revoked := revokedAt.UTC()
	return func(keyID string) (conductor.SignatureKey, error) {
		key, err := inner(keyID)
		if err != nil {
			return conductor.SignatureKey{}, err
		}
		key.RevokedAt = &revoked
		return key, nil
	}
}

// TestDryRunReplay_NoSecretsInResponsesOrLogs proves invariant 6: no signing
// material and no operator reason text leaks into any dry-run/replay response or
// the handler's logs.
func TestDryRunReplay_NoSecretsInResponsesOrLogs(t *testing.T) {
	secretReason := "operator note SECRET-" + "AKIA" + "IOSFODNN7EXAMPLE"
	msg, _ := signedRemoteKillMessageWithResolver(t, "kill-secret", 1, conductor.KillSwitchActive, testNow)
	msg.Reason = secretReason
	// Re-sign after mutating the reason so the message stays valid.
	var resolver conductor.SignatureKeyResolver
	msg.Signatures, resolver = signConductorPreimage(t, msg.SignablePreimage, signing.PurposeRemoteKillSigning, "kill-secret-a", "kill-secret-b")
	if err := msg.Validate(); err != nil {
		t.Fatalf("secret kill Validate() error = %v", err)
	}
	signatureHex := msg.Signatures[0].Signature

	var logBuf bytes.Buffer
	handler := newTestHandlerWithOptions(t, mustStore(t), nil, resolver)
	handler.logger = slog.New(slog.NewTextHandler(&logBuf, nil))

	// Dry-run kill.
	dry := remoteKillJSON(t, handler, publishRemoteKillRequest{Message: msg, DryRun: true})
	if dry.Code != http.StatusOK {
		t.Fatalf("secret dry-run kill code=%d body=%s", dry.Code, dry.Body.String())
	}
	// Replay kill.
	replay := replayJSON(t, handler, decisionReplayRequest{RemoteKill: &msg}, true, false)
	if replay.Code != http.StatusOK {
		t.Fatalf("secret replay kill code=%d body=%s", replay.Code, replay.Body.String())
	}

	for _, tc := range []struct {
		name string
		text string
	}{
		{"dry_run_body", dry.Body.String()},
		{"replay_body", replay.Body.String()},
		{"logs", logBuf.String()},
	} {
		if strings.Contains(tc.text, secretReason) {
			t.Fatalf("%s leaked the operator reason", tc.name)
		}
		if strings.Contains(tc.text, "AKIA"+"IOSFODNN7EXAMPLE") {
			t.Fatalf("%s leaked the planted secret", tc.name)
		}
		if strings.Contains(tc.text, signatureHex) {
			t.Fatalf("%s leaked signing material", tc.name)
		}
	}
}
