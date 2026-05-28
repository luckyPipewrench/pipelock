//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// TestAudienceHashCanonicalizesInstanceIDOrder is a security regression for the
// stream-key fragmentation bypass. Without canonicalization, audiences with
// reordered InstanceIDs map to different stream keys, bypassing per-stream
// forward-chain enforcement (rollback rejection, previous_bundle_hash check).
func TestAudienceHashCanonicalizesInstanceIDOrder(t *testing.T) {
	a := conductor.Audience{InstanceIDs: []string{"pl-prod-1", "pl-prod-2", "pl-prod-3"}}
	b := conductor.Audience{InstanceIDs: []string{"pl-prod-3", "pl-prod-1", "pl-prod-2"}}
	ha, err := audienceHash(a)
	if err != nil {
		t.Fatalf("audienceHash(a) error = %v", err)
	}
	hb, err := audienceHash(b)
	if err != nil {
		t.Fatalf("audienceHash(b) error = %v", err)
	}
	if ha != hb {
		t.Fatalf("audienceHash order-variant: ha=%q hb=%q (reordered InstanceIDs must hash identically)", ha, hb)
	}
	// Negative case: distinct content still hashes distinctly.
	c := conductor.Audience{InstanceIDs: []string{"pl-prod-1", "pl-prod-2", "pl-prod-4"}}
	hc, err := audienceHash(c)
	if err != nil {
		t.Fatalf("audienceHash(c) error = %v", err)
	}
	if ha == hc {
		t.Fatalf("audienceHash collision: distinct content produced same hash %q", ha)
	}
	d := conductor.Audience{InstanceIDs: []string{"pl-prod-1", "pl-prod-2", "pl-prod-2", "pl-prod-3"}}
	hd, err := audienceHash(d)
	if err != nil {
		t.Fatalf("audienceHash(d) error = %v", err)
	}
	if ha != hd {
		t.Fatalf("audienceHash duplicate-variant: ha=%q hd=%q (duplicate InstanceIDs must not fragment stream keys)", ha, hd)
	}
}

// TestPublishRejectsReorderedAudienceAsSameStream proves the canonicalization
// fix end-to-end: a publish of v2 with reordered InstanceIDs and the same
// previous_bundle_hash as v1 must succeed (same stream), and a v2 with empty
// previous_bundle_hash and reordered IDs must be rejected as a conflict (would
// otherwise have opened a parallel stream).
func TestPublishRejectsReorderedAudienceAsSameStream(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"pl-prod-1", "pl-prod-2"}},
	})
	v1Rec, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	// Pre-fix bypass: publish v1' with empty previous_bundle_hash but
	// reordered InstanceIDs. Under the old hash, this opened a parallel
	// stream and silently succeeded. Under the fix it shares the stream
	// and must be rejected because the first record in a stream needs an
	// empty previous_bundle_hash AND no existing head, but a head exists.
	bypass := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-bypass",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"pl-prod-2", "pl-prod-1"}},
	})
	if _, _, err := store.Publish(t.Context(), bypass, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(reordered bypass) error = %v, want ErrBundleConflict", err)
	}
	// Legitimate forward step on the same stream with reordered IDs must
	// succeed when previous_bundle_hash chains correctly.
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"pl-prod-2", "pl-prod-1"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(v2 reordered) error = %v, want nil", err)
	}
}

// TestPublishMapsBodyTooLargeTo413 covers the http.MaxBytesError mapping. A
// generic 400 swallows the size signal and makes operators chase a phantom
// "bad bundle" when they should be raising the request body cap.
func TestPublishMapsBodyTooLargeTo413(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:               store,
		Capabilities:        DefaultCapabilities("conductor-test"),
		Now:                 func() time.Time { return testNow },
		MaxRequestBodyBytes: 64,
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	big := strings.NewReader(`{"bundle":{"bundle_id":"` + strings.Repeat("a", 256) + `"}}`)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, big)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d body=%s, want 413", w.Code, w.Body.String())
	}
}

// TestLatestMapsFollowerValidationTo401 covers the writeStoreError branch for
// ErrFollowerRequired surfaced from the store (resolver returned a non-error
// identity that nonetheless fails Validate). The previous default mapped this
// to 400; 401 makes the auth failure unambiguous to clients.
func TestLatestMapsFollowerValidationTo401(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	handler, err := NewHandler(HandlerOptions{
		Store:        store,
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			// Resolver succeeds with an incomplete identity.
			return FollowerIdentity{OrgID: "org-main"}, nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid follower identity status = %d body=%s, want 401", w.Code, w.Body.String())
	}
}

// TestLoadRejectsBrokenForwardChain proves load() refuses to open a store
// whose on-disk records have a forward-chain integrity hole, for example, a
// stream head whose previous_bundle_hash points at a missing ancestor. Without
// this check, a tampered or partially-restored bundles directory could be
// served unchanged.
func TestLoadRejectsBrokenForwardChain(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	v1Rec, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	_, _, err = store.Publish(t.Context(), v2, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	// Remove the ancestor; v2's previous_bundle_hash now dangles.
	if err := os.Remove(filepath.Join(store.bundlesDir, v1Rec.BundleHash+".json")); err != nil {
		t.Fatalf("remove ancestor: %v", err)
	}
	if _, err := OpenFileBundleStore(store.dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(broken chain) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestSweepTempFilesOnOpen drops a stale temp file mimicking a crashed write
// in the bundle directory. Open() must remove it so the directory listing is
// clean and the next durable write does not collide with a stale name.
func TestSweepTempFilesOnOpen(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	stale := filepath.Join(store.bundlesDir, ".bundle-stale.tmp")
	if err := os.WriteFile(stale, []byte("garbage"), bundleRecordFileMode); err != nil {
		t.Fatalf("seed stale temp: %v", err)
	}
	if _, err := OpenFileBundleStore(dir); err != nil {
		t.Fatalf("OpenFileBundleStore(reopen) error = %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp not swept: stat err = %v", err)
	}
}

// TestSecureDirAutoChmodsLoosePerms covers the secureDir branch that tightens
// an existing too-loose mode. Operators may create the directory ahead of time
// with the default umask; the store must enforce 0o700 on open.
func TestSecureDirAutoChmodsLoosePerms(t *testing.T) {
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	// Test fixture deliberately seeds a loose mode so secureDir can tighten it;
	// nolint comments scope the gosec exception to these two seeding calls.
	if err := os.MkdirAll(loose, 0o755); err != nil { //nolint:gosec // G301: test seeds loose perms to verify auto-tighten.
		t.Fatalf("mkdir loose: %v", err)
	}
	if err := os.Chmod(loose, 0o755); err != nil { //nolint:gosec // G302: test seeds loose perms to verify auto-tighten.
		t.Fatalf("chmod loose: %v", err)
	}
	resolved, err := secureDir(loose)
	if err != nil {
		t.Fatalf("secureDir(loose) error = %v", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		t.Fatalf("stat resolved: %v", err)
	}
	if got := info.Mode().Perm(); got != bundleStoreDirMode {
		t.Fatalf("secureDir did not tighten perms: got %v want %v", got, bundleStoreDirMode)
	}
}

// TestETagInvalidatesAfterNewPublish proves that once a new bundle becomes the
// latest on a stream, the prior ETag no longer matches and the follower
// receives the new content. Without this, an upgraded fleet could pin itself
// to a stale cache via If-None-Match.
func TestETagInvalidatesAfterNewPublish(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	handler := newTestHandler(t, store, nil)
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	publish(t, handler, v1)

	// Capture the first ETag.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", w.Code)
	}
	oldETag := w.Header().Get("ETag")
	if oldETag == "" {
		t.Fatal("first GET ETag empty")
	}

	// Confirm the same ETag round-trips as 304.
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	req.Header.Set("If-None-Match", oldETag)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotModified {
		t.Fatalf("ETag match status = %d, want 304", w.Code)
	}

	// Publish v2 and confirm the stale ETag now returns 200 with new content.
	v1Hash := strings.Trim(oldETag, "\"")
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: v1Hash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	publish(t, handler, v2)

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, LatestPolicyBundlePath, nil)
	req.Header.Set("If-None-Match", oldETag)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("stale ETag after rollout status = %d, want 200", w.Code)
	}
	newETag := w.Header().Get("ETag")
	if newETag == oldETag || newETag == "" {
		t.Fatalf("ETag did not advance: old=%q new=%q", oldETag, newETag)
	}
}

// TestConcurrentPublishAndLatest exercises the store under concurrent writers
// and readers. The race detector catches lock misuse. Idempotent publishes of
// the same hash from many goroutines must converge to a single record, and
// concurrent Latest calls must never observe a torn record.
func TestConcurrentPublishAndLatest(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	bundle := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	follower := FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}

	var wg sync.WaitGroup
	const workers = 8
	createdCount := 0
	var createdMu sync.Mutex
	wg.Add(workers * 2)
	for range workers {
		go func() {
			defer wg.Done()
			_, created, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
			if err != nil {
				t.Errorf("concurrent Publish error = %v", err)
				return
			}
			if created {
				createdMu.Lock()
				createdCount++
				createdMu.Unlock()
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := store.Latest(t.Context(), follower, testNow); err != nil && !errors.Is(err, ErrBundleNotFound) {
				t.Errorf("concurrent Latest error = %v", err)
			}
		}()
	}
	wg.Wait()
	if createdCount != 1 {
		t.Fatalf("concurrent Publish created count = %d, want 1", createdCount)
	}
}

// TestDecodeStrictJSONRejectsMissingBody covers the r.Body == nil guard.
// httptest hides this branch by default; we construct the request manually.
func TestDecodeStrictJSONRejectsMissingBody(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, http.NoBody)
	req.Header.Set("X-Pipelock-Publisher", "ok")
	req.Body = nil
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("nil body status = %d, want 400", w.Code)
	}
}

// TestDefaultCapabilitiesFallsBackOnEmptyID locks in the empty-ID fallback so
// the handler always advertises a non-empty conductor_id.
func TestDefaultCapabilitiesFallsBackOnEmptyID(t *testing.T) {
	caps := DefaultCapabilities("   ")
	if caps.ConductorID != "conductor" {
		t.Fatalf("DefaultCapabilities(whitespace) ConductorID = %q, want %q", caps.ConductorID, "conductor")
	}
	if err := caps.Validate(); err != nil {
		t.Fatalf("DefaultCapabilities(whitespace) Validate() error = %v", err)
	}
}

// TestStreamKeyDistinctOrgFleetEnv proves the NUL separator prevents
// concatenation collisions across {OrgID, FleetID, Environment}.
func TestStreamKeyDistinctOrgFleetEnv(t *testing.T) {
	bundleA, err := bundleForStream("orgA", "fleet", "prod")
	if err != nil {
		t.Fatalf("bundleForStream(A) error = %v", err)
	}
	bundleB, err := bundleForStream("org", "Afleet", "prod")
	if err != nil {
		t.Fatalf("bundleForStream(B) error = %v", err)
	}
	keyA, err := streamKey(bundleA)
	if err != nil {
		t.Fatalf("streamKey(A) error = %v", err)
	}
	keyB, err := streamKey(bundleB)
	if err != nil {
		t.Fatalf("streamKey(B) error = %v", err)
	}
	if keyA == keyB {
		t.Fatalf("streamKey concatenation collision: %q == %q", keyA, keyB)
	}
}

// TestWriteBundleRecordRejectsInvalidRecord covers the validateStoredRecord
// guard inside writeBundleRecord. Hand-rolled callers in future may attempt
// to persist records that bypass Publish-side hash computation.
func TestWriteBundleRecordRejectsInvalidRecord(t *testing.T) {
	dir := t.TempDir()
	bogus := PublishedBundle{BundleHash: "not-hex"}
	if err := writeBundleRecord(dir, bogus); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("writeBundleRecord(bogus) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestLoadRejectsCorruptJSON covers the readBundleRecord decode error branch
// with malformed JSON.
func TestLoadRejectsCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	corrupt := filepath.Join(store.bundlesDir, strings.Repeat("a", 64)+".json")
	if err := os.WriteFile(corrupt, []byte("{not-json"), bundleRecordFileMode); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if _, err := OpenFileBundleStore(dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(corrupt) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestReadBundleRecordRejectsOversize covers the file-size cap on read.
func TestReadBundleRecordRejectsOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "oversize.json")
	bloat := make([]byte, maxBundleRecordJSONSize+1)
	for i := range bloat {
		bloat[i] = 'a'
	}
	if err := os.WriteFile(path, bloat, bundleRecordFileMode); err != nil {
		t.Fatalf("write oversize: %v", err)
	}
	if _, err := readBundleRecord(path); !errors.Is(err, conductor.ErrPayloadTooLarge) {
		t.Fatalf("readBundleRecord(oversize) error = %v, want ErrPayloadTooLarge", err)
	}
}

// TestPublishRejectsInitialBundleWithPreviousHash covers the
// authorizeForwardLocked branch where no stream head exists yet but the
// candidate bundle declares a previous_bundle_hash. The first record in a
// stream must have an empty previous_bundle_hash; otherwise the chain begins
// dangling.
func TestPublishRejectsInitialBundleWithPreviousHash(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:           "bundle-1",
		version:      1,
		previousHash: strings.Repeat("a", 64),
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(initial with prev) error = %v, want ErrBundleConflict", err)
	}
}

// TestPublishRejectsVersionDowngradeWithoutRollback covers the
// `version < current.Version` branch inside authorizeForwardLocked without
// using the Rollback short-circuit. A downgrade publish must fail unless
// rollback authorization is wired up.
func TestPublishRejectsVersionDowngradeWithoutRollback(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-2",
		version:  2,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	if _, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow}); err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:         "bundle-old",
		version:    1,
		audience:   conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML: "mode: balanced\n",
	})
	if _, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow}); !errors.Is(err, ErrBundleConflict) {
		t.Fatalf("Publish(v1 after v2) error = %v, want ErrBundleConflict", err)
	}
	if _, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow}); !errors.Is(err, ErrUnsupportedRollback) {
		t.Fatalf("Publish(v1 after v2) does not wrap ErrUnsupportedRollback: %v", err)
	}
}

// TestPublishWrongMethodIsMethodNotAllowed covers the bare-method guard on
// the publish endpoint (only PUT and POST are accepted; everything else must
// return 405 with an Allow header).
func TestPublishWrongMethodIsMethodNotAllowed(t *testing.T) {
	handler := newTestHandler(t, mustStore(t), nil)
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), method, PublishPolicyBundlePath, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("publish %s status = %d, want 405", method, w.Code)
			}
			if !strings.Contains(w.Header().Get("Allow"), http.MethodPut) ||
				!strings.Contains(w.Header().Get("Allow"), http.MethodPost) {
				t.Fatalf("publish %s Allow = %q, want PUT and POST listed", method, w.Header().Get("Allow"))
			}
		})
	}
}

// TestLoadRejectsDuplicateBundleHash covers load()'s rejection of two record
// files that claim the same bundle_hash. Without this, a partial-restore
// scenario where the same record appears under two filenames would silently
// overwrite the first by the second on each open.
func TestLoadRejectsDuplicateBundleHash(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	rec, _, err := store.Publish(t.Context(), bundle, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	src := filepath.Join(store.bundlesDir, rec.BundleHash+".json")
	dup := filepath.Join(store.bundlesDir, "duplicate.json")
	data, err := os.ReadFile(filepath.Clean(src))
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	if err := os.WriteFile(dup, data, bundleRecordFileMode); err != nil {
		t.Fatalf("write duplicate: %v", err)
	}
	if _, err := OpenFileBundleStore(dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(duplicate) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestLoadRejectsVersionNonDecreaseInChain covers the
// verifyStreamChainsLocked branch for a chain whose ancestor's Version is
// >= the cursor's Version. This is the structural cousin of a downgrade
// attempt that slipped through on a manual disk surgery.
func TestLoadRejectsVersionNonDecreaseInChain(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  3,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	v1Rec, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	// Build a v2 that points back at v1, but has the SAME Version (3).
	// Publish refuses this (same-version-different-content). To exercise
	// the load-time chain check we bypass Publish and write the record
	// directly: hash must still match content, so we keep the same bundle
	// shape and just change the BundleID.
	cousin := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-cousin",
		version:      3,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: balanced\n",
	})
	cousinHash, err := cousin.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash() error = %v", err)
	}
	streamKey, err := streamKey(cousin)
	if err != nil {
		t.Fatalf("streamKey() error = %v", err)
	}
	cousinRec := PublishedBundle{
		Bundle:      cousin,
		BundleHash:  cousinHash,
		StreamKey:   streamKey,
		PublishedAt: testNow.Add(time.Second),
	}
	if err := writeBundleRecord(store.bundlesDir, cousinRec); err != nil {
		t.Fatalf("writeBundleRecord(cousin) error = %v", err)
	}
	if _, err := OpenFileBundleStore(dir); !errors.Is(err, ErrInvalidStoreRecord) {
		t.Fatalf("OpenFileBundleStore(version non-decrease) error = %v, want ErrInvalidStoreRecord", err)
	}
}

// TestLoadRejectsUnreachableSameStreamFork proves load() mirrors the Publish
// invariant that a stream has one forward chain. A handcrafted same-stream
// record that is not reachable from the selected head is a fork, even if each
// individual previous_bundle_hash points at an existing lower-version record.
func TestLoadRejectsUnreachableSameStreamFork(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	v1Rec, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: strict\napi_allowlist:\n  - api2.example.com\n",
	})
	v2Rec, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	v3Fork := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-3-fork",
		version:      3,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: balanced\n",
	})
	v3Hash, err := v3Fork.CanonicalHash()
	if err != nil {
		t.Fatalf("CanonicalHash(v3Fork) error = %v", err)
	}
	streamKey, err := streamKey(v3Fork)
	if err != nil {
		t.Fatalf("streamKey(v3Fork) error = %v", err)
	}
	v3Rec := PublishedBundle{
		Bundle:      v3Fork,
		BundleHash:  v3Hash,
		StreamKey:   streamKey,
		PublishedAt: testNow.Add(2 * time.Second),
	}
	if err := writeBundleRecord(store.bundlesDir, v3Rec); err != nil {
		t.Fatalf("writeBundleRecord(v3Fork) error = %v", err)
	}
	if _, err := OpenFileBundleStore(dir); !errors.Is(err, ErrInvalidStoreRecord) || !strings.Contains(err.Error(), v2Rec.BundleHash) {
		t.Fatalf("OpenFileBundleStore(unreachable fork) error = %v, want unreachable ErrInvalidStoreRecord mentioning v2", err)
	}
}

// TestNewHandlerDefaultsCapabilitiesAndClock covers the "options zero-value
// defaults" path of NewHandler: empty Capabilities falls back to the package
// default, nil Now falls back to wall-clock.
func TestNewHandlerDefaultsCapabilitiesAndClock(t *testing.T) {
	store := mustStore(t)
	h, err := NewHandler(HandlerOptions{
		Store: store,
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{OrgID: "o", FleetID: "f", InstanceID: "i", Environment: "e"}, nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          rejectingAuditKeyResolver,
	})
	if err != nil {
		t.Fatalf("NewHandler(zero opts) error = %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, conductor.CapabilitiesPath, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("capabilities status = %d, want 200", w.Code)
	}
	var caps conductor.CapabilitiesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &caps); err != nil {
		t.Fatalf("decode caps: %v", err)
	}
	if caps.ConductorID == "" {
		t.Fatal("default ConductorID empty")
	}
	now := h.now()
	if time.Since(now) > time.Minute {
		t.Fatalf("default now too far in the past: %v", now)
	}
}

// TestPublishAndLatestDefaultNowToWallClock covers the zero-time fallback in
// both Publish and Latest. Callers that omit Now (e.g., real production
// callers) must get wall-clock semantics.
func TestPublishAndLatestDefaultNowToWallClock(t *testing.T) {
	store, err := OpenFileBundleStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	bundle := signedControlBundle(t, newTestSigner(t), bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
		// Make the bundle currently valid against wall-clock by setting
		// a wide window relative to time.Now().
	})
	bundle.NotBefore = time.Now().UTC().Add(-time.Hour)
	bundle.ExpiresAt = time.Now().UTC().Add(time.Hour)
	bundle.CreatedAt = bundle.NotBefore
	// Re-sign after window adjustment so hashes still match.
	bundle = resignBundle(t, bundle)

	rec, created, err := store.Publish(t.Context(), bundle, PublishOptions{})
	if err != nil {
		t.Fatalf("Publish(default now) error = %v", err)
	}
	if !created {
		t.Fatal("Publish(default now) created = false, want true")
	}
	if rec.PublishedAt.IsZero() {
		t.Fatal("Publish(default now) PublishedAt zero")
	}

	latest, err := store.Latest(t.Context(), FollowerIdentity{OrgID: "org-main", FleetID: "prod", InstanceID: "pl-prod-1", Environment: "prod"}, time.Time{})
	if err != nil {
		t.Fatalf("Latest(default now) error = %v", err)
	}
	if latest.BundleHash != rec.BundleHash {
		t.Fatalf("Latest(default now) hash = %q, want %q", latest.BundleHash, rec.BundleHash)
	}
}

// TestLoadSkipsNonRecordEntries covers the load() filter that ignores
// subdirectories and non-.json files. Operators occasionally leave README
// files or backup directories alongside the data; load must not choke on them.
func TestLoadSkipsNonRecordEntries(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	if err := os.Mkdir(filepath.Join(store.bundlesDir, "subdir"), bundleStoreDirMode); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.bundlesDir, "README.txt"), []byte("hi"), bundleRecordFileMode); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if _, err := OpenFileBundleStore(dir); err != nil {
		t.Fatalf("OpenFileBundleStore(noise) error = %v, want nil", err)
	}
}

// TestVerifyChainRejectsStreamKeyMismatch covers the cross-stream ancestor
// guard. A handcrafted records map where the head's previous_bundle_hash
// resolves to a record on a different stream must be rejected.
func TestVerifyChainRejectsStreamKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenFileBundleStore(dir)
	if err != nil {
		t.Fatalf("OpenFileBundleStore() error = %v", err)
	}
	signer := newTestSigner(t)
	v1 := signedControlBundle(t, signer, bundleSpec{
		id:       "bundle-1",
		version:  1,
		audience: conductor.Audience{InstanceIDs: []string{"*"}},
	})
	v1Rec, _, err := store.Publish(t.Context(), v1, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v1) error = %v", err)
	}
	v2 := signedControlBundle(t, signer, bundleSpec{
		id:           "bundle-2",
		version:      2,
		previousHash: v1Rec.BundleHash,
		audience:     conductor.Audience{InstanceIDs: []string{"*"}},
		configYAML:   "mode: balanced\n",
	})
	v2Rec, _, err := store.Publish(t.Context(), v2, PublishOptions{Now: testNow})
	if err != nil {
		t.Fatalf("Publish(v2) error = %v", err)
	}
	// Tamper the in-memory v1 ancestor's StreamKey so the chain walk
	// detects the inconsistency without disk surgery.
	fakeStore := &FileBundleStore{
		records: map[string]PublishedBundle{},
		streams: map[string]PublishedBundle{},
	}
	tampered := v1Rec
	tampered.StreamKey = "different-stream"
	fakeStore.records[tampered.BundleHash] = tampered
	fakeStore.records[v2Rec.BundleHash] = v2Rec
	fakeStore.streams[v2Rec.StreamKey] = v2Rec
	if err := fakeStore.verifyStreamChainsLocked(); !errors.Is(err, ErrInvalidStoreRecord) || !strings.Contains(err.Error(), "different stream") {
		t.Fatalf("verifyStreamChainsLocked(stream mismatch) error = %v, want different-stream ErrInvalidStoreRecord", err)
	}
}

// TestReadBundleRecordRejectsSymlink covers the file-mode guard. A symlinked
// bundle record could redirect reads to attacker-controlled content outside
// the bundles directory; readBundleRecord must reject non-regular files
// even if the link target itself is a regular JSON file.
func TestReadBundleRecordRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{}`), bundleRecordFileMode); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	if _, err := readBundleRecord(link); !errors.Is(err, ErrInvalidStoreRecord) || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("readBundleRecord(symlink) error = %v, want non-regular ErrInvalidStoreRecord", err)
	}
}

// TestSecureDirRejectsRelativeAndNonDirectory covers the validation gates
// before any FS mutation: empty path, relative path, and a path that resolves
// to a regular file rather than a directory.
func TestSecureDirRejectsRelativeAndNonDirectory(t *testing.T) {
	if _, err := secureDir(""); err == nil {
		t.Fatal("secureDir(empty) error = nil, want error")
	}
	if _, err := secureDir("./relative"); err == nil {
		t.Fatal("secureDir(relative) error = nil, want error")
	}
	root := filepath.VolumeName(os.TempDir()) + string(os.PathSeparator)
	if _, err := secureDir(root); err == nil {
		t.Fatalf("secureDir(root %q) error = nil, want error", root)
	}
	// A path that exists as a regular file must be rejected. MkdirAll on
	// an existing file returns ENOTDIR before we reach the EvalSymlinks
	// branch. The rejection happens, just via a different error path.
	regular := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(regular, []byte("x"), bundleRecordFileMode); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := secureDir(regular); err == nil {
		t.Fatalf("secureDir(file) error = nil, want error")
	}
}

func resignBundle(t *testing.T, bundle conductor.PolicyBundle) conductor.PolicyBundle {
	t.Helper()
	bundle.Signatures = nil
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		t.Fatalf("SignablePreimage() error = %v", err)
	}
	sig := ed25519.Sign(priv, preimage)
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: "policy-key-2",
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(sig),
	}}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("resigned bundle Validate() error = %v", err)
	}
	return bundle
}

func publish(t *testing.T, handler *Handler, bundle conductor.PolicyBundle) {
	t.Helper()
	body, err := json.Marshal(publishPolicyBundleRequest{Bundle: bundle})
	if err != nil {
		t.Fatalf("Marshal(publish) error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, PublishPolicyBundlePath, strings.NewReader(string(body)))
	req.Header.Set("X-Pipelock-Publisher", "ok")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("publish status = %d body=%s, want 201", w.Code, w.Body.String())
	}
}

func bundleForStream(org, fleet, env string) (conductor.PolicyBundle, error) {
	payload := conductor.PolicyBundlePayload{ConfigYAML: "mode: strict\n"}
	payloadHash, err := payload.PayloadHash()
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	policyHash, err := payload.PolicyHash()
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	bundle := conductor.PolicyBundle{
		SchemaVersion:      conductor.SchemaVersion,
		BundleID:           "b-1",
		OrgID:              org,
		FleetID:            fleet,
		Environment:        env,
		Audience:           conductor.Audience{InstanceIDs: []string{"*"}},
		Version:            1,
		CreatedAt:          testNow.Add(-time.Minute),
		NotBefore:          testNow.Add(-time.Minute),
		ExpiresAt:          testNow.Add(time.Hour),
		MinPipelockVersion: "1.2.3",
		PolicyHash:         policyHash,
		PayloadSHA256:      payloadHash,
		Payload:            payload,
	}
	preimage, err := bundle.SignablePreimage()
	if err != nil {
		return conductor.PolicyBundle{}, err
	}
	sig := ed25519.Sign(priv, preimage)
	bundle.Signatures = []conductor.SignatureProof{{
		SignerKeyID: "policy-key-1",
		KeyPurpose:  signing.PurposePolicyBundleSigning,
		Algorithm:   conductor.SignatureAlgorithmEd25519,
		Signature:   conductor.SignaturePrefixEd25519 + hex.EncodeToString(sig),
	}}
	return bundle, nil
}
