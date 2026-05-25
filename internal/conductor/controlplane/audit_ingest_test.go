// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

func TestHandlerIngestsSignedAuditBatch(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)

	w := postAuditBatch(t, handler, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("audit ingest status = %d body=%s, want 202", w.Code, w.Body.String())
	}
	if len(sink.batches) != 1 {
		t.Fatalf("sink batch count = %d, want 1", len(sink.batches))
	}
	got := sink.batches[0]
	if got.Identity.InstanceID != "pl-prod-1" || got.Envelope.BatchID != "audit-batch-1" {
		t.Fatalf("sink got identity=%+v batch_id=%q", got.Identity, got.Envelope.BatchID)
	}
	if string(got.Payload) != string(payload) {
		t.Fatalf("sink payload = %q, want %q", string(got.Payload), string(payload))
	}
	if got.EnvelopeHash == "" {
		t.Fatal("sink envelope hash empty")
	}
	var resp ingestAuditBatchResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.BatchID != got.Envelope.BatchID || resp.EnvelopeHash != got.EnvelopeHash || resp.SeqStart != 10 || resp.SeqEnd != 10 {
		t.Fatalf("response = %+v, sink hash=%q", resp, got.EnvelopeHash)
	}
}

func TestHandlerRejectsInvalidAuditBatch(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	for _, tc := range []struct {
		name      string
		req       ingestAuditBatchRequest
		resolver  AuditKeyResolver
		want      int
		mustHide  string
		mutateReq func(*ingestAuditBatchRequest)
	}{
		{
			name: "identity_mismatch",
			req: signedAuditIngestRequest(t, FollowerIdentity{
				OrgID:       "org-main",
				FleetID:     "prod",
				InstanceID:  "pl-other",
				Environment: "prod",
			}, payload, priv, testNow),
			resolver: auditKeyResolverFor(pub),
			want:     http.StatusForbidden,
		},
		{
			name:     "payload_hash_mismatch",
			req:      signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow),
			resolver: auditKeyResolverFor(pub),
			want:     http.StatusUnprocessableEntity,
			mutateReq: func(req *ingestAuditBatchRequest) {
				req.Payload = []byte(`{"entry":"tampered"}`)
			},
		},
		{
			name: "unknown_audit_key",
			req:  signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow),
			resolver: func(FollowerIdentity, string) (conductor.SignatureKey, error) {
				return conductor.SignatureKey{}, errors.New("secret roster detail")
			},
			want:     http.StatusUnauthorized,
			mustHide: "secret roster detail",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			if tc.mutateReq != nil {
				tc.mutateReq(&req)
			}
			sink := &captureAuditSink{}
			handler := newAuditIngestTestHandler(t, sink, tc.resolver, 0)
			w := postAuditBatch(t, handler, req)
			if w.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
			if len(sink.batches) != 0 {
				t.Fatalf("sink batch count = %d, want 0", len(sink.batches))
			}
			if tc.mustHide != "" && strings.Contains(w.Body.String(), tc.mustHide) {
				t.Fatalf("response leaked %q: %s", tc.mustHide, w.Body.String())
			}
		})
	}
}

func TestHandlerAuditBatchStrictJSONAndMethod(t *testing.T) {
	pub, _ := testAuditSigner(t)
	handler := newAuditIngestTestHandler(t, &captureAuditSink{}, auditKeyResolverFor(pub), 64)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath, nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("wrong method status=%d allow=%q, want 405 POST", w.Code, w.Header().Get("Allow"))
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{"envelope":{},"payload":"","extra":true}`))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status = %d body=%s, want 400", w.Code, w.Body.String())
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{"envelope":{},"payload":"`+strings.Repeat("a", 256)+`"}`))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status = %d body=%s, want 413", w.Code, w.Body.String())
	}
}

func TestHandlerAuditSinkErrorIsGeneric(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{err: errors.New("database token secret")}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)

	w := postAuditBatch(t, handler, signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("sink error status = %d body=%s, want 500", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), sink.err.Error()) || !strings.Contains(w.Body.String(), "internal server error") {
		t.Fatalf("sink error body = %s, want generic internal server error", w.Body.String())
	}
}

func TestWriteAuditIngestErrorMapping(t *testing.T) {
	internalErr := errors.New("storage password detail")
	for _, tc := range []struct {
		name       string
		err        error
		want       int
		body       string
		mustNotSee string
	}{
		{name: "too_large", err: conductor.ErrPayloadTooLarge, want: http.StatusRequestEntityTooLarge, body: conductor.ErrPayloadTooLarge.Error()},
		{name: "skew", err: conductor.ErrSkewExceeded, want: http.StatusUnprocessableEntity, body: conductor.ErrSkewExceeded.Error()},
		{name: "invalid_hash", err: conductor.ErrInvalidHash, want: http.StatusBadRequest, body: conductor.ErrInvalidHash.Error()},
		{name: "internal", err: internalErr, want: http.StatusInternalServerError, body: "internal server error", mustNotSee: internalErr.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeAuditIngestError(w, tc.err)
			if w.Code != tc.want {
				t.Fatalf("status = %d body=%s, want %d", w.Code, w.Body.String(), tc.want)
			}
			if !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("body = %s, want %q", w.Body.String(), tc.body)
			}
			if tc.mustNotSee != "" && strings.Contains(w.Body.String(), tc.mustNotSee) {
				t.Fatalf("body leaked %q: %s", tc.mustNotSee, w.Body.String())
			}
		})
	}
}

// TestAuditIngestRejectsSkewExceeded covers the only at-this-layer replay
// defense. A batch whose EmittedAt is outside DefaultAuditMaxSkew of the
// server's "now" must be rejected with 422.
func TestAuditIngestRejectsSkewExceeded(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	for _, tc := range []struct {
		name    string
		emitted time.Time
	}{
		{name: "too_old", emitted: testNow.Add(-conductor.DefaultAuditMaxSkew - time.Second)},
		{name: "too_new", emitted: testNow.Add(conductor.DefaultAuditMaxSkew + time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := &captureAuditSink{}
			handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
			req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, tc.emitted)
			w := postAuditBatch(t, handler, req)
			if w.Code != http.StatusUnprocessableEntity {
				t.Fatalf("skew %s status = %d body=%s, want 422", tc.name, w.Code, w.Body.String())
			}
			if len(sink.batches) != 0 {
				t.Fatalf("skew %s sink batch count = %d, want 0", tc.name, len(sink.batches))
			}
		})
	}
}

// TestAuditIngestRejectsMissingSignatures covers the threshold check end to
// end: an envelope with no signatures must fail before reaching the resolver.
func TestAuditIngestRejectsMissingSignatures(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	resolved := false
	resolver := func(id FollowerIdentity, keyID string) (conductor.SignatureKey, error) {
		resolved = true
		return auditKeyResolverFor(pub)(id, keyID)
	}
	handler := newAuditIngestTestHandler(t, sink, resolver, 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
	req.Envelope.Signatures = nil

	w := postAuditBatch(t, handler, req)
	// Validate() runs before VerifySignaturesAt and fires
	// ErrThresholdRequired structurally; the handler maps that to 401.
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing signatures status = %d body=%s, want 401", w.Code, w.Body.String())
	}
	if resolved {
		t.Fatal("resolver was called for a signature-less envelope")
	}
	if len(sink.batches) != 0 {
		t.Fatal("sink received signature-less batch")
	}
}

// TestAuditIngestRejectsWrongKeyPurpose covers the case where the resolver
// returns a key enrolled with the wrong KeyPurpose. This is the canonical
// roster-misconfiguration shape and must hard-fail at signature verification
// time, not be silently accepted.
func TestAuditIngestRejectsWrongKeyPurpose(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	resolver := func(_ FollowerIdentity, signerKeyID string) (conductor.SignatureKey, error) {
		if signerKeyID != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown audit key")
		}
		// Wrong purpose for an audit batch key.
		return conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposePolicyBundleSigning,
		}, nil
	}
	handler := newAuditIngestTestHandler(t, sink, resolver, 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
	w := postAuditBatch(t, handler, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key purpose status = %d body=%s, want 401", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), conductor.ErrSignatureVerification.Error()) {
		t.Fatalf("wrong key purpose body = %s, want canonical signature failure", w.Body.String())
	}
	if len(sink.batches) != 0 {
		t.Fatal("sink received wrong-purpose batch")
	}
}

// TestAuditIngestRejectsTamperedSignature covers the case where the signature
// is structurally valid (correct prefix and hex length) but verifies false
// because the bytes do not match the preimage.
func TestAuditIngestRejectsTamperedSignature(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
	// Flip the last byte of the signature hex. Format and prefix stay
	// intact, so structural Validate() passes, but ed25519 verify fails.
	sig := req.Envelope.Signatures[0].Signature
	last := sig[len(sig)-1]
	flipped := byte('0')
	if last == '0' {
		flipped = '1'
	}
	req.Envelope.Signatures[0].Signature = sig[:len(sig)-1] + string(flipped)

	w := postAuditBatch(t, handler, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tampered signature status = %d body=%s, want 401", w.Code, w.Body.String())
	}
	if len(sink.batches) != 0 {
		t.Fatal("sink received tampered batch")
	}
}

// TestAuditIngestIdentityResolverErrorReturns401 covers the
// followerIdentity-returns-error branch, distinct from the
// identity.Validate()-fails branch (both 401 but different code paths).
func TestAuditIngestIdentityResolverErrorReturns401(t *testing.T) {
	pub, _ := testAuditSigner(t)
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{}, errors.New("mTLS peer cert missing internal subject detail")
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          auditKeyResolverFor(pub),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("resolver error status = %d body=%s, want 401", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "mTLS peer cert missing internal subject detail") {
		t.Fatalf("resolver error text leaked: %s", w.Body.String())
	}
}

// TestAuditIngestIncompleteIdentityReturns401 covers the identity.Validate()
// branch, where the resolver succeeds but the returned identity is missing
// required fields.
func TestAuditIngestIncompleteIdentityReturns401(t *testing.T) {
	pub, _ := testAuditSigner(t)
	handler, err := NewHandler(HandlerOptions{
		Store:        mustStore(t),
		Capabilities: DefaultCapabilities("conductor-test"),
		Now:          func() time.Time { return testNow },
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return FollowerIdentity{OrgID: "org-main"}, nil
		},
		AuthorizePublisher: func(*http.Request) error { return nil },
		AuditSink:          discardAuditSink{},
		AuditKeys:          auditKeyResolverFor(pub),
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("incomplete identity status = %d body=%s, want 401", w.Code, w.Body.String())
	}
}

// TestAuditIngestReplayWithinSkewWindowSucceeds locks in the documented
// behavior that this MVP layer does NOT deduplicate. Two identical signed
// batches within the skew window both result in 202 + sink ingest. If a
// future change ever wires per-handler dedup, that change must also revise
// the AuditBatchSink doc comment (which currently tells sinks to handle
// idempotency themselves).
func TestAuditIngestReplayWithinSkewWindowSucceeds(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)

	for i := range 3 {
		w := postAuditBatch(t, handler, req)
		if w.Code != http.StatusAccepted {
			t.Fatalf("replay #%d status = %d body=%s, want 202", i, w.Code, w.Body.String())
		}
	}
	if len(sink.batches) != 3 {
		t.Fatalf("sink batch count after replays = %d, want 3 (this layer does not dedup)", len(sink.batches))
	}
}

// TestAuditIngestRejectsStructurallyInvalidEnvelope covers the 400 path:
// the request decodes successfully but the envelope fails ErrMissingField /
// ErrInvalidIdentifier / similar structural checks.
func TestAuditIngestRejectsStructurallyInvalidEnvelope(t *testing.T) {
	payload := []byte(`{"entry":"ok"}`)
	pub, priv := testAuditSigner(t)
	sink := &captureAuditSink{}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
	req := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload, priv, testNow)
	// Blank BatchID: structural Validate fires before crypto.
	req.Envelope.BatchID = ""
	w := postAuditBatch(t, handler, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("structural reject status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	if len(sink.batches) != 0 {
		t.Fatal("sink received structurally-invalid batch")
	}
}

// TestAuditIngestSinkCanRetainPayload verifies the public retention contract:
// after an accepted request returns, a sink-retained payload remains stable even
// after a later ingest delivers a different payload.
func TestAuditIngestSinkCanRetainPayload(t *testing.T) {
	payload1 := []byte(`{"entry":"original"}`)
	payload2 := []byte(`{"entry":"next"}`)
	pub, priv := testAuditSigner(t)
	sink := &nonCopyingAuditSink{}
	handler := newAuditIngestTestHandler(t, sink, auditKeyResolverFor(pub), 0)
	req1 := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload1, priv, testNow)
	req2 := signedAuditIngestRequest(t, defaultFollowerIdentity(), payload2, priv, testNow)

	w := postAuditBatch(t, handler, req1)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s, want 202", w.Code, w.Body.String())
	}
	w = postAuditBatch(t, handler, req2)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status2 = %d body=%s, want 202", w.Code, w.Body.String())
	}
	if len(sink.batches) != 2 {
		t.Fatalf("sink batch count = %d, want 2", len(sink.batches))
	}
	if string(sink.batches[0].Payload) != `{"entry":"original"}` {
		t.Fatalf("first retained payload mutated: %q", string(sink.batches[0].Payload))
	}
	if string(sink.batches[1].Payload) != `{"entry":"next"}` {
		t.Fatalf("second retained payload = %q, want next payload", string(sink.batches[1].Payload))
	}
}

type nonCopyingAuditSink struct{ batches []AcceptedAuditBatch }

func (s *nonCopyingAuditSink) IngestAuditBatch(_ context.Context, batch AcceptedAuditBatch) error {
	s.batches = append(s.batches, batch)
	return nil
}

type discardAuditSink struct{}

func (discardAuditSink) IngestAuditBatch(context.Context, AcceptedAuditBatch) error {
	return nil
}

type captureAuditSink struct {
	batches []AcceptedAuditBatch
	err     error
}

func (s *captureAuditSink) IngestAuditBatch(_ context.Context, batch AcceptedAuditBatch) error {
	if s.err != nil {
		return s.err
	}
	batch.Payload = append([]byte(nil), batch.Payload...)
	s.batches = append(s.batches, batch)
	return nil
}

func rejectingAuditKeyResolver(FollowerIdentity, string) (conductor.SignatureKey, error) {
	return conductor.SignatureKey{}, errors.New("unexpected audit key resolution")
}

func newAuditIngestTestHandler(t *testing.T, sink AuditBatchSink, resolver AuditKeyResolver, maxAuditBody int64) *Handler {
	t.Helper()
	handler, err := NewHandler(HandlerOptions{
		Store:             mustStore(t),
		Capabilities:      DefaultCapabilities("conductor-test"),
		Now:               func() time.Time { return testNow },
		MaxAuditBodyBytes: maxAuditBody,
		FollowerIdentity: func(*http.Request) (FollowerIdentity, error) {
			return defaultFollowerIdentity(), nil
		},
		AuthorizePublisher: func(*http.Request) error {
			return nil
		},
		AuditSink: sink,
		AuditKeys: resolver,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func defaultFollowerIdentity() FollowerIdentity {
	return FollowerIdentity{
		OrgID:       "org-main",
		FleetID:     "prod",
		InstanceID:  "pl-prod-1",
		Environment: "prod",
	}
}

func signedAuditIngestRequest(t *testing.T, identity FollowerIdentity, payload []byte, priv ed25519.PrivateKey, emittedAt time.Time) ingestAuditBatchRequest {
	t.Helper()
	sum := sha256.Sum256(payload)
	recorderPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(recorder) error = %v", err)
	}
	envelope := conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            "audit-batch-1",
		OrgID:              identity.OrgID,
		FleetID:            identity.FleetID,
		InstanceID:         identity.InstanceID,
		AuditSchemaVersion: conductor.SchemaVersion,
		EmittedAt:          emittedAt,
		SeqStart:           10,
		SeqEnd:             10,
		EventCount:         1,
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Dropped:            conductor.DroppedAccounting{},
		Chain: conductor.EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-1",
			SeqStart:               10,
			SeqEnd:                 10,
			SegmentHeadHash:        auditTestHash("head"),
			SegmentTailHash:        auditTestHash("tail"),
			CheckpointSeq:          10,
			CheckpointHash:         auditTestHash("checkpoint"),
			CheckpointSignature:    conductor.SignaturePrefixEd25519 + stringsOf("a", 128),
			CheckpointSignerKeyID:  "receipt-key-1",
			FollowerRecorderKeyID:  "recorder-key-1",
			FollowerRecorderPubHex: hex.EncodeToString(recorderPub),
		},
	}
	signed, err := auditbatcher.SignEnvelope(envelope, "audit-key-1", priv)
	if err != nil {
		t.Fatalf("SignEnvelope() error = %v", err)
	}
	return ingestAuditBatchRequest{Envelope: signed, Payload: payload}
}

func postAuditBatch(t *testing.T, handler *Handler, body ingestAuditBatchRequest) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(string(data)))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func auditKeyResolverFor(pub ed25519.PublicKey) AuditKeyResolver {
	return func(_ FollowerIdentity, signerKeyID string) (conductor.SignatureKey, error) {
		if signerKeyID != "audit-key-1" {
			return conductor.SignatureKey{}, errors.New("unknown audit key")
		}
		return conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		}, nil
	}
}

func testAuditSigner(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(audit) error = %v", err)
	}
	return pub, priv
}

func auditTestHash(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}
