//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"bytes"
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

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/conductor/auditbatcher"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

var sinkTestNow = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

func TestHandler_AcceptsSignedBatchAndListsMetadata(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean audit event"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)

	resp := postBatch(t, handler, env, payload)
	if resp.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}

	duplicate := postBatch(t, handler, env, payload)
	if duplicate.Code != http.StatusAccepted {
		t.Fatalf("duplicate status = %d body=%s", duplicate.Code, duplicate.Body.String())
	}
	if !strings.Contains(duplicate.Body.String(), `"status":"duplicate"`) {
		t.Fatalf("duplicate response missing duplicate status: %s", duplicate.Body.String())
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
	list := httptest.NewRecorder()
	handler.ServeHTTP(list, req)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", list.Code, list.Body.String())
	}
	if strings.Contains(list.Body.String(), "clean audit event") {
		t.Fatalf("query response leaked raw payload: %s", list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"batch_id":"batch-1"`) {
		t.Fatalf("query response missing batch metadata: %s", list.Body.String())
	}
}

func TestHandler_GetBatchMetadata(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean audit event"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)
	if resp := postBatch(t, handler, env, payload); resp.Code != http.StatusAccepted {
		t.Fatalf("post status = %d body=%s", resp.Code, resp.Body.String())
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, AuditBatchesPath+"/batch-1?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", nil)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), `"batch_id":"batch-1"`) {
		t.Fatalf("get response missing batch metadata: %s", resp.Body.String())
	}
	if strings.Contains(resp.Body.String(), "clean audit event") {
		t.Fatalf("get response leaked raw payload: %s", resp.Body.String())
	}
}

func TestHandler_RoutesHealthAndErrors(t *testing.T) {
	handler, _, _ := testHandler(t)

	for _, tc := range []struct {
		name   string
		method string
		path   string
		want   int
	}{
		{"health", http.MethodGet, "/health", http.StatusOK},
		{"method", http.MethodDelete, AuditBatchesPath, http.StatusMethodNotAllowed},
		{"not_found", http.MethodGet, "/missing", http.StatusNotFound},
		{"get_missing_namespace", http.MethodGet, AuditBatchesPath + "/batch-1", http.StatusBadRequest},
		{"get_missing_batch", http.MethodGet, AuditBatchesPath + "/missing?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a", http.StatusNotFound},
		{"bad_limit", http.MethodGet, AuditBatchesPath + "?org_id=org-test&fleet_id=fleet-prod&instance_id=instance-a&limit=not-int", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), tc.method, tc.path, nil)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status = %d body=%s want=%d", resp.Code, resp.Body.String(), tc.want)
			}
		})
	}
}

func TestHandler_RejectsUnsupportedContentType(t *testing.T) {
	handler, _, _ := testHandler(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "text/plain")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestHandler_RejectsStrictWireFormatDrift(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean audit event"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)
	body, err := json.Marshal(map[string]any{
		"envelope": env,
		"payload":  payload,
		"extra":    "drift",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestHandler_RejectsMalformedBodies(t *testing.T) {
	handler, _, priv := testHandler(t)
	payload := []byte(`{"events":[{"message":"clean audit event"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)
	envelopeRaw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		body string
		want int
	}{
		{"trailing_top_level", `{"envelope":` + string(envelopeRaw) + `,"payload":"e30="}{}`, http.StatusBadRequest},
		{"unknown_envelope_field", `{"envelope":{"schema_version":1,"extra":true},"payload":"e30="}`, http.StatusBadRequest},
		{"oversize", `{"envelope":{},"payload":"` + strings.Repeat("A", 128) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			if tc.name == "oversize" {
				handler.maxRequestBytes = 32
				t.Cleanup(func() { handler.maxRequestBytes = DefaultMaxRequestBytes })
			}
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != tc.want {
				t.Fatalf("status = %d body=%s want=%d", resp.Code, resp.Body.String(), tc.want)
			}
		})
	}
}

func TestHandler_RejectsOffRosterSignature(t *testing.T) {
	handler, _, _ := testHandler(t)
	_, roguePriv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"events":[{"message":"clean audit event"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, roguePriv)

	resp := postBatch(t, handler, env, payload)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestHandler_DLPBeforeStore(t *testing.T) {
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler, err := NewHandler(Options{
		Store:      store,
		Resolver:   staticResolver(pub),
		DLPScanner: containsDLPScanner("fleet-sink-test-secret"),
		Now:        func() time.Time { return sinkTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"events":[{"message":"fleet-sink-test-secret"}]}`)
	env := signedEnvelope(t, "batch-1", 1, 1, payload, priv)

	resp := postBatch(t, handler, env, payload)
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d body=%s", resp.Code, resp.Body.String())
	}
	got, err := store.List(context.Background(), Query{OrgID: "org-test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("DLP-rejected payload was stored: %+v", got)
	}
}

type containsDLPScanner string

func (s containsDLPScanner) ScanTextForDLP(_ context.Context, text string) scanner.TextDLPResult {
	if !strings.Contains(text, string(s)) {
		return scanner.TextDLPResult{Clean: true}
	}
	return scanner.TextDLPResult{
		Clean: false,
		Matches: []scanner.TextDLPMatch{{
			PatternName: "Fleet Sink Test Secret",
			Severity:    config.SeverityCritical,
		}},
	}
}

func TestHandler_DetectsSequenceFork(t *testing.T) {
	handler, _, priv := testHandler(t)
	firstPayload := []byte(`{"events":[{"message":"first"}]}`)
	first := signedEnvelope(t, "batch-1", 1, 2, firstPayload, priv)
	if resp := postBatch(t, handler, first, firstPayload); resp.Code != http.StatusAccepted {
		t.Fatalf("first status = %d body=%s", resp.Code, resp.Body.String())
	}

	forkPayload := []byte(`{"events":[{"message":"fork"}]}`)
	fork := signedEnvelope(t, "batch-2", 2, 3, forkPayload, priv)
	resp := postBatch(t, handler, fork, forkPayload)
	if resp.Code != http.StatusConflict {
		t.Fatalf("fork status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestHandler_DetectsBatchIDConflict(t *testing.T) {
	handler, _, priv := testHandler(t)
	firstPayload := []byte(`{"events":[{"message":"first"}]}`)
	first := signedEnvelope(t, "batch-1", 1, 1, firstPayload, priv)
	if resp := postBatch(t, handler, first, firstPayload); resp.Code != http.StatusAccepted {
		t.Fatalf("first status = %d body=%s", resp.Code, resp.Body.String())
	}

	secondPayload := []byte(`{"events":[{"message":"second"}]}`)
	second := signedEnvelope(t, "batch-1", 3, 3, secondPayload, priv)
	resp := postBatch(t, handler, second, secondPayload)
	if resp.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d body=%s", resp.Code, resp.Body.String())
	}
}

func TestNewHandlerRequiresDependencies(t *testing.T) {
	_, store, _ := testHandler(t)
	for _, tc := range []struct {
		name string
		opts Options
		want error
	}{
		{"store", Options{}, ErrMissingStore},
		{"resolver", Options{Store: store}, ErrMissingResolver},
		{"dlp", Options{Store: store, Resolver: staticResolver(ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)))}, ErrMissingDLPScanner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHandler(tc.opts)
			if !errors.Is(err, tc.want) {
				t.Fatalf("NewHandler() err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestStoreOpenAndQueryEdgeCases(t *testing.T) {
	if _, err := OpenStore(context.Background(), ""); err == nil {
		t.Fatal("OpenStore accepted empty path")
	}
	var missing *Store
	if _, err := missing.Put(context.Background(), acceptedBatch{}, nil); !errors.Is(err, ErrMissingStore) {
		t.Fatalf("nil store Put err = %v, want ErrMissingStore", err)
	}
	if got := normalizeLimit(maxQueryLimit + 1); got != maxQueryLimit {
		t.Fatalf("normalizeLimit cap = %d, want %d", got, maxQueryLimit)
	}
	if _, err := parseLimit("bad"); !errors.Is(err, ErrInvalidRequestBody) {
		t.Fatalf("parseLimit bad err = %v", err)
	}
	if _, err := parseUintField("field", "not-uint"); err == nil {
		t.Fatal("parseUintField accepted invalid value")
	}
	if got := dlpPatternNames([]scanner.TextDLPMatch{
		{PatternName: "A"},
		{PatternName: "A"},
		{},
		{PatternName: "B"},
	}); strings.Join(got, ",") != "A,B" {
		t.Fatalf("dlpPatternNames = %v, want A,B", got)
	}
	if statusForError(errors.New("other")) != http.StatusInternalServerError {
		t.Fatal("statusForError default did not return 500")
	}
}

func testHandler(t *testing.T) (*Handler, *Store, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(context.Background(), t.TempDir()+"/sink.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	handler, err := NewHandler(Options{
		Store:      store,
		Resolver:   staticResolver(pub),
		DLPScanner: scanner.New(config.Defaults()),
		Now:        func() time.Time { return sinkTestNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, store, priv
}

func postBatch(t *testing.T, handler *Handler, env conductor.AuditBatchEnvelope, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(uploadRequest{Envelope: env, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, AuditBatchesPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func signedEnvelope(t *testing.T, batchID string, seqStart, seqEnd uint64, payload []byte, priv ed25519.PrivateKey) conductor.AuditBatchEnvelope {
	t.Helper()
	sum := sha256.Sum256(payload)
	env := conductor.AuditBatchEnvelope{
		SchemaVersion:      conductor.SchemaVersion,
		BatchID:            batchID,
		OrgID:              "org-test",
		FleetID:            "fleet-prod",
		InstanceID:         "instance-a",
		AuditSchemaVersion: 2,
		EmittedAt:          sinkTestNow,
		SeqStart:           seqStart,
		SeqEnd:             seqEnd,
		EventCount:         1,
		PayloadSHA256:      hex.EncodeToString(sum[:]),
		PayloadBytes:       uint64(len(payload)),
		Chain: conductor.EvidenceChain{
			EntryVersion:           2,
			SegmentID:              "segment-" + batchID,
			SeqStart:               seqStart,
			SeqEnd:                 seqEnd,
			SegmentHeadHash:        hashHex("head-" + batchID),
			SegmentTailHash:        hashHex("tail-" + batchID + string(payload)),
			CheckpointSeq:          seqEnd,
			CheckpointHash:         hashHex("checkpoint-" + batchID),
			CheckpointSignature:    "ed25519:" + strings.Repeat("aa", ed25519.SignatureSize),
			CheckpointSignerKeyID:  "checkpoint-signer",
			FollowerRecorderKeyID:  "recorder-key",
			FollowerRecorderPubHex: strings.Repeat("11", ed25519.PublicKeySize),
		},
	}
	signed, err := auditbatcher.SignEnvelope(env, "audit-signer", priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func staticResolver(pub ed25519.PublicKey) conductor.SignatureKeyResolver {
	return func(signerKeyID string) (conductor.SignatureKey, error) {
		if signerKeyID != "audit-signer" {
			return conductor.SignatureKey{}, conductor.ErrInvalidSignature
		}
		return conductor.SignatureKey{PublicKey: pub, KeyPurpose: signing.PurposeAuditBatchSigning}, nil
	}
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
