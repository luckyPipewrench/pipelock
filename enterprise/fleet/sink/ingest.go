//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package sink

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

type Handler struct {
	store           *Store
	resolver        conductor.SignatureKeyResolver
	dlpScanner      DLPScanner
	now             func() time.Time
	maxSkew         time.Duration
	maxRequestBytes int64
	keyBindings     map[string]KeyBinding
	readerToken     string
}

func NewHandler(opts Options) (*Handler, error) {
	if opts.Store == nil {
		return nil, ErrMissingStore
	}
	if opts.Resolver == nil {
		return nil, ErrMissingResolver
	}
	if opts.DLPScanner == nil {
		return nil, ErrMissingDLPScanner
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return time.Now().UTC() }
	}
	if opts.MaxSkew <= 0 {
		opts.MaxSkew = conductor.DefaultAuditMaxSkew
	}
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = DefaultMaxRequestBytes
	}
	// Copy the binding map so the handler isn't mutated after construction.
	bindings := make(map[string]KeyBinding, len(opts.KeyBindings))
	for k, v := range opts.KeyBindings {
		bindings[k] = v
	}
	return &Handler{
		store:           opts.Store,
		resolver:        opts.Resolver,
		dlpScanner:      opts.DLPScanner,
		now:             opts.Now,
		maxSkew:         opts.MaxSkew,
		maxRequestBytes: opts.MaxRequestBytes,
		keyBindings:     bindings,
		readerToken:     opts.ReaderToken,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/health":
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case r.URL.Path == AuditBatchesPath && r.Method == http.MethodPost:
		h.handleIngest(w, r)
	case r.URL.Path == AuditBatchesPath && r.Method == http.MethodGet:
		h.handleList(w, r)
	case strings.HasPrefix(r.URL.Path, AuditBatchesPath+"/") && r.Method == http.MethodGet:
		h.handleGet(w, r)
	case r.URL.Path == AuditBatchesPath:
		writeError(w, http.StatusMethodNotAllowed, ErrUnsupportedMethod)
	default:
		writeError(w, http.StatusNotFound, ErrUnsupportedPath)
	}
}

func (h *Handler) handleIngest(w http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(strings.ToLower(ct), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, fmt.Errorf("%w: content-type=%q", ErrInvalidRequestBody, ct))
		return
	}
	upload, err := decodeUpload(w, r, h.maxRequestBytes)
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}

	now := h.now().UTC()
	if err := upload.Envelope.ValidateForConductorWithPayload(now, h.maxSkew, upload.Payload); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := upload.Envelope.VerifySignaturesAt(now, h.resolver); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	// Binding enforcement runs AFTER signature verification: only
	// keys that proved possession are checked, and we never leak
	// information about binding constraints to clients who haven't
	// passed the crypto gate.
	if err := h.enforceBindings(upload.Envelope); err != nil {
		writeError(w, http.StatusForbidden, err)
		return
	}

	dlpResult := h.dlpScanner.ScanTextForDLP(r.Context(), string(upload.Payload))
	if !dlpResult.Clean {
		writeError(w, http.StatusUnprocessableEntity, fmt.Errorf("%w: %s", ErrDLPRejected, dlpPatternNames(dlpResult.Matches)))
		return
	}

	canonicalHash, err := upload.Envelope.CanonicalHash()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	result, err := h.store.Put(r.Context(), acceptedBatch{
		Envelope:      upload.Envelope,
		Payload:       upload.Payload,
		ReceivedAt:    now,
		CanonicalHash: canonicalHash,
	}, dlpPatternNames(dlpResult.InformationalMatches))
	if err != nil {
		writeError(w, statusForError(err), err)
		return
	}

	status := "accepted"
	if result.Duplicate {
		status = "duplicate"
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"status":         status,
		"batch_id":       result.Summary.BatchID,
		"canonical_hash": result.Summary.CanonicalHash,
	})
}

func (h *Handler) handleList(w http.ResponseWriter, r *http.Request) {
	if err := h.checkReaderAuth(r); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	q := r.URL.Query()
	orgID := q.Get("org_id")
	fleetID := q.Get("fleet_id")
	instanceID := q.Get("instance_id")
	// Require the full namespace tuple on list. Without it, an
	// authorized reader could enumerate every tenant's batches in
	// one request — even on a single-tenant deployment that's
	// information disclosure we don't need to grant.
	if orgID == "" || fleetID == "" || instanceID == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: org_id, fleet_id, and instance_id are required", ErrInvalidRequestBody))
		return
	}
	limit, err := parseLimit(q.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	results, err := h.store.List(r.Context(), Query{
		OrgID:      orgID,
		FleetID:    fleetID,
		InstanceID: instanceID,
		BatchID:    q.Get("batch_id"),
		Limit:      limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": results})
}

func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	if err := h.checkReaderAuth(r); err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	batchID := strings.TrimPrefix(r.URL.Path, AuditBatchesPath+"/")
	if batchID == "" || strings.Contains(batchID, "/") {
		writeError(w, http.StatusNotFound, ErrUnsupportedPath)
		return
	}
	q := r.URL.Query()
	if q.Get("org_id") == "" || q.Get("fleet_id") == "" || q.Get("instance_id") == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: org_id, fleet_id, and instance_id are required", ErrInvalidRequestBody))
		return
	}
	summary, ok, err := h.store.Get(r.Context(), q.Get("org_id"), q.Get("fleet_id"), q.Get("instance_id"), batchID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, ErrUnsupportedPath)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// checkReaderAuth validates the bearer token on GET endpoints when one
// is configured. The token comparison is constant-time to keep timing
// oracles off the table even though leaking a few bits on length is
// already known. When no token is configured the check is a no-op:
// operators MUST gate non-loopback bindings on either mTLS or a
// reader token, enforced at SinkCmd start.
func (h *Handler) checkReaderAuth(r *http.Request) error {
	if h.readerToken == "" {
		return nil
	}
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ErrUnauthorized
	}
	provided := strings.TrimSpace(header[len(prefix):])
	if subtle.ConstantTimeCompare([]byte(provided), []byte(h.readerToken)) != 1 {
		return ErrUnauthorized
	}
	return nil
}

// enforceBindings rejects an envelope whose signers include any keys
// whose configured binding does not match the envelope's namespace.
// Every signature that contributed to verification is checked — not
// just the threshold — so a single bound key being used outside its
// scope rejects the entire batch even if other unbound keys also
// signed. Keys with no binding entry are unrestricted.
func (h *Handler) enforceBindings(env conductor.AuditBatchEnvelope) error {
	if len(h.keyBindings) == 0 {
		return nil
	}
	for _, sig := range env.Signatures {
		binding, ok := h.keyBindings[sig.SignerKeyID]
		if !ok {
			continue
		}
		if !binding.Matches(env) {
			return fmt.Errorf("%w: key_id=%q org=%q fleet=%q instance=%q",
				ErrKeyBindingViolated, sig.SignerKeyID, env.OrgID, env.FleetID, env.InstanceID)
		}
	}
	return nil
}

type uploadRequest struct {
	Envelope conductor.AuditBatchEnvelope `json:"envelope"`
	Payload  []byte                       `json:"payload"`
}

func decodeUpload(w http.ResponseWriter, r *http.Request, maxBytes int64) (uploadRequest, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return uploadRequest{}, ErrRequestTooLarge
		}
		return uploadRequest{}, fmt.Errorf("%w: %w", ErrInvalidRequestBody, err)
	}

	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&top); err != nil {
		return uploadRequest{}, fmt.Errorf("%w: %w", ErrInvalidRequestBody, err)
	}
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return uploadRequest{}, fmt.Errorf("%w: trailing JSON token", ErrInvalidRequestBody)
	}
	// `json.RawMessage("null")` is a non-nil 4-byte value, so a `== nil`
	// check happily passes when the client sends `{"envelope": null,
	// "payload": null}`. Treat missing-key and explicit-null the same.
	if len(top) != 2 || isMissingOrNull(top["envelope"]) || isMissingOrNull(top["payload"]) {
		return uploadRequest{}, fmt.Errorf("%w: expected envelope and payload only", ErrInvalidRequestBody)
	}

	var req uploadRequest
	if err := strictDecode(top["envelope"], &req.Envelope); err != nil {
		return uploadRequest{}, fmt.Errorf("%w: envelope: %w", ErrInvalidRequestBody, err)
	}
	if err := strictDecode(top["payload"], &req.Payload); err != nil {
		return uploadRequest{}, fmt.Errorf("%w: payload: %w", ErrInvalidRequestBody, err)
	}
	return req, nil
}

func isMissingOrNull(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	trimmed := bytes.TrimSpace(raw)
	return bytes.Equal(trimmed, []byte("null"))
}

func strictDecode(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON token")
	}
	return nil
}

func dlpPatternNames(matches []scanner.TextDLPMatch) []string {
	names := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if match.PatternName == "" {
			continue
		}
		if _, ok := seen[match.PatternName]; ok {
			continue
		}
		seen[match.PatternName] = struct{}{}
		names = append(names, match.PatternName)
	}
	return names
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func statusForError(err error) int {
	switch {
	case errors.Is(err, ErrRequestTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, ErrInvalidRequestBody):
		return http.StatusBadRequest
	case errors.Is(err, ErrUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, ErrKeyBindingViolated):
		return http.StatusForbidden
	case errors.Is(err, ErrBatchConflict), errors.Is(err, ErrForkDetected):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
