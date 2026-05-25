// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/conductor"
)

const (
	defaultConductorID = "conductor"

	PublishPolicyBundlePath = "/api/v1/conductor/policy-bundles"
	LatestPolicyBundlePath  = "/api/v1/conductor/policy/latest"

	defaultMaxRequestBodyBytes = conductor.MaxConfigYAMLBytes * 2
)

// FollowerIdentityResolver returns the [FollowerIdentity] for an incoming
// request. Production implementations MUST derive identity from authenticated
// transport metadata (mTLS peer certificate subject, SAN, or extensions). A
// resolver that trusts a plain HTTP header lets any caller claim any
// follower identity and bypass every per-audience scoping check in this
// package. Returning a non-nil error causes the latest-bundle endpoint to
// respond with HTTP 401.
type FollowerIdentityResolver func(*http.Request) (FollowerIdentity, error)

// PublisherAuthorizer authorizes a policy bundle publish request. Production
// implementations MUST authenticate the publisher principal and restrict the
// orgs, fleets, and environments they may publish into; this package only
// invokes the hook and does not bind publisher to bundle org/fleet. Returning
// a non-nil error causes the publish endpoint to respond with HTTP 403.
type PublisherAuthorizer func(*http.Request) error

type HandlerOptions struct {
	Store               BundleStore
	Capabilities        conductor.CapabilitiesResponse
	Now                 func() time.Time
	MaxRequestBodyBytes int64
	FollowerIdentity    FollowerIdentityResolver
	AuthorizePublisher  PublisherAuthorizer
}

type Handler struct {
	store              BundleStore
	capabilities       conductor.CapabilitiesResponse
	now                func() time.Time
	maxRequestBody     int64
	followerIdentity   FollowerIdentityResolver
	authorizePublisher PublisherAuthorizer
}

type publishPolicyBundleRequest struct {
	Bundle conductor.PolicyBundle `json:"bundle"`
}

type publishPolicyBundleResponse struct {
	BundleID    string    `json:"bundle_id"`
	BundleHash  string    `json:"bundle_hash"`
	Version     uint64    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	Created     bool      `json:"created"`
}

func NewHandler(opts HandlerOptions) (*Handler, error) {
	if opts.Store == nil {
		return nil, ErrStoreRequired
	}
	if opts.FollowerIdentity == nil {
		return nil, ErrFollowerRequired
	}
	if opts.AuthorizePublisher == nil {
		return nil, ErrPublisherForbidden
	}
	capabilities := opts.Capabilities
	if capabilities.SchemaVersion == 0 {
		capabilities = DefaultCapabilities(defaultConductorID)
	}
	if err := capabilities.ValidateWithLocalThresholdCap(conductor.MaxCapabilityThreshold); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	maxBody := opts.MaxRequestBodyBytes
	if maxBody <= 0 {
		maxBody = defaultMaxRequestBodyBytes
	}
	return &Handler{
		store:              opts.Store,
		capabilities:       capabilities,
		now:                now,
		maxRequestBody:     maxBody,
		followerIdentity:   opts.FollowerIdentity,
		authorizePublisher: opts.AuthorizePublisher,
	}, nil
}

func DefaultCapabilities(conductorID string) conductor.CapabilitiesResponse {
	if strings.TrimSpace(conductorID) == "" {
		conductorID = defaultConductorID
	}
	return conductor.CapabilitiesResponse{
		SchemaVersion:          conductor.SchemaVersion,
		ConductorID:            conductorID,
		RequiredMTLS:           true,
		ConductorBundle:        conductor.SchemaRange{Min: conductor.SchemaVersion, Max: conductor.SchemaVersion},
		RemoteKill:             conductor.SchemaRange{Min: conductor.SchemaVersion, Max: conductor.SchemaVersion},
		RollbackAuthorization:  conductor.SchemaRange{Min: conductor.SchemaVersion, Max: conductor.SchemaVersion},
		AuditBatch:             conductor.SchemaRange{Min: conductor.SchemaVersion, Max: conductor.SchemaVersion},
		ReceiptEntryVersions:   []int{2},
		MaxCreatedSkewSeconds:  int(conductor.DefaultAuditMaxSkew / time.Second),
		EmergencyStream:        false,
		RemoteKillThreshold:    conductor.RequiredCatastrophicSigners,
		RollbackThreshold:      conductor.RequiredCatastrophicSigners,
		TrustRotationThreshold: conductor.RequiredCatastrophicSigners,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case conductor.CapabilitiesPath:
		h.handleCapabilities(w, r)
	case PublishPolicyBundlePath:
		h.handlePublishPolicyBundle(w, r)
	case LatestPolicyBundlePath:
		h.handleLatestPolicyBundle(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, h.capabilities)
}

func (h *Handler) handlePublishPolicyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPut, http.MethodPost)
		return
	}
	if err := h.authorizePublisher(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	var req publishPolicyBundleRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	record, created, err := h.store.Publish(r.Context(), req.Bundle, PublishOptions{Now: h.now()})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, publishPolicyBundleResponse{
		BundleID:    record.Bundle.BundleID,
		BundleHash:  record.BundleHash,
		Version:     record.Bundle.Version,
		PublishedAt: record.PublishedAt,
		Created:     created,
	})
}

func (h *Handler) handleLatestPolicyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	record, err := h.store.Latest(r.Context(), identity, h.now())
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	etag := fmt.Sprintf("%q", record.BundleHash)
	if ifNoneMatchMatches(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	writeJSON(w, http.StatusOK, record.Bundle)
}

func ifNoneMatchMatches(raw, etag string) bool {
	if raw == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, part := range strings.Split(raw, ",") {
		candidate := strings.TrimSpace(part)
		if candidate == "*" {
			return true
		}
		if strings.TrimPrefix(candidate, "W/") == want {
			return true
		}
	}
	return false
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dest any) error {
	if r.Body == nil {
		return errors.New("request body required")
	}
	body := http.MaxBytesReader(w, r.Body, maxBytes)
	defer func() { _ = body.Close() }()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dest); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON document")
	}
	return nil
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBundleConflict), errors.Is(err, ErrUnsupportedRollback):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, conductor.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, err)
	case errors.Is(err, conductor.ErrExpired):
		writeError(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, ErrFollowerRequired):
		// The transport-derived identity reached the store but did not
		// satisfy FollowerIdentity.Validate. Treat as an auth failure
		// rather than a generic bad request; a resolver that produces
		// an incomplete identity is functionally indistinguishable from
		// a missing one.
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
	default:
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}

func writeMethodNotAllowed(w http.ResponseWriter, methods ...string) {
	w.Header().Set("Allow", strings.Join(methods, ", "))
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
