//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
)

const (
	defaultConductorID = "conductor"

	PublishPolicyBundlePath    = "/api/v1/conductor/policy-bundles"
	LatestPolicyBundlePath     = "/api/v1/conductor/policy/latest"
	RemoteKillPath             = "/api/v1/conductor/remote-kill"
	RollbackAuthorizationsPath = "/api/v1/conductor/rollback-authorizations"
	AuditBatchesPath           = conductor.AuditBatchesPath
	FollowersPath              = "/api/v1/conductor/followers"
	StreamStatusPath           = "/api/v1/conductor/stream"
	EnrollPath                 = "/api/v1/conductor/enroll"
	EnrollmentTokensPath       = "/api/v1/conductor/enrollment-tokens" //nolint:gosec // route constant, not a credential
	HealthPath                 = "/health"
	HealthzPath                = "/healthz"
	MetricsPath                = "/metrics"
	ReadyzPath                 = "/readyz"

	defaultMaxRequestBodyBytes = conductor.MaxConfigYAMLBytes * 2
	defaultMaxAuditBodyBytes   = conductor.MaxAuditPayloadBytes * 2

	DefaultRemoteKillMaxValidity = 72 * time.Hour
	DefaultRollbackMaxValidity   = 24 * time.Hour
	// DefaultEnrollmentTokenMaxValidity caps how far in the future a minted
	// enrollment token may expire. An enrollment token is a one-shot bearer
	// credential handed to a starting follower; a multi-week window is a large
	// leaked-credential exposure with no upside, so the server rejects an
	// over-long --ttl rather than trusting the operator to keep it short.
	DefaultEnrollmentTokenMaxValidity = 24 * time.Hour
)

// Publish-conflict codes. A policy-bundle publish can be rejected with HTTP 409
// for three operationally distinct reasons; the control plane carries one of
// these machine-readable codes in the JSON error body's "code" field so the
// publishing CLI can render an accurate, actionable message instead of a single
// misleading "version is stale". The codes are part of the publish API contract
// and MUST stay in sync with the CLI's mapping (enterprise/cli/conductor).
const (
	// PublishConflictRollbackAttempt: the supplied version is below the current
	// (rolled-back) stream head. A forward publish cannot perform a rollback;
	// the operator must use the rollback authorization flow instead.
	PublishConflictRollbackAttempt = "rollback_attempt"
	// PublishConflictVersionBelowStreamMax: the version is not strictly greater
	// than the highest version EVER published in the stream (vN+1..vM exist after
	// a rollback, so a forward publish needs a version greater than M, not N).
	PublishConflictVersionBelowStreamMax = "version_below_stream_max"
	// PublishConflictPreviousHashMismatch: previous_bundle_hash does not match
	// the current stream head hash (a stale or copy-pasted chain pointer).
	PublishConflictPreviousHashMismatch = "previous_hash_mismatch"
	// PublishConflictOther: a 409 conflict that is none of the above (e.g. a
	// bundle_id/version already published with a different hash, or an initial
	// bundle that carries a previous_bundle_hash).
	PublishConflictOther = "conflict"
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

// BundleAuthorizer authorizes a parsed policy bundle after transport/client
// authentication has already succeeded. It exists so production wiring can
// enforce org/fleet scoped publisher credentials instead of treating bearer
// possession as global publish authority.
type BundleAuthorizer func(*http.Request, conductor.PolicyBundle) error

// AuditQueryAuthorizer authorizes a parsed metadata query. It MUST scope
// callers to the org/fleet they are permitted to inspect.
type AuditQueryAuthorizer func(*http.Request, AuditBatchQuery) error

// FollowerListAuthorizer authorizes a parsed follower-roster query. Like
// [AuditQueryAuthorizer] it MUST scope callers to the org/fleet they are
// permitted to inspect; a follower roster is fleet-topology metadata and is
// authorized identically to audit metadata.
type FollowerListAuthorizer func(*http.Request, FollowerListQuery) error

// StreamStatusAuthorizer authorizes a parsed stream-overview query. Like
// [FollowerListAuthorizer] it MUST scope callers to the org/fleet they are
// permitted to inspect; stream topology is fleet metadata and is authorized
// identically to the follower roster.
type StreamStatusAuthorizer func(*http.Request, StreamStatusQuery) error

type HandlerOptions struct {
	Store               BundleStore
	Capabilities        conductor.CapabilitiesResponse
	Now                 func() time.Time
	MaxRequestBodyBytes int64
	MaxAuditBodyBytes   int64
	FollowerIdentity    FollowerIdentityResolver
	AuthorizePublisher  PublisherAuthorizer
	AuthorizeBundle     BundleAuthorizer
	AuthorizeAuditQuery AuditQueryAuthorizer
	AuthorizeFollowers  FollowerListAuthorizer
	AuthorizeStream     StreamStatusAuthorizer
	AuthorizeAdmin      PublisherAuthorizer
	AuditSink           AuditBatchSink
	AuditKeys           AuditKeyResolver
	Enrollments         EnrollmentStore
	EmergencyControls   EmergencyStore
	EmergencyKeys       conductor.SignatureKeyResolver
	RemoteKillMaxTTL    time.Duration
	RollbackMaxTTL      time.Duration
	// EnrollmentTokenMaxTTL caps the validity window of a minted enrollment
	// token. Zero falls back to DefaultEnrollmentTokenMaxValidity.
	EnrollmentTokenMaxTTL time.Duration
	Metrics               *metrics.Metrics
	Logger                *slog.Logger
}

type Handler struct {
	store               BundleStore
	capabilities        conductor.CapabilitiesResponse
	now                 func() time.Time
	maxRequestBody      int64
	maxAuditBody        int64
	followerIdentity    FollowerIdentityResolver
	authorizePublisher  PublisherAuthorizer
	authorizeBundle     BundleAuthorizer
	authorizeAuditQuery AuditQueryAuthorizer
	authorizeFollowers  FollowerListAuthorizer
	authorizeStream     StreamStatusAuthorizer
	authorizeAdmin      PublisherAuthorizer
	auditSink           AuditBatchSink
	// nil auditQuerier means the configured sink does not implement
	// [AuditBatchQuerier], so GET returns 501 rather than a retryable 500.
	auditQuerier          AuditBatchQuerier
	auditKeys             AuditKeyResolver
	enrollments           EnrollmentStore
	emergencyControls     EmergencyStore
	emergencyKeys         conductor.SignatureKeyResolver
	remoteKillMaxTTL      time.Duration
	rollbackMaxTTL        time.Duration
	enrollmentTokenMaxTTL time.Duration
	metrics               *metrics.Metrics
	logger                *slog.Logger
}

type rollbackAuthorizationEnumerator interface {
	RollbackAuthorizations(context.Context) ([]StoredRollbackAuthorization, error)
}

type rollbackHeadReconciler interface {
	ReconcileRollbackHeads(context.Context, []StoredRollbackAuthorization, time.Time) ([]RollbackReconcileSkip, error)
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

type createEnrollmentTokenRequest struct {
	TokenID     string    `json:"token_id"`
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type createEnrollmentTokenResponse struct {
	TokenID   string    `json:"token_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type enrollRequest struct {
	Token          string `json:"token"`
	AuditKeyID     string `json:"audit_key_id"`
	AuditPublicKey string `json:"audit_public_key"`
}

type enrollResponse struct {
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	AuditKeyID  string    `json:"audit_key_id"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

type publishRemoteKillRequest struct {
	Message conductor.RemoteKillMessage `json:"message"`
}

type publishRemoteKillResponse struct {
	MessageID   string    `json:"message_id"`
	MessageHash string    `json:"message_hash"`
	Counter     uint64    `json:"counter"`
	PublishedAt time.Time `json:"published_at"`
	Created     bool      `json:"created"`
}

type publishRollbackAuthorizationRequest struct {
	Authorization conductor.RollbackAuthorization `json:"authorization"`
}

type publishRollbackAuthorizationResponse struct {
	AuthorizationID   string    `json:"authorization_id"`
	AuthorizationHash string    `json:"authorization_hash"`
	Counter           uint64    `json:"counter"`
	PublishedAt       time.Time `json:"published_at"`
	Created           bool      `json:"created"`
}

type healthResponse struct {
	Status string `json:"status"`
}

type readyResponse struct {
	Status     string          `json:"status"`
	Subsystems readySubsystems `json:"subsystems"`
}

type readySubsystems struct {
	PolicyStore         bool `json:"policy_store"`
	AuditSink           bool `json:"audit_sink"`
	AuditQuerySupported bool `json:"audit_query_supported"`
	AuditKeyResolver    bool `json:"audit_key_resolver"`
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
	if opts.AuditSink == nil {
		return nil, ErrAuditSinkRequired
	}
	if opts.AuditKeys == nil {
		return nil, ErrAuditKeyRequired
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
	maxAuditBody := opts.MaxAuditBodyBytes
	if maxAuditBody <= 0 {
		maxAuditBody = defaultMaxAuditBodyBytes
	}
	remoteKillMaxTTL := opts.RemoteKillMaxTTL
	if remoteKillMaxTTL <= 0 {
		remoteKillMaxTTL = DefaultRemoteKillMaxValidity
	}
	rollbackMaxTTL := opts.RollbackMaxTTL
	if rollbackMaxTTL <= 0 {
		rollbackMaxTTL = DefaultRollbackMaxValidity
	}
	enrollmentTokenMaxTTL := opts.EnrollmentTokenMaxTTL
	if enrollmentTokenMaxTTL <= 0 {
		enrollmentTokenMaxTTL = DefaultEnrollmentTokenMaxValidity
	}
	authorizeAuditQuery := opts.AuthorizeAuditQuery
	if authorizeAuditQuery == nil {
		authorizeAuditQuery = func(*http.Request, AuditBatchQuery) error {
			return ErrAuditQueryForbidden
		}
	}
	authorizeFollowers := opts.AuthorizeFollowers
	if authorizeFollowers == nil {
		// Fail closed: an unconfigured roster authorizer denies every read
		// rather than exposing the enrollment roster to any caller.
		authorizeFollowers = func(*http.Request, FollowerListQuery) error {
			return ErrFollowerListForbidden
		}
	}
	authorizeStream := opts.AuthorizeStream
	if authorizeStream == nil {
		// Fail closed: an unconfigured stream-status authorizer denies every read
		// rather than exposing stream topology to any caller.
		authorizeStream = func(*http.Request, StreamStatusQuery) error {
			return ErrStreamStatusForbidden
		}
	}
	authorizeBundle := opts.AuthorizeBundle
	if authorizeBundle == nil {
		authorizeBundle = func(*http.Request, conductor.PolicyBundle) error {
			return ErrPublisherForbidden
		}
	}
	authorizeAdmin := opts.AuthorizeAdmin
	if authorizeAdmin == nil {
		authorizeAdmin = func(*http.Request) error {
			return ErrPublisherForbidden
		}
	}
	auditQuerier, _ := opts.AuditSink.(AuditBatchQuerier)
	// Wrap the configured emergency store in the signature-verifying view. This
	// wrapper is the ONLY emergency-store type the Handler holds, so every read
	// and enumeration path filters out records that pass structural validation
	// but fail Ed25519 verification against the static operator-trusted control
	// keys. Startup reconcile below and all request-time reads consume the
	// verified view. A nil store stays nil (no emergency controls configured);
	// a nil/empty resolver quarantines every record but does not crash startup.
	emergencyControls := newVerifiedEmergencyStore(opts.EmergencyControls, opts.EmergencyKeys, opts.Logger, opts.Metrics)
	if err := reconcileRollbackHeads(opts.Store, emergencyControls, now(), opts.Logger); err != nil {
		return nil, err
	}
	return &Handler{
		store:                 opts.Store,
		capabilities:          capabilities,
		now:                   now,
		maxRequestBody:        maxBody,
		maxAuditBody:          maxAuditBody,
		followerIdentity:      opts.FollowerIdentity,
		authorizePublisher:    opts.AuthorizePublisher,
		authorizeBundle:       authorizeBundle,
		authorizeAuditQuery:   authorizeAuditQuery,
		authorizeFollowers:    authorizeFollowers,
		authorizeStream:       authorizeStream,
		authorizeAdmin:        authorizeAdmin,
		auditSink:             opts.AuditSink,
		auditQuerier:          auditQuerier,
		auditKeys:             opts.AuditKeys,
		enrollments:           opts.Enrollments,
		emergencyControls:     emergencyControls,
		emergencyKeys:         opts.EmergencyKeys,
		remoteKillMaxTTL:      remoteKillMaxTTL,
		rollbackMaxTTL:        rollbackMaxTTL,
		enrollmentTokenMaxTTL: enrollmentTokenMaxTTL,
		metrics:               opts.Metrics,
		logger:                opts.Logger,
	}, nil
}

// reconcileRollbackHeads re-applies persisted rollback authorizations to the
// stream heads at startup. It is best-effort: a failure to enumerate or a single
// unapplyable authorization is logged and tolerated, never fatal, so the control
// plane still starts (the durable head markers loaded by the store hold the
// effective head regardless). Only a programming error from the store (nil
// receiver) is propagated.
func reconcileRollbackHeads(store BundleStore, emergencyControls EmergencyStore, now time.Time, logger *slog.Logger) error {
	if emergencyControls == nil {
		return nil
	}
	lister, ok := emergencyControls.(rollbackAuthorizationEnumerator)
	if !ok {
		return nil
	}
	reconciler, ok := store.(rollbackHeadReconciler)
	if !ok {
		return nil
	}
	records, err := lister.RollbackAuthorizations(context.Background())
	if err != nil {
		// A control plane must still start even if the persisted rollback
		// authorizations cannot be listed; the durable head markers remain the
		// source of truth for the effective policy head.
		if logger != nil {
			logger.Warn("conductor_rollback_reconcile_list_failed", "error", err.Error())
		}
		return nil
	}
	skipped, err := reconciler.ReconcileRollbackHeads(context.Background(), records, now)
	if err != nil {
		return err
	}
	for _, skip := range skipped {
		if logger != nil {
			logger.Warn("conductor_rollback_reconcile_skipped",
				"authorization_id", skip.AuthorizationID,
				"error", skip.Err.Error())
		}
	}
	return nil
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
	h.serveMeasured(w, r, h.serveControlHTTP)
}

func (h *Handler) ProbeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serveMeasured(w, r, h.serveProbeHTTP)
	})
}

func (h *Handler) serveMeasured(w http.ResponseWriter, r *http.Request, serve func(http.ResponseWriter, *http.Request)) {
	route := conductorRoute(r.URL.Path)
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	start := time.Now()
	defer func() {
		duration := time.Since(start)
		status := rec.status
		h.recordRequest(r, route, status, duration)
	}()
	serve(rec, r)
}

func (h *Handler) serveControlHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case conductor.CapabilitiesPath:
		h.handleCapabilities(w, r)
	case EnrollmentTokensPath:
		h.handleEnrollmentTokens(w, r)
	case EnrollPath:
		h.handleEnroll(w, r)
	case RemoteKillPath:
		h.handleRemoteKill(w, r)
	case RollbackAuthorizationsPath:
		h.handleRollbackAuthorizations(w, r)
	case PublishPolicyBundlePath:
		h.handlePublishPolicyBundle(w, r)
	case LatestPolicyBundlePath:
		h.handleLatestPolicyBundle(w, r)
	case AuditBatchesPath:
		h.handleAuditBatch(w, r)
	case FollowersPath:
		h.handleListFollowers(w, r)
	case StreamStatusPath:
		h.handleStreamStatus(w, r)
	default:
		if isAuditBatchSubroute(r.URL.Path) {
			h.handleGetAuditBatch(w, r)
			return
		}
		http.NotFound(w, r)
	}
}

func (h *Handler) serveProbeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case HealthPath, HealthzPath:
		h.handleHealth(w, r)
	case MetricsPath:
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, http.MethodGet)
			return
		}
		if h.metrics == nil {
			http.NotFound(w, r)
			return
		}
		h.metrics.PrometheusHandler().ServeHTTP(w, r)
	case ReadyzPath:
		h.handleReady(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) recordRequest(r *http.Request, route string, status int, duration time.Duration) {
	h.metrics.RecordConductorServerRequest(route, r.Method, status, duration)
	if route == AuditBatchesPath {
		switch r.Method {
		case http.MethodPost:
			h.metrics.RecordConductorServerAuditIngest(conductorOperationOutcome(status, "accepted"), conductorStatusReason(status))
		case http.MethodGet:
			h.metrics.RecordConductorServerAuditQuery(conductorOperationOutcome(status, "listed"), conductorStatusReason(status))
		}
	}
	if h.logger == nil {
		return
	}
	h.logger.InfoContext(r.Context(), "conductor_request",
		slog.String("event", "conductor_request"),
		slog.String("route", route),
		slog.String("method", r.Method),
		slog.Int("status", status),
		slog.String("status_class", statusClass(status)),
		slog.Duration("duration", duration),
	)
}

func conductorRoute(path string) string {
	if isAuditBatchSubroute(path) {
		return AuditBatchesPath
	}
	switch path {
	case HealthPath, HealthzPath, MetricsPath, ReadyzPath, conductor.CapabilitiesPath, EnrollmentTokensPath, EnrollPath, RemoteKillPath, RollbackAuthorizationsPath, PublishPolicyBundlePath, LatestPolicyBundlePath, AuditBatchesPath, FollowersPath, StreamStatusPath:
		return path
	default:
		return "unknown"
	}
}

func isAuditBatchSubroute(path string) bool {
	return strings.HasPrefix(path, AuditBatchesPath+"/")
}

func conductorOperationOutcome(status int, success string) string {
	switch {
	case status >= 200 && status < 300:
		return success
	case status == http.StatusNotImplemented:
		return "unsupported"
	case status >= 400 && status < 500:
		return "rejected"
	default:
		return "error"
	}
}

func conductorStatusReason(status int) string {
	switch status {
	case http.StatusOK, http.StatusAccepted:
		return "ok"
	case http.StatusBadRequest:
		return "bad_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusConflict:
		return "conflict"
	case http.StatusRequestEntityTooLarge:
		return "payload_too_large"
	case http.StatusUnprocessableEntity:
		return "unprocessable_entity"
	case http.StatusNotImplemented:
		return "unsupported"
	default:
		return statusClass(status)
	}
}

func statusClass(status int) string {
	switch {
	case status >= 100 && status < 200:
		return "1xx"
	case status >= 200 && status < 300:
		return "2xx"
	case status >= 300 && status < 400:
		return "3xx"
	case status >= 400 && status < 500:
		return "4xx"
	case status >= 500 && status < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(p)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, http.MethodGet)
		return
	}
	subsystems := readySubsystems{
		PolicyStore:         h.store != nil,
		AuditSink:           h.auditSink != nil,
		AuditQuerySupported: h.auditQuerier != nil,
		AuditKeyResolver:    h.auditKeys != nil,
	}
	status := http.StatusOK
	state := "ready"
	if !subsystems.PolicyStore || !subsystems.AuditSink || !subsystems.AuditKeyResolver {
		status = http.StatusServiceUnavailable
		state = "not_ready"
	}
	writeJSON(w, status, readyResponse{
		Status:     state,
		Subsystems: subsystems,
	})
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
	if err := h.authorizeBundle(r, req.Bundle); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	record, created, err := h.store.Publish(r.Context(), req.Bundle, PublishOptions{Now: h.now()})
	if err != nil {
		writePublishStoreError(w, err)
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
	now := h.now()
	record, err := h.store.Latest(r.Context(), identity, now)
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	record, err = h.applyRollbackCeiling(r, identity, record, now)
	if err != nil {
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

func (h *Handler) applyRollbackCeiling(r *http.Request, identity FollowerIdentity, latest PublishedBundle, now time.Time) (PublishedBundle, error) {
	if h.emergencyControls == nil {
		return latest, nil
	}
	rollback, ok, err := h.emergencyControls.ActiveRollbackForFollower(r.Context(), identity, now)
	if err != nil {
		return PublishedBundle{}, err
	}
	if !ok {
		return latest, nil
	}
	auth := rollback.Authorization
	if latest.Bundle.Version > auth.CurrentVersion {
		return latest, nil
	}
	current, err := h.store.BundleByIDVersion(r.Context(), auth.CurrentBundleID, auth.CurrentVersion)
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			return PublishedBundle{}, fmt.Errorf("active rollback current unavailable: %w", err)
		}
		return PublishedBundle{}, err
	}
	target, err := h.store.BundleByIDVersion(r.Context(), auth.TargetBundleID, auth.TargetVersion)
	if err != nil {
		if errors.Is(err, ErrBundleNotFound) {
			return PublishedBundle{}, fmt.Errorf("active rollback target unavailable: %w", err)
		}
		return PublishedBundle{}, err
	}
	if current.StreamKey != latest.StreamKey || target.StreamKey != latest.StreamKey {
		return latest, nil
	}
	return target, nil
}

func (h *Handler) handleRemoteKill(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleLatestRemoteKill(w, r)
	case http.MethodPut, http.MethodPost:
		h.handlePublishRemoteKill(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPost)
	}
}

func (h *Handler) handlePublishRemoteKill(w http.ResponseWriter, r *http.Request) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	if h.emergencyKeys == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyKeyRequired)
		return
	}
	var req publishRemoteKillRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := h.now()
	if err := validateMaxValidity(req.Message.NotBefore, req.Message.ExpiresAt, h.remoteKillMaxTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := req.Message.VerifySignaturesAt(now, h.emergencyKeys); err != nil {
		writeStoreError(w, err)
		return
	}
	record, created, err := h.emergencyControls.PublishRemoteKill(r.Context(), req.Message, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, publishRemoteKillResponse{
		MessageID:   record.Message.MessageID,
		MessageHash: record.MessageHash,
		Counter:     record.Message.Counter,
		PublishedAt: record.PublishedAt,
		Created:     created,
	})
}

func (h *Handler) handleLatestRemoteKill(w http.ResponseWriter, r *http.Request) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	record, err := h.emergencyControls.LatestRemoteKill(r.Context(), identity, h.now())
	if err != nil {
		if errors.Is(err, ErrEmergencyNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record.Message)
}

func (h *Handler) handleRollbackAuthorizations(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleLatestRollbackAuthorization(w, r)
	case http.MethodPut, http.MethodPost:
		h.handlePublishRollbackAuthorization(w, r)
	case http.MethodDelete:
		h.handleClearRollbackAuthorization(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodGet, http.MethodPut, http.MethodPost, http.MethodDelete)
	}
}

func (h *Handler) handlePublishRollbackAuthorization(w http.ResponseWriter, r *http.Request) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	if h.emergencyKeys == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyKeyRequired)
		return
	}
	var req publishRollbackAuthorizationRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Authorization.Audience.InstanceIDs) != 0 || len(req.Authorization.Audience.Labels) != 0 {
		writeStoreError(w, fmt.Errorf("%w: rollback audience must be empty", conductor.ErrInvalidRollback))
		return
	}
	now := h.now()
	if err := validateMaxValidity(req.Authorization.CreatedAt, req.Authorization.ExpiresAt, h.rollbackMaxTTL); err != nil {
		writeStoreError(w, err)
		return
	}
	if err := req.Authorization.VerifySignaturesAt(now, h.emergencyKeys); err != nil {
		writeStoreError(w, err)
		return
	}
	if _, err := h.store.BundleByIDVersion(r.Context(), req.Authorization.TargetBundleID, req.Authorization.TargetVersion); err != nil {
		writeStoreError(w, err)
		return
	}
	record, created, err := h.emergencyControls.PublishRollbackAuthorization(r.Context(), req.Authorization, now)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := h.store.ApplyRollbackHead(r.Context(), req.Authorization, now); err != nil {
		writeStoreError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, publishRollbackAuthorizationResponse{
		AuthorizationID:   record.Authorization.AuthorizationID,
		AuthorizationHash: record.AuthorizationHash,
		Counter:           record.Authorization.Counter,
		PublishedAt:       record.PublishedAt,
		Created:           created,
	})
}

// rollbackClearer is the optional interface an [EmergencyStore] may implement
// to support clearing (removing) a rollback authorization by its
// authorization_id. The [FileEmergencyStore] implements it. Stores that do not
// implement it degrade to HTTP 501 Not Implemented on DELETE.
type rollbackClearer interface {
	ClearRollbackAuthorization(ctx context.Context, authorizationID string) (bool, error)
}

// clearRollbackAuthorizationRequest is the JSON body for DELETE
// /api/v1/conductor/rollback-authorizations.
type clearRollbackAuthorizationRequest struct {
	AuthorizationID string `json:"authorization_id"`
}

func (h *Handler) handleClearRollbackAuthorization(w http.ResponseWriter, r *http.Request) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	clearer, ok := h.emergencyControls.(rollbackClearer)
	if !ok {
		writeError(w, http.StatusNotImplemented, ErrEmergencyClearUnsupported)
		return
	}
	var req clearRollbackAuthorizationRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if strings.TrimSpace(req.AuthorizationID) == "" {
		writeError(w, http.StatusBadRequest, fmt.Errorf("%w: authorization_id", conductor.ErrMissingField))
		return
	}
	cleared, err := clearer.ClearRollbackAuthorization(r.Context(), req.AuthorizationID)
	if err != nil {
		if errors.Is(err, ErrEmergencyClearUnsupported) {
			writeError(w, http.StatusNotImplemented, err)
			return
		}
		writeStoreError(w, err)
		return
	}
	if !cleared {
		writeError(w, http.StatusNotFound, ErrEmergencyNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authorization_id": req.AuthorizationID,
		"cleared":          true,
	})
}

func (h *Handler) handleLatestRollbackAuthorization(w http.ResponseWriter, r *http.Request) {
	if h.emergencyControls == nil {
		writeError(w, http.StatusNotImplemented, ErrEmergencyStoreRequired)
		return
	}
	identity, err := h.followerIdentity(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrFollowerRequired)
		return
	}
	lookup, err := rollbackLookupFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	record, err := h.emergencyControls.LatestRollbackAuthorization(r.Context(), identity, lookup, h.now())
	if err != nil {
		if errors.Is(err, ErrEmergencyNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record.Authorization)
}

func rollbackLookupFromRequest(r *http.Request) (RollbackLookup, error) {
	q := r.URL.Query()
	currentVersion, err := parseRequiredUint64Query(q.Get("current_version"), "current_version")
	if err != nil {
		return RollbackLookup{}, err
	}
	targetVersion, err := parseRequiredUint64Query(q.Get("target_version"), "target_version")
	if err != nil {
		return RollbackLookup{}, err
	}
	lookup := RollbackLookup{
		CurrentBundleID: q.Get("current_bundle_id"),
		CurrentVersion:  currentVersion,
		TargetBundleID:  q.Get("target_bundle_id"),
		TargetVersion:   targetVersion,
	}
	if err := lookup.Validate(); err != nil {
		return RollbackLookup{}, err
	}
	return lookup, nil
}

func parseRequiredUint64Query(value, field string) (uint64, error) {
	if strings.TrimSpace(value) == "" {
		return 0, fmt.Errorf("%w: %s", conductor.ErrMissingField, field)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", field, err)
	}
	return parsed, nil
}

func validateMaxValidity(start, expires time.Time, maxTTL time.Duration) error {
	if maxTTL <= 0 {
		return nil
	}
	if start.IsZero() || expires.IsZero() || !expires.After(start) {
		return conductor.ErrInvalidValidityWindow
	}
	if expires.Sub(start) > maxTTL {
		return fmt.Errorf("%w: validity %s exceeds max %s", conductor.ErrInvalidValidityWindow, expires.Sub(start), maxTTL)
	}
	return nil
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

// writePublishStoreError maps a policy-bundle Publish error to an HTTP response.
// It preserves the exact status semantics of writeStoreError (publish conflicts
// remain HTTP 409 Conflict) but DE-CONFLATES the 409 body: it attaches a
// machine-readable "code" so the publishing CLI can distinguish a rollback
// attempt, a below-stream-max version, and a previous_bundle_hash mismatch
// instead of collapsing all three into one misleading "version is stale".
// Non-conflict errors fall through to writeStoreError unchanged.
func writePublishStoreError(w http.ResponseWriter, err error) {
	if !errors.Is(err, ErrBundleConflict) {
		writeStoreError(w, err)
		return
	}
	writeCodedError(w, http.StatusConflict, publishConflictCode(err), err)
}

// publishConflictCode classifies an ErrBundleConflict from the forward-publish
// authorization path into one of the operator-facing PublishConflict* codes.
// Order matters: the rollback-attempt case wraps ErrUnsupportedRollback in
// addition to ErrBundleConflict, so it must be checked before the umbrella
// fallthrough. The codes mirror the distinct wrapped sentinels set by
// authorizeForwardLocked in store.go.
func publishConflictCode(err error) string {
	switch {
	case errors.Is(err, ErrUnsupportedRollback):
		return PublishConflictRollbackAttempt
	case errors.Is(err, ErrVersionBelowStreamMax):
		return PublishConflictVersionBelowStreamMax
	case errors.Is(err, ErrPreviousHashMismatch):
		return PublishConflictPreviousHashMismatch
	default:
		return PublishConflictOther
	}
}

// writeCodedError writes a JSON error body carrying both the human-readable
// message and a stable machine-readable code. Mirrors writeError's shape with
// the extra "code" field so existing {"error":"..."} parsers keep working.
func writeCodedError(w http.ResponseWriter, status int, code string, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error(), "code": code})
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBundleConflict), errors.Is(err, ErrUnsupportedRollback), errors.Is(err, ErrEmergencyConflict), errors.Is(err, ErrEmergencyStaleCounter):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, ErrBundleNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, conductor.ErrPayloadTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, err)
	case errors.Is(err, conductor.ErrUnsupportedSchemaVersion), errors.Is(err, conductor.ErrInvalidHash),
		errors.Is(err, conductor.ErrInvalidSequenceRange), errors.Is(err, conductor.ErrInvalidDroppedAccounting),
		errors.Is(err, conductor.ErrInvalidMinVersion):
		// Client-input validation sentinels for a malformed-but-well-formed
		// bundle structure. PolicyBundle.Validate produces these on publish;
		// they are caller faults, not internal errors. Mirrors the
		// audit-ingest path (writeAuditIngestError) which maps the same
		// structural sentinels to 400.
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, conductor.ErrExpired), errors.Is(err, conductor.ErrHashMismatch):
		// Semantically invalid but well-formed: an expired window or a hash
		// that does not match the supplied payload. Mirrors the audit-ingest
		// path which maps ErrHashMismatch to 422.
		writeError(w, http.StatusUnprocessableEntity, err)
	case errors.Is(err, conductor.ErrInvalidRollback), errors.Is(err, conductor.ErrInvalidState),
		errors.Is(err, conductor.ErrInvalidAudience), errors.Is(err, conductor.ErrMissingField),
		errors.Is(err, conductor.ErrInvalidValidityWindow), errors.Is(err, conductor.ErrInvalidReason),
		errors.Is(err, conductor.ErrThresholdRequired), errors.Is(err, conductor.ErrWrongKeyPurpose),
		errors.Is(err, conductor.ErrInvalidIdentifier), errors.Is(err, conductor.ErrInvalidSignature),
		errors.Is(err, conductor.ErrSignatureVerification), errors.Is(err, conductor.ErrNotYetValid):
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
