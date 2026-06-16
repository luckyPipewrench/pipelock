//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"container/heap"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	enrollmentTokenBytes  = 32
	enrollmentTokenPrefix = "pl_enroll_"

	// defaultFollowerListLimit / maxFollowerListLimit bound the roster read so
	// a large or malicious enrollment store cannot force an unbounded response.
	defaultFollowerListLimit = 100
	maxFollowerListLimit     = 1000
)

var (
	ErrEnrollmentStoreRequired  = errors.New("conductor enrollment store required")
	ErrEnrollmentTokenInvalid   = errors.New("conductor enrollment token invalid")
	ErrEnrollmentTokenConflict  = errors.New("conductor enrollment token conflicts with existing token")
	ErrEnrollmentTokenConsumed  = errors.New("conductor enrollment token consumed")
	ErrEnrollmentTokenExpired   = errors.New("conductor enrollment token expired")
	ErrEnrollmentActiveInstance = errors.New("conductor follower instance already enrolled")
	ErrEnrollmentTokenNotFound  = errors.New("conductor enrollment token not found")
	// ErrEnrollmentTokenNotPending is returned when a revoke targets a token
	// that is no longer pending (already consumed or already revoked). Revoke is
	// only meaningful for an outstanding, unused token; a consumed token has
	// already done its one job and re-revoking it must fail loud rather than
	// pretend to undo an enrollment.
	ErrEnrollmentTokenNotPending = errors.New("conductor enrollment token is not pending")
)

type EnrollmentStore interface {
	CreateEnrollmentToken(context.Context, EnrollmentTokenSpec) (IssuedEnrollmentToken, error)
	ConsumeEnrollmentToken(context.Context, ConsumeEnrollmentTokenRequest) (EnrolledFollower, error)
	ResolveEnrolledAuditKey(FollowerIdentity, string) (conductor.SignatureKey, error)
	ListEnrolledFollowers(context.Context, FollowerListQuery) ([]FollowerSummary, error)
	// ListEnrollmentTokens returns the metadata-only roster of enrollment
	// tokens. It MUST NOT return token bytes or the token hash: the secret is
	// write-once at mint time and never readable again.
	ListEnrollmentTokens(context.Context, EnrollmentTokenListQuery) ([]EnrollmentTokenSummary, error)
	// RevokeEnrollmentToken invalidates a single pending token by its stable
	// token_id so a leaked-but-unused token can be killed before it enrolls a
	// follower. It fails closed: a consumed or already-revoked token is not
	// re-revoked (ErrEnrollmentTokenNotPending), and an unknown id is
	// ErrEnrollmentTokenNotFound.
	RevokeEnrollmentToken(context.Context, RevokeEnrollmentTokenRequest) (EnrollmentTokenSummary, error)
}

// EnrollmentTokenState is the lifecycle state reported for an enrollment token.
// It is derived (not persisted) from the record's consumed/revoked/expiry
// fields at read time so a single source of truth (the record) drives it.
type EnrollmentTokenState string

const (
	EnrollmentTokenStatePending  EnrollmentTokenState = "pending"
	EnrollmentTokenStateConsumed EnrollmentTokenState = "consumed"
	EnrollmentTokenStateRevoked  EnrollmentTokenState = "revoked"
	EnrollmentTokenStateExpired  EnrollmentTokenState = "expired"
)

// EnrollmentTokenListQuery scopes an enrollment-token metadata read. All filter
// fields are optional exact-match filters; an empty query lists every token
// (bounded by Limit). TokenID is the lookup key for the single-token status
// read. Now is the reference time used to DERIVE each token's lifecycle state
// (pending vs expired); zero falls back to the wall clock so a direct store
// caller still works, but the handler passes its injected clock so state is
// computed against the same clock the rest of the control plane uses.
type EnrollmentTokenListQuery struct {
	TokenID     string
	OrgID       string
	FleetID     string
	InstanceID  string
	Environment string
	Limit       int
	Now         time.Time
}

// RevokeEnrollmentTokenRequest names the token to revoke and the time to stamp
// the revocation. TokenID is the stable mint-time id, never the secret.
type RevokeEnrollmentTokenRequest struct {
	TokenID string
	Now     time.Time
}

// EnrollmentTokenSummary is the metadata-only view of one enrollment token. It
// deliberately omits the token bytes AND the token hash: the secret is only ever
// returned once, at mint, so an operator listing or inspecting tokens sees
// lifecycle metadata, never anything that could re-derive or replay the
// credential.
type EnrollmentTokenSummary struct {
	TokenID     string               `json:"token_id"`
	OrgID       string               `json:"org_id"`
	FleetID     string               `json:"fleet_id"`
	InstanceID  string               `json:"instance_id"`
	Environment string               `json:"environment"`
	State       EnrollmentTokenState `json:"state"`
	CreatedAt   time.Time            `json:"created_at"`
	ExpiresAt   time.Time            `json:"expires_at"`
	ConsumedAt  *time.Time           `json:"consumed_at,omitempty"`
	RevokedAt   *time.Time           `json:"revoked_at,omitempty"`
}

// FollowerListQuery scopes a follower-roster read. OrgID is mandatory at the
// handler layer; the store applies whichever of OrgID/FleetID/InstanceID are
// non-empty as exact-match filters. Limit caps the returned roster size to
// bound memory and response size for a malicious or pathological store.
type FollowerListQuery struct {
	OrgID      string
	FleetID    string
	InstanceID string
	Limit      int
}

// FollowerSummary is the metadata-only view of one enrolled follower returned
// by [EnrollmentStore.ListEnrolledFollowers]. It deliberately omits the audit
// PUBLIC key bytes: an operator listing the roster has no need for the raw key
// material, and excluding it keeps the response surface minimal. The store
// tracks enrollment state only; applied bundle version and last-contact time
// are NOT recorded by the enrollment store today, so this summary does not
// claim them.
type FollowerSummary struct {
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	AuditKeyID  string    `json:"audit_key_id"`
	EnrolledAt  time.Time `json:"enrolled_at"`
	Active      bool      `json:"active"`
}

type EnrollmentTokenSpec struct {
	TokenID  string
	Identity FollowerIdentity
	Expires  time.Time
	Now      time.Time
}

type IssuedEnrollmentToken struct {
	TokenID   string
	Token     string
	ExpiresAt time.Time
}

type ConsumeEnrollmentTokenRequest struct {
	Token      string
	AuditKeyID string
	AuditKey   conductor.SignatureKey
	Now        time.Time
}

type EnrolledFollower struct {
	Identity   FollowerIdentity
	AuditKeyID string
	AuditKey   conductor.SignatureKey
	EnrolledAt time.Time
}

type FileEnrollmentStore struct {
	path string
	mu   sync.Mutex
	data enrollmentDiskState
}

type enrollmentDiskState struct {
	Tokens    map[string]enrollmentTokenRecord  `json:"tokens"`
	Followers map[string]enrolledFollowerRecord `json:"followers"`
}

type enrollmentTokenRecord struct {
	TokenID      string           `json:"token_id"`
	TokenHash    string           `json:"token_hash"`
	Identity     FollowerIdentity `json:"identity"`
	CreatedAt    time.Time        `json:"created_at"`
	ExpiresAt    time.Time        `json:"expires_at"`
	ConsumedAt   *time.Time       `json:"consumed_at,omitempty"`
	ConsumedByID string           `json:"consumed_by_instance_id,omitempty"`
	RevokedAt    *time.Time       `json:"revoked_at,omitempty"`
}

// tokenState derives the lifecycle state of a token record relative to now.
// Order matters: a consumed token stays "consumed" even past expiry (it did its
// job); a revoked-but-unconsumed token is "revoked"; otherwise expiry wins over
// pending. This is the single place the four states are decided.
func (r enrollmentTokenRecord) tokenState(now time.Time) EnrollmentTokenState {
	switch {
	case r.ConsumedAt != nil:
		return EnrollmentTokenStateConsumed
	case r.RevokedAt != nil:
		return EnrollmentTokenStateRevoked
	case !now.Before(r.ExpiresAt):
		return EnrollmentTokenStateExpired
	default:
		return EnrollmentTokenStatePending
	}
}

func (r enrollmentTokenRecord) summary(now time.Time) EnrollmentTokenSummary {
	return EnrollmentTokenSummary{
		TokenID:     r.TokenID,
		OrgID:       r.Identity.OrgID,
		FleetID:     r.Identity.FleetID,
		InstanceID:  r.Identity.InstanceID,
		Environment: r.Identity.Environment,
		State:       r.tokenState(now),
		CreatedAt:   r.CreatedAt,
		ExpiresAt:   r.ExpiresAt,
		ConsumedAt:  r.ConsumedAt,
		RevokedAt:   r.RevokedAt,
	}
}

type enrolledFollowerRecord struct {
	Identity   FollowerIdentity       `json:"identity"`
	AuditKeyID string                 `json:"audit_key_id"`
	AuditKey   conductor.SignatureKey `json:"audit_key"`
	EnrolledAt time.Time              `json:"enrolled_at"`
	Active     bool                   `json:"active"`
}

func OpenFileEnrollmentStore(path string) (*FileEnrollmentStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("conductor enrollment store path required")
	}
	clean := filepath.Clean(path)
	dir, err := secureDir(filepath.Dir(clean))
	if err != nil {
		return nil, err
	}
	store := &FileEnrollmentStore{
		path: filepath.Join(dir, filepath.Base(clean)),
		data: enrollmentDiskState{
			Tokens:    make(map[string]enrollmentTokenRecord),
			Followers: make(map[string]enrolledFollowerRecord),
		},
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileEnrollmentStore) CreateEnrollmentToken(_ context.Context, spec EnrollmentTokenSpec) (IssuedEnrollmentToken, error) {
	if s == nil {
		return IssuedEnrollmentToken{}, ErrEnrollmentStoreRequired
	}
	spec.TokenID = strings.TrimSpace(spec.TokenID)
	if err := conductor.ValidateIdentifier("token_id", spec.TokenID); err != nil {
		return IssuedEnrollmentToken{}, err
	}
	if err := spec.Identity.Validate(); err != nil {
		return IssuedEnrollmentToken{}, err
	}
	now := spec.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	expires := spec.Expires.UTC()
	if expires.IsZero() || !expires.After(now) {
		return IssuedEnrollmentToken{}, conductor.ErrInvalidValidityWindow
	}
	token, err := newEnrollmentToken()
	if err != nil {
		return IssuedEnrollmentToken{}, err
	}
	record := enrollmentTokenRecord{
		TokenID:   spec.TokenID,
		TokenHash: hashEnrollmentToken(token),
		Identity:  spec.Identity,
		CreatedAt: now,
		ExpiresAt: expires,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data.Tokens[spec.TokenID]; exists {
		return IssuedEnrollmentToken{}, ErrEnrollmentTokenConflict
	}
	s.data.Tokens[spec.TokenID] = record
	if err := s.saveLocked(); err != nil {
		delete(s.data.Tokens, spec.TokenID)
		return IssuedEnrollmentToken{}, err
	}
	return IssuedEnrollmentToken{TokenID: spec.TokenID, Token: token, ExpiresAt: expires}, nil
}

func (s *FileEnrollmentStore) ConsumeEnrollmentToken(_ context.Context, req ConsumeEnrollmentTokenRequest) (EnrolledFollower, error) {
	if s == nil {
		return EnrolledFollower{}, ErrEnrollmentStoreRequired
	}
	req.Token = strings.TrimSpace(req.Token)
	req.AuditKeyID = strings.TrimSpace(req.AuditKeyID)
	if req.Token == "" {
		return EnrolledFollower{}, ErrEnrollmentTokenInvalid
	}
	if err := conductor.ValidateIdentifier("audit_key_id", req.AuditKeyID); err != nil {
		return EnrolledFollower{}, err
	}
	if len(req.AuditKey.PublicKey) != ed25519.PublicKeySize || req.AuditKey.KeyPurpose != signing.PurposeAuditBatchSigning {
		return EnrolledFollower{}, ErrAuditKeyRequired
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	tokenHash := hashEnrollmentToken(req.Token)

	s.mu.Lock()
	defer s.mu.Unlock()
	tokenID, token, ok := s.findTokenByHashLocked(tokenHash)
	if !ok {
		return EnrolledFollower{}, ErrEnrollmentTokenInvalid
	}
	if token.ConsumedAt != nil {
		return EnrolledFollower{}, ErrEnrollmentTokenConsumed
	}
	if token.RevokedAt != nil {
		// A revoked token must never enroll a follower. Treat it as invalid so a
		// leaked-then-revoked token fails closed at consume time.
		return EnrolledFollower{}, ErrEnrollmentTokenInvalid
	}
	if !now.Before(token.ExpiresAt) {
		return EnrolledFollower{}, ErrEnrollmentTokenExpired
	}
	followerKey := followerEnrollmentKey(token.Identity)
	if follower, ok := s.data.Followers[followerKey]; ok && follower.Active {
		return EnrolledFollower{}, ErrEnrollmentActiveInstance
	}
	previousFollower, hadPreviousFollower := s.data.Followers[followerKey]
	enrolled := enrolledFollowerRecord{
		Identity:   token.Identity,
		AuditKeyID: req.AuditKeyID,
		AuditKey:   req.AuditKey,
		EnrolledAt: now,
		Active:     true,
	}
	token.ConsumedAt = &now
	token.ConsumedByID = token.Identity.InstanceID
	s.data.Tokens[tokenID] = token
	s.data.Followers[followerKey] = enrolled
	if err := s.saveLocked(); err != nil {
		token.ConsumedAt = nil
		token.ConsumedByID = ""
		s.data.Tokens[tokenID] = token
		if hadPreviousFollower {
			s.data.Followers[followerKey] = previousFollower
		} else {
			delete(s.data.Followers, followerKey)
		}
		return EnrolledFollower{}, err
	}
	return EnrolledFollower{
		Identity:   enrolled.Identity,
		AuditKeyID: enrolled.AuditKeyID,
		AuditKey:   enrolled.AuditKey,
		EnrolledAt: enrolled.EnrolledAt,
	}, nil
}

func (s *FileEnrollmentStore) ResolveEnrolledAuditKey(identity FollowerIdentity, signerKeyID string) (conductor.SignatureKey, error) {
	if s == nil {
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	follower, ok := s.data.Followers[followerEnrollmentKey(identity)]
	if !ok || !follower.Active || follower.AuditKeyID != signerKeyID {
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
	return follower.AuditKey, nil
}

// ListEnrolledFollowers returns the metadata-only roster of enrolled
// followers matching q. The org/fleet/instance filters are applied as exact
// matches over the persisted records; the handler is responsible for forcing a
// non-empty OrgID and binding it to the caller's authorized scope so this
// method is never reachable as an unscoped "list everything" read. Results are
// sorted deterministically (org, fleet, instance, environment) and capped at
// FollowerListQuery.Limit (clamped to [1, maxFollowerListLimit]).
func (s *FileEnrollmentStore) ListEnrolledFollowers(_ context.Context, q FollowerListQuery) ([]FollowerSummary, error) {
	if s == nil {
		return nil, ErrEnrollmentStoreRequired
	}
	limit := normalizeFollowerListLimit(q.Limit)

	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(followerSummaryMaxHeap, 0, limit)
	for _, follower := range s.data.Followers {
		if q.OrgID != "" && follower.Identity.OrgID != q.OrgID {
			continue
		}
		if q.FleetID != "" && follower.Identity.FleetID != q.FleetID {
			continue
		}
		if q.InstanceID != "" && follower.Identity.InstanceID != q.InstanceID {
			continue
		}
		summary := FollowerSummary{
			OrgID:       follower.Identity.OrgID,
			FleetID:     follower.Identity.FleetID,
			InstanceID:  follower.Identity.InstanceID,
			Environment: follower.Identity.Environment,
			AuditKeyID:  follower.AuditKeyID,
			EnrolledAt:  follower.EnrolledAt,
			Active:      follower.Active,
		}
		if len(out) < limit {
			heap.Push(&out, summary)
			continue
		}
		if followerSummaryLess(summary, out[0]) {
			out[0] = summary
			heap.Fix(&out, 0)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return followerSummaryLess(out[i], out[j])
	})
	return []FollowerSummary(out), nil
}

// ListEnrollmentTokens returns the metadata-only roster of enrollment tokens
// matching q, newest-first by creation time (ties broken by token_id). It NEVER
// returns the token bytes or token hash; only lifecycle metadata. The result is
// capped at q.Limit (clamped to [1, maxFollowerListLimit]) to bound the response
// for a large or pathological store.
func (s *FileEnrollmentStore) ListEnrollmentTokens(_ context.Context, q EnrollmentTokenListQuery) ([]EnrollmentTokenSummary, error) {
	if s == nil {
		return nil, ErrEnrollmentStoreRequired
	}
	limit := normalizeFollowerListLimit(q.Limit)
	now := q.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]EnrollmentTokenSummary, 0, len(s.data.Tokens))
	for _, token := range s.data.Tokens {
		if q.TokenID != "" && token.TokenID != q.TokenID {
			continue
		}
		if q.OrgID != "" && token.Identity.OrgID != q.OrgID {
			continue
		}
		if q.FleetID != "" && token.Identity.FleetID != q.FleetID {
			continue
		}
		if q.InstanceID != "" && token.Identity.InstanceID != q.InstanceID {
			continue
		}
		if q.Environment != "" && token.Identity.Environment != q.Environment {
			continue
		}
		out = append(out, token.summary(now))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].TokenID < out[j].TokenID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RevokeEnrollmentToken marks a single pending token revoked so it can no longer
// be consumed. It fails closed: an unknown token_id is ErrEnrollmentTokenNotFound
// and a token that is not pending (already consumed, already revoked, or
// expired) is ErrEnrollmentTokenNotPending. The persisted RevokedAt stamp is
// durable across restart, and ConsumeEnrollmentToken rejects a revoked token, so
// a revoked token stays dead.
func (s *FileEnrollmentStore) RevokeEnrollmentToken(_ context.Context, req RevokeEnrollmentTokenRequest) (EnrollmentTokenSummary, error) {
	if s == nil {
		return EnrollmentTokenSummary{}, ErrEnrollmentStoreRequired
	}
	tokenID := strings.TrimSpace(req.TokenID)
	if err := conductor.ValidateIdentifier("token_id", tokenID); err != nil {
		return EnrollmentTokenSummary{}, err
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	token, ok := s.data.Tokens[tokenID]
	if !ok {
		return EnrollmentTokenSummary{}, ErrEnrollmentTokenNotFound
	}
	// Only a still-pending token may be revoked. Deriving the gate from
	// tokenState keeps the "what is pending" decision in one place.
	if token.tokenState(now) != EnrollmentTokenStatePending {
		return EnrollmentTokenSummary{}, ErrEnrollmentTokenNotPending
	}
	revokedAt := now
	token.RevokedAt = &revokedAt
	s.data.Tokens[tokenID] = token
	if err := s.saveLocked(); err != nil {
		// Roll back the in-memory mutation so a failed durable write does not
		// leave a token that looks revoked in memory but is not on disk.
		token.RevokedAt = nil
		s.data.Tokens[tokenID] = token
		return EnrollmentTokenSummary{}, err
	}
	return token.summary(now), nil
}

type followerSummaryMaxHeap []FollowerSummary

func (h followerSummaryMaxHeap) Len() int {
	return len(h)
}

func (h followerSummaryMaxHeap) Less(i, j int) bool {
	return followerSummaryLess(h[j], h[i])
}

func (h followerSummaryMaxHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *followerSummaryMaxHeap) Push(x any) {
	*h = append(*h, x.(FollowerSummary))
}

func (h *followerSummaryMaxHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func followerSummaryLess(a, b FollowerSummary) bool {
	if a.OrgID != b.OrgID {
		return a.OrgID < b.OrgID
	}
	if a.FleetID != b.FleetID {
		return a.FleetID < b.FleetID
	}
	if a.InstanceID != b.InstanceID {
		return a.InstanceID < b.InstanceID
	}
	return a.Environment < b.Environment
}

func normalizeFollowerListLimit(limit int) int {
	if limit <= 0 {
		return defaultFollowerListLimit
	}
	if limit > maxFollowerListLimit {
		return maxFollowerListLimit
	}
	return limit
}

func (s *FileEnrollmentStore) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read enrollment store: %w", err)
	}
	var state enrollmentDiskState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("decode enrollment store: %w", err)
	}
	if state.Tokens == nil {
		state.Tokens = make(map[string]enrollmentTokenRecord)
	}
	if state.Followers == nil {
		state.Followers = make(map[string]enrolledFollowerRecord)
	}
	s.data = state
	return nil
}

func (s *FileEnrollmentStore) saveLocked() error {
	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode enrollment store: %w", err)
	}
	data = append(data, '\n')
	if err := durableWrite(s.path, data); err != nil {
		return fmt.Errorf("write enrollment store: %w", err)
	}
	return nil
}

func (s *FileEnrollmentStore) findTokenByHashLocked(tokenHash string) (string, enrollmentTokenRecord, bool) {
	for id, token := range s.data.Tokens {
		if subtle.ConstantTimeCompare([]byte(token.TokenHash), []byte(tokenHash)) == 1 {
			return id, token, true
		}
	}
	return "", enrollmentTokenRecord{}, false
}

func CompositeAuditKeyResolver(primary EnrollmentStore, fallback AuditKeyResolver) AuditKeyResolver {
	return func(identity FollowerIdentity, signerKeyID string) (conductor.SignatureKey, error) {
		if primary != nil {
			key, err := primary.ResolveEnrolledAuditKey(identity, signerKeyID)
			if err == nil {
				return key, nil
			}
		}
		if fallback != nil {
			return fallback(identity, signerKeyID)
		}
		return conductor.SignatureKey{}, conductor.ErrSignatureVerification
	}
}

func (h *Handler) handleEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handleCreateEnrollmentToken(w, r)
	case http.MethodGet:
		h.handleListEnrollmentTokens(w, r)
	case http.MethodDelete:
		h.handleRevokeEnrollmentToken(w, r)
	default:
		writeMethodNotAllowed(w, http.MethodPost, http.MethodGet, http.MethodDelete)
	}
}

func (h *Handler) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	var req createEnrollmentTokenRequest
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
	// Enforce the server-side maximum validity window BEFORE the store mints a
	// token. An operator cannot widen their leaked-credential exposure past the
	// configured ceiling regardless of the --ttl they pass. A zero-width or
	// already-expired window and an over-long window both surface here as
	// ErrInvalidValidityWindow; route through writeEnrollmentError so the
	// enrollment endpoint maps validity-window faults to 400 consistently with
	// the store's own create-path validation.
	if err := validateMaxValidity(now, req.ExpiresAt, h.enrollmentTokenMaxTTL); err != nil {
		writeEnrollmentError(w, err)
		return
	}
	issued, err := h.enrollments.CreateEnrollmentToken(r.Context(), EnrollmentTokenSpec{
		TokenID: req.TokenID,
		Identity: FollowerIdentity{
			OrgID:       req.OrgID,
			FleetID:     req.FleetID,
			InstanceID:  req.InstanceID,
			Environment: req.Environment,
		},
		Expires: req.ExpiresAt,
		Now:     now,
	})
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createEnrollmentTokenResponse(issued))
}

type listEnrollmentTokensResponse struct {
	Tokens []EnrollmentTokenSummary `json:"tokens"`
	Count  int                      `json:"count"`
}

// handleListEnrollmentTokens serves the admin enrollment-token metadata read
// (GET). The same endpoint serves single-token "status" via the token_id query
// filter. It returns lifecycle metadata only; the store never exposes the token
// bytes or hash.
func (h *Handler) handleListEnrollmentTokens(w http.ResponseWriter, r *http.Request) {
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	query, err := parseEnrollmentTokenListQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	query.Now = h.now()
	tokens, err := h.enrollments.ListEnrollmentTokens(r.Context(), query)
	if err != nil {
		if h.logger != nil {
			h.logger.ErrorContext(r.Context(), "conductor_enrollment_tokens_list_failed",
				slog.String("event", "conductor_enrollment_tokens_list_failed"),
				slog.String("error", err.Error()),
			)
		}
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
		return
	}
	if tokens == nil {
		tokens = []EnrollmentTokenSummary{}
	}
	writeJSON(w, http.StatusOK, listEnrollmentTokensResponse{Tokens: tokens, Count: len(tokens)})
}

// handleRevokeEnrollmentToken serves the admin enrollment-token revoke (DELETE).
// It invalidates a single pending token by token_id and returns the resulting
// metadata-only summary.
func (h *Handler) handleRevokeEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	if err := h.authorizeAdmin(r); err != nil {
		writeError(w, http.StatusForbidden, ErrPublisherForbidden)
		return
	}
	var req revokeEnrollmentTokenRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	summary, err := h.enrollments.RevokeEnrollmentToken(r.Context(), RevokeEnrollmentTokenRequest{
		TokenID: req.TokenID,
		Now:     h.now(),
	})
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

type revokeEnrollmentTokenRequest struct {
	TokenID string `json:"token_id"`
}

func parseEnrollmentTokenListQuery(r *http.Request) (EnrollmentTokenListQuery, error) {
	values := r.URL.Query()
	if err := validateFollowerListValues(values, "token_id", "org_id", "fleet_id", "instance_id", "environment", "limit"); err != nil {
		return EnrollmentTokenListQuery{}, err
	}
	q := EnrollmentTokenListQuery{
		TokenID:     values.Get("token_id"),
		OrgID:       values.Get("org_id"),
		FleetID:     values.Get("fleet_id"),
		InstanceID:  values.Get("instance_id"),
		Environment: values.Get("environment"),
	}
	for _, c := range []struct{ field, value string }{
		{"token_id", q.TokenID},
		{"org_id", q.OrgID},
		{"fleet_id", q.FleetID},
		{"instance_id", q.InstanceID},
		{"environment", q.Environment},
	} {
		if c.value == "" {
			continue
		}
		if err := conductor.ValidateIdentifier(c.field, c.value); err != nil {
			return EnrollmentTokenListQuery{}, err
		}
	}
	if rawLimit := values.Get("limit"); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit <= 0 || limit > maxFollowerListLimit {
			return EnrollmentTokenListQuery{}, fmt.Errorf("invalid limit query parameter: %q (must be 1..%d)", rawLimit, maxFollowerListLimit)
		}
		q.Limit = limit
	}
	return q, nil
}

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
	if h.enrollments == nil {
		writeError(w, http.StatusNotImplemented, ErrEnrollmentStoreRequired)
		return
	}
	var req enrollRequest
	if err := decodeStrictJSON(w, r, h.maxRequestBody, &req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, conductor.ErrPayloadTooLarge)
			return
		}
		writeError(w, http.StatusBadRequest, err)
		return
	}
	pub, err := signing.ParsePublicKey(req.AuditPublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, ErrAuditKeyRequired)
		return
	}
	enrolled, err := h.enrollments.ConsumeEnrollmentToken(r.Context(), ConsumeEnrollmentTokenRequest{
		Token:      req.Token,
		AuditKeyID: req.AuditKeyID,
		AuditKey: conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		},
		Now: h.now(),
	})
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, enrollResponse{
		OrgID:       enrolled.Identity.OrgID,
		FleetID:     enrolled.Identity.FleetID,
		InstanceID:  enrolled.Identity.InstanceID,
		Environment: enrolled.Identity.Environment,
		AuditKeyID:  enrolled.AuditKeyID,
		EnrolledAt:  enrolled.EnrolledAt,
	})
}

func writeEnrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEnrollmentTokenInvalid), errors.Is(err, ErrEnrollmentTokenConsumed), errors.Is(err, ErrEnrollmentTokenExpired):
		writeError(w, http.StatusUnauthorized, ErrEnrollmentTokenInvalid)
	case errors.Is(err, ErrEnrollmentTokenNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrEnrollmentActiveInstance), errors.Is(err, ErrEnrollmentTokenConflict), errors.Is(err, ErrEnrollmentTokenNotPending):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, conductor.ErrInvalidValidityWindow),
		errors.Is(err, conductor.ErrInvalidIdentifier),
		errors.Is(err, ErrFollowerRequired),
		errors.Is(err, ErrAuditKeyRequired):
		writeError(w, http.StatusBadRequest, err)
	default:
		writeError(w, http.StatusInternalServerError, errors.New("internal server error"))
	}
}

func newEnrollmentToken() (string, error) {
	var raw [enrollmentTokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate enrollment token: %w", err)
	}
	return enrollmentTokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func hashEnrollmentToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func followerEnrollmentKey(identity FollowerIdentity) string {
	return identity.OrgID + "\x00" + identity.FleetID + "\x00" + identity.InstanceID + "\x00" + identity.Environment
}
