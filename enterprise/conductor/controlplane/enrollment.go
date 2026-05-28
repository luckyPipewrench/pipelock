//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
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
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	enrollmentStoreFileMode = 0o600
	enrollmentTokenBytes    = 32
	enrollmentTokenPrefix   = "pl_enroll_"
)

var (
	ErrEnrollmentStoreRequired  = errors.New("conductor enrollment store required")
	ErrEnrollmentTokenInvalid   = errors.New("conductor enrollment token invalid")
	ErrEnrollmentTokenConflict  = errors.New("conductor enrollment token conflicts with existing token")
	ErrEnrollmentTokenConsumed  = errors.New("conductor enrollment token consumed")
	ErrEnrollmentTokenExpired   = errors.New("conductor enrollment token expired")
	ErrEnrollmentActiveInstance = errors.New("conductor follower instance already enrolled")
)

type EnrollmentStore interface {
	CreateEnrollmentToken(context.Context, EnrollmentTokenSpec) (IssuedEnrollmentToken, error)
	ConsumeEnrollmentToken(context.Context, ConsumeEnrollmentTokenRequest) (EnrolledFollower, error)
	ResolveEnrolledAuditKey(FollowerIdentity, string) (conductor.SignatureKey, error)
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
	if err := durableWrite(s.path, data, enrollmentStoreFileMode); err != nil {
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
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, http.MethodPost)
		return
	}
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
	issued, err := h.enrollments.CreateEnrollmentToken(r.Context(), EnrollmentTokenSpec{
		TokenID: req.TokenID,
		Identity: FollowerIdentity{
			OrgID:       req.OrgID,
			FleetID:     req.FleetID,
			InstanceID:  req.InstanceID,
			Environment: req.Environment,
		},
		Expires: req.ExpiresAt,
		Now:     h.now(),
	})
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createEnrollmentTokenResponse(issued))
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
	case errors.Is(err, ErrEnrollmentActiveInstance), errors.Is(err, ErrEnrollmentTokenConflict):
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
