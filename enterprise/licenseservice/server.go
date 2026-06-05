//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Package licenseservice implements the Pipelock license service: a standalone
// HTTP server that receives Polar.sh webhooks, maintains subscription and
// entitlement state in SQLite, issues Ed25519-signed license tokens, and
// delivers them via Resend email.
//
// Architecture:
//
//	Polar.sh --webhook--> /webhook/polar --> validate sig --> fetch sub state
//	  --> upsert entitlement --> idempotency check --> mint token --> email
//
// All state lives in a single SQLite database. An append-only JSONL audit
// ledger records every significant event for compliance and debugging.
package licenseservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// Server is the license service HTTP server. It exposes webhook and health
// endpoints and coordinates all subsystems.
type Server struct {
	cfg     *Config
	handler *WebhookHandler
	ledger  *AuditLedger
	log     zerolog.Logger
	mux     *http.ServeMux
	srv     *http.Server

	crlMu         sync.Mutex
	crlCache      []byte
	crlCacheETag  string
	crlCacheUntil time.Time
}

const crlCacheTTL = time.Minute

// NewServer creates a license service server with all dependencies wired.
func NewServer(
	cfg *Config,
	handler *WebhookHandler,
	ledger *AuditLedger,
	log zerolog.Logger,
) *Server {
	s := &Server{
		cfg:     cfg,
		handler: handler,
		ledger:  ledger,
		log:     log,
		mux:     http.NewServeMux(),
	}

	s.mux.HandleFunc("POST /webhook/polar", s.handleWebhook)
	s.mux.HandleFunc(http.MethodGet+" /crl.json", s.handleCRL)
	s.mux.HandleFunc("GET /health", s.handleHealth)

	s.srv = &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second, // 10s: prevent slowloris
		ReadTimeout:       30 * time.Second, // 30s: generous for webhook bodies
		WriteTimeout:      30 * time.Second, // 30s: includes license issuance time
		IdleTimeout:       60 * time.Second, // 60s: standard keepalive
	}

	return s
}

// ListenAndServe starts the HTTP server. Blocks until the server is shut down.
func (s *Server) ListenAndServe() error {
	s.log.Info().
		Str("addr", s.cfg.ListenAddr).
		Msg("license service starting")
	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the server with the given context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// handleWebhook processes incoming Polar webhook events.
//
// Flow:
//  1. Read and cap request body (1 MiB max to prevent memory exhaustion)
//  2. Validate Standard Webhooks signature
//  3. Parse event envelope
//  4. Delegate to WebhookHandler for business logic
//  5. Return 200 on success, 500 on processing failure (so Polar retries;
//     idempotency logic prevents duplicate processing)
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Cap request body to prevent memory exhaustion from oversized payloads.
	const maxWebhookBody = 1 << 20 // 1 MiB: generous for any Polar webhook
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody+1))
	if err != nil {
		s.log.Error().Err(err).Msg("read webhook body")
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxWebhookBody {
		s.log.Warn().Int("bytes_read", len(body)).Msg("webhook body too large")
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Validate webhook signature (Standard Webhooks format).
	msgID := r.Header.Get("Webhook-Id")
	msgTimestamp := r.Header.Get("Webhook-Timestamp")
	sigHeader := r.Header.Get("Webhook-Signature")
	if err := ValidateWebhookSignature(body, msgID, msgTimestamp, sigHeader, s.cfg.PolarWebhookSecret); err != nil {
		s.log.Warn().Err(err).Msg("webhook signature validation failed")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	// Parse event.
	event, err := ParseWebhookEvent(body)
	if err != nil {
		s.log.Error().Err(err).Msg("parse webhook event")
		http.Error(w, "invalid event payload", http.StatusBadRequest)
		return
	}

	// Check if this is an order event (one-time purchases like trials and the
	// Enterprise Eval). order.paid mints, order.refunded/order.updated revoke,
	// order.created remains the legacy trial path. Return 500 on failure so Polar
	// retries; the per-handler webhook-id dedupe prevents duplicate processing.
	if isOrderEvent(event.Type) {
		var err error
		switch event.Type {
		case EventOrderPaid:
			err = s.handler.HandleOrderPaidEvent(r.Context(), event, msgID)
		case EventOrderRefunded, EventOrderUpdated:
			err = s.handler.HandleOrderRefundEvent(r.Context(), event, msgID)
		default: // EventOrderCreated (legacy trial path)
			err = s.handler.HandleOrderEvent(r.Context(), event)
		}
		if err != nil {
			s.log.Error().Err(err).
				Str("event_type", event.Type).
				Msg("order webhook processing error")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{"status":"error"}`)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	// Check if this is a subscription event we care about.
	if !isSubscriptionEvent(event.Type) {
		s.log.Debug().
			Str("event_type", event.Type).
			Msg("ignoring unhandled event type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ignored","event_type":%q}`, event.Type)
		return
	}

	// Process the event. Return 500 on failure so Polar retries.
	// The idempotency logic in HandleEvent prevents duplicate processing.
	if err := s.handler.HandleEvent(r.Context(), event); err != nil {
		s.log.Error().Err(err).
			Str("event_type", event.Type).
			Msg("webhook processing error")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprintf(w, `{"status":"error"}`)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
}

// handleCRL returns the current signed license revocation list.
func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	body, etag, err := s.cachedCRL(r.Context(), time.Now())
	if err != nil {
		s.log.Error().Err(err).Msg("build license CRL")
		http.Error(w, "failed to build CRL", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if ifNoneMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(body); err != nil {
		s.log.Error().Err(err).Msg("write license CRL")
	}
}

func (s *Server) cachedCRL(ctx context.Context, now time.Time) ([]byte, string, error) {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()

	if len(s.crlCache) > 0 && now.Before(s.crlCacheUntil) {
		return s.crlCache, s.crlCacheETag, nil
	}
	crl, err := s.handler.SignedCRL(ctx, now)
	if err != nil {
		return nil, "", err
	}
	body, err := json.Marshal(crl)
	if err != nil {
		return nil, "", fmt.Errorf("marshal license CRL: %w", err)
	}
	body = append(body, '\n')
	sum := sha256.Sum256(body)
	s.crlCache = body
	s.crlCacheETag = `"` + hex.EncodeToString(sum[:]) + `"`
	s.crlCacheUntil = now.Add(crlCacheTTL)
	return s.crlCache, s.crlCacheETag, nil
}

func ifNoneMatch(header, etag string) bool {
	if header == "" || etag == "" {
		return false
	}
	normalizedETag := normalizeETag(etag)
	for candidate := range strings.SplitSeq(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || normalizeETag(candidate) == normalizedETag {
			return true
		}
	}
	return false
}

func normalizeETag(etag string) string {
	etag = strings.TrimSpace(etag)
	etag = strings.TrimPrefix(etag, "W/")
	etag = strings.Trim(etag, `"`)
	return etag
}

// handleHealth returns 200 if the service is running.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"healthy"}`)
}

// isSubscriptionEvent returns true for Polar event types that affect
// subscription/entitlement state.
func isSubscriptionEvent(eventType string) bool {
	switch eventType {
	case EventSubscriptionCreated,
		EventSubscriptionUpdated,
		EventSubscriptionActive,
		EventSubscriptionRevoked,
		EventSubscriptionCanceled:
		return true
	default:
		return false
	}
}

// isOrderEvent returns true for Polar order event types (one-time purchases).
func isOrderEvent(eventType string) bool {
	switch eventType {
	case EventOrderCreated, EventOrderPaid, EventOrderRefunded, EventOrderUpdated:
		return true
	default:
		return false
	}
}
