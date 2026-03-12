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
	"fmt"
	"io"
	"net/http"
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
}

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
	body, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBody))
	if err != nil {
		s.log.Error().Err(err).Msg("read webhook body")
		http.Error(w, "failed to read body", http.StatusBadRequest)
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

	// Check if this is a subscription event we care about.
	if !isSubscriptionEvent(event.Type) {
		s.log.Debug().
			Str("event_type", event.Type).
			Msg("ignoring non-subscription event")
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
		http.Error(w, `{"status":"error"}`, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"status":"ok"}`)
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
