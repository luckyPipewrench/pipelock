//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Self-serve resend lets a customer who lost their license email ask for it
// again. The caller is unauthenticated and supplies only an email address, so
// the design keeps every property of the original delivery channel:
//
//   - The token goes only to the address already on record for an active,
//     unexpired, unrevoked license. Typing someone else's address sends that
//     person their own license and nothing to the caller.
//   - The existing deterministic token is re-sent. Nothing is minted and no
//     expiry moves.
//   - The HTTP response is identical and immediate whether or not a license
//     exists. Lookup and delivery run on a background worker, so neither the
//     body nor the timing says whether an address belongs to a customer.
//   - Admitted sends are rate limited per address and globally in the
//     database, so a restart does not reset the limits and the endpoint cannot
//     be turned into a mail cannon against customers.
const (
	// resendAddressInterval is the minimum spacing between two sends to one
	// address. Long enough to stop a refresh loop, short enough that a customer
	// whose first email went to spam can try again the same session.
	resendAddressInterval = 15 * time.Minute
	// resendAddressDailyMax bounds sends to one address per resendWindow.
	resendAddressDailyMax = 3
	// resendWindow is the longest limiter window and the row retention period.
	resendWindow = 24 * time.Hour
	// resendGlobalHourlyMax bounds admitted sends across all addresses per hour.
	// It counts emails, not requests. The customer base is small; a real
	// recovery burst stays far below this.
	resendGlobalHourlyMax = 60
	// resendMaxLicensesPerRequest bounds how many licenses one request
	// re-sends, so a single admission cannot fan out without limit.
	resendMaxLicensesPerRequest = 10

	// resendQueueSize bounds pending requests. When full, the endpoint
	// answers 503, which depends only on load and never on the address.
	resendQueueSize = 32
	// maxResendBody caps the request body. An email address fits in far less.
	maxResendBody = 4 << 10
	// resendJobTimeout bounds one lookup plus delivery.
	resendJobTimeout = 60 * time.Second

	// AuditLicenseResendRequested is written before a license is re-sent, and
	// the send is refused if it cannot be written, so every delivered resend
	// is attributable. AuditLicenseResent records completion and
	// AuditLicenseResendThrottled a matching request the limiter refused.
	AuditLicenseResendRequested = "license_resend_requested"
	AuditLicenseResent          = "license_resent"
	AuditLicenseResendThrottled = "license_resend_throttled"

	resendReasonSelfServe = "self-serve resend"
	resendAcceptedMessage = "If that address has an active Pipelock license, we sent it there again. Check your inbox and spam folder."
)

// ErrResendThrottled means the per-address or global limiter refused a send.
var ErrResendThrottled = errors.New("license resend rate limited")

func resendEmailKey(normalizedEmail string) string {
	sum := sha256.Sum256([]byte(normalizedEmail))
	return hex.EncodeToString(sum[:])
}

// ResendableSubscriptionIDsForEmail returns, least recently delivered first,
// the entitlements whose stored
// customer address normalizes to normalizedEmail and whose last license is
// active and unexpired at now. Stored addresses are compared after
// normalization, the same way the trial-slot count compares them.
func (e *EntitlementDB) ResendableSubscriptionIDsForEmail(ctx context.Context, normalizedEmail string, now time.Time) ([]string, error) {
	const query = `
	SELECT subscription_id, customer_email FROM entitlements
	WHERE status = ? AND last_license_id != '' AND last_license_expires_at > ?
	ORDER BY last_delivery_attempt_at IS NOT NULL, last_delivery_attempt_at ASC, subscription_id ASC
	`
	rows, err := e.db.QueryContext(ctx, query, statusActive, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("list resendable entitlements: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var subID, stored string
		if err := rows.Scan(&subID, &stored); err != nil {
			return nil, fmt.Errorf("scan resendable entitlement: %w", err)
		}
		canonical, nerr := NormalizeEmail(stored)
		if nerr != nil {
			continue
		}
		if canonical == normalizedEmail {
			ids = append(ids, subID)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate resendable entitlements: %w", err)
	}
	return ids, nil
}

// AdmitLicenseResend records one request to normalizedEmail that will send
// sends emails, if the per-address request limits and the global email budget
// allow it, and returns ErrResendThrottled otherwise. The check and the insert
// share one transaction so two processes on the same database cannot both
// admit the last available send.
func (e *EntitlementDB) AdmitLicenseResend(ctx context.Context, normalizedEmail string, sends int, now time.Time) (err error) {
	// Bounding sends by the budget also keeps global+sends from overflowing.
	if sends < 1 || sends > resendGlobalHourlyMax {
		return fmt.Errorf("resend admission needs 1 to %d sends, got %d", resendGlobalHourlyMax, sends)
	}
	now = now.UTC()
	key := resendEmailKey(normalizedEmail)
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin resend admission: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, `DELETE FROM license_resend_requests WHERE requested_at <= ?`, now.Add(-resendWindow)); err != nil {
		return fmt.Errorf("prune resend requests: %w", err)
	}
	var global int
	if err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(sends), 0) FROM license_resend_requests WHERE requested_at > ?`, now.Add(-time.Hour)).Scan(&global); err != nil {
		return fmt.Errorf("count global resends: %w", err)
	}
	if global+sends > resendGlobalHourlyMax {
		err = ErrResendThrottled
		return err
	}
	var daily, recent int
	if err = tx.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN requested_at > ? THEN 1 ELSE 0 END), 0)
		 FROM license_resend_requests WHERE email_sha256 = ?`,
		now.Add(-resendAddressInterval), key).Scan(&daily, &recent); err != nil {
		return fmt.Errorf("count address resends: %w", err)
	}
	if daily >= resendAddressDailyMax || recent > 0 {
		err = ErrResendThrottled
		return err
	}
	if _, err = tx.ExecContext(ctx,
		`INSERT INTO license_resend_requests (email_sha256, requested_at, sends) VALUES (?, ?, ?)`, key, now, sends); err != nil {
		return fmt.Errorf("record resend request: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit resend admission: %w", err)
	}
	return nil
}

// ResendLicensesForEmail re-sends every active license whose address on record
// matches rawEmail, to that address, and returns how many were sent. An
// address that does not parse or has no license is not an error: the caller
// must not be able to tell the cases apart, and there is nothing to do.
func (h *WebhookHandler) ResendLicensesForEmail(ctx context.Context, rawEmail string, now time.Time) (int, error) {
	normalized, err := NormalizeEmail(rawEmail)
	if err != nil {
		return 0, nil
	}
	// The lookup runs before the locks. Anyone can reach this with any
	// address, and the limiter only applies after a match, so holding the
	// locks here would let unmatched requests keep webhook processing waiting.
	// resendOneLicense re-checks each reloaded row under the locks.
	ids, err := h.db.ResendableSubscriptionIDsForEmail(ctx, normalized, now)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	if len(ids) > resendMaxLicensesPerRequest {
		ids = ids[:resendMaxLicensesPerRequest]
	}
	sent := 0
	var prepared []*preparedResend
	var firstErr error
	err = h.db.withTrialSupportLock(ctx, func() error {
		h.processMu.Lock()
		defer h.processMu.Unlock()

		if err := h.db.AdmitLicenseResend(ctx, normalized, len(ids), now); err != nil {
			if errors.Is(err, ErrResendThrottled) {
				if lerr := h.ledger.Log(AuditEntry{
					Event:         AuditLicenseResendThrottled,
					CustomerEmail: normalized,
					Detail:        resendReasonSelfServe,
				}); lerr != nil {
					h.log.Error().Err(lerr).Msg("record throttled license resend")
				}
			}
			return err
		}
		revoked, err := h.revokedLicenseIDs(ctx)
		if err != nil {
			return err
		}
		for _, subID := range ids {
			p, err := h.prepareResend(ctx, subID, normalized, revoked, now)
			if err != nil {
				h.log.Error().Err(err).Str("subscription_id", subID).Msg("self-serve license resend")
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if p != nil {
				prepared = append(prepared, p)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	// Delivery runs after the locks are released: a slow mail provider must
	// not hold up webhook processing. Each token was checked and its request
	// audited under the locks. A webhook that lands in between can at most
	// mean an already-verified address receives a token the revocation list
	// then disables; it can never redirect a token to another address.
	for _, p := range prepared {
		if err := h.deliverPreparedResend(ctx, p, now); err != nil {
			h.log.Error().Err(err).Str("subscription_id", p.ent.SubscriptionID).Msg("self-serve license resend")
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		sent++
	}
	return sent, firstErr
}

func (h *WebhookHandler) revokedLicenseIDs(ctx context.Context) (map[string]bool, error) {
	records, err := h.db.ListLicenseRevocations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list license revocations: %w", err)
	}
	revoked := make(map[string]bool, len(records))
	for _, record := range records {
		revoked[record.LicenseID] = true
	}
	return revoked, nil
}

// preparedResend is one license checked and audited under the locks, ready to
// deliver after they are released.
type preparedResend struct {
	ent   *Entitlement
	token string
}

// resendOneLicense prepares and delivers one license. The self-serve path
// calls the two halves separately so delivery runs outside the locks.
func (h *WebhookHandler) resendOneLicense(ctx context.Context, subID, normalized string, revoked map[string]bool, now time.Time) (bool, error) {
	p, err := h.prepareResend(ctx, subID, normalized, revoked, now)
	if err != nil || p == nil {
		return false, err
	}
	if err := h.deliverPreparedResend(ctx, p, now); err != nil {
		return false, err
	}
	return true, nil
}

// prepareResend re-checks one entitlement, records the request in the audit
// ledger and rebuilds its existing token. It returns nil without error when
// the entitlement stopped qualifying between the lookup and now.
func (h *WebhookHandler) prepareResend(ctx context.Context, subID, normalized string, revoked map[string]bool, now time.Time) (*preparedResend, error) {
	ent, err := h.db.GetBySubscriptionID(ctx, subID)
	if err != nil {
		return nil, fmt.Errorf("reload entitlement for resend: %w", err)
	}
	if ent == nil || ent.Status != statusActive || ent.LastLicenseID == "" || revoked[ent.LastLicenseID] {
		return nil, nil
	}
	if ent.LastLicenseExpiresAt == nil || !now.Before(*ent.LastLicenseExpiresAt) {
		return nil, nil
	}
	// The address is compared again because the entitlement row may have been
	// rewritten by a webhook between the lookup and this reload.
	if canonical, nerr := NormalizeEmail(ent.CustomerEmail); nerr != nil || canonical != normalized {
		return nil, nil
	}
	// Only a token whose issuance was durably recorded is re-sent, the same
	// requirement the operator resend enforces.
	issuances, err := h.db.ListUnexpiredLicenseIssuances(ctx, subID, now)
	if err != nil {
		return nil, fmt.Errorf("verify persisted issuance: %w", err)
	}
	matched := false
	for _, issuance := range issuances {
		if issuance.LicenseID == ent.LastLicenseID {
			matched = true
			break
		}
	}
	if !matched {
		return nil, nil
	}
	if err := h.ledger.Log(AuditEntry{
		Event:          AuditLicenseResendRequested,
		SubscriptionID: ent.SubscriptionID,
		CustomerEmail:  ent.CustomerEmail,
		LicenseID:      ent.LastLicenseID,
		Tier:           ent.LastLicenseTier,
		ExpiresAt:      formatAuditExpiry(ent.LastLicenseExpiresAt),
		Detail:         resendReasonSelfServe,
	}); err != nil {
		return nil, fmt.Errorf("record license resend request: %w", err)
	}
	token, err := h.regenerateToken(ent)
	if err != nil {
		return nil, err
	}
	return &preparedResend{ent: ent, token: token}, nil
}

// deliverPreparedResend sends a prepared license and confirms the delivery.
func (h *WebhookHandler) deliverPreparedResend(ctx context.Context, p *preparedResend, now time.Time) error {
	var err error
	if p.ent.Tier == tierEnterpriseEval {
		err = h.deliverEvalToken(ctx, p.ent, p.token)
	} else {
		err = h.deliverLicenseEmail(ctx, p.ent, p.token, p.ent.LastLicenseTier, now)
	}
	if err != nil {
		return fmt.Errorf("deliver license: %w", err)
	}
	updated, err := h.db.GetBySubscriptionID(ctx, p.ent.SubscriptionID)
	if err != nil {
		return fmt.Errorf("confirm delivery status: %w", err)
	}
	if updated == nil || updated.LastDeliveryStatus != "sent" {
		return fmt.Errorf("license %s email delivery failed", p.ent.LastLicenseID)
	}
	if err := h.ledger.Log(AuditEntry{
		Event:          AuditLicenseResent,
		SubscriptionID: p.ent.SubscriptionID,
		CustomerEmail:  p.ent.CustomerEmail,
		LicenseID:      p.ent.LastLicenseID,
		Tier:           p.ent.LastLicenseTier,
		ExpiresAt:      formatAuditExpiry(p.ent.LastLicenseExpiresAt),
		Detail:         resendReasonSelfServe,
	}); err != nil {
		// The request entry above already makes this resend attributable.
		h.log.Error().Err(err).Str("subscription_id", p.ent.SubscriptionID).Msg("record license resend completion")
	}
	return nil
}

// resendWorker runs self-serve resend jobs off the request path.
type resendWorker struct {
	queue  chan string
	stop   chan struct{}
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once

	// admitMu orders enqueueing against shutdown: handlers enqueue under the
	// read lock, and stop sets closed under the write lock before the worker
	// is told to drain, so nothing is accepted after the final drain.
	admitMu sync.RWMutex
	closed  bool
}

// enqueue reports whether email was accepted for processing.
func (w *resendWorker) enqueue(email string) bool {
	w.admitMu.RLock()
	defer w.admitMu.RUnlock()
	if w.closed {
		return false
	}
	select {
	case w.queue <- email:
		return true
	default:
		return false
	}
}

func (s *Server) startResendWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	w := &resendWorker{
		queue:  make(chan string, resendQueueSize),
		stop:   make(chan struct{}),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	s.resend = w
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				// Finish the requests already accepted before exiting.
				for {
					select {
					case email := <-w.queue:
						s.runResendJob(ctx, email)
					default:
						return
					}
				}
			case email := <-w.queue:
				s.runResendJob(ctx, email)
			}
		}
	}()
}

func (s *Server) runResendJob(parent context.Context, email string) {
	ctx, cancel := context.WithTimeout(parent, resendJobTimeout)
	defer cancel()
	sent, err := s.handler.ResendLicensesForEmail(ctx, email, s.now())
	if err != nil && !errors.Is(err, ErrResendThrottled) {
		s.log.Error().Err(err).Msg("self-serve license resend failed")
		return
	}
	s.log.Info().Int("sent", sent).Bool("throttled", errors.Is(err, ErrResendThrottled)).Msg("self-serve license resend processed")
}

// stopResendWorker drains queued requests until ctx ends. At the deadline it
// cancels the running job and returns without waiting for it: a job can be
// blocked on a lock that does not observe cancellation, and shutdown must not
// outlive its deadline for it. Call it after the HTTP server stops accepting
// requests.
func (s *Server) stopResendWorker(ctx context.Context) {
	if s.resend == nil {
		return
	}
	s.resend.once.Do(func() {
		s.resend.admitMu.Lock()
		s.resend.closed = true
		s.resend.admitMu.Unlock()
		close(s.resend.stop)
		select {
		case <-s.resend.done:
		case <-ctx.Done():
			s.log.Warn().Int("queued", len(s.resend.queue)).Msg("self-serve resend worker still busy at shutdown deadline")
		}
		s.resend.cancel()
	})
}

// Per-client limits run before a request is queued or looked up, so an
// anonymous caller cannot fill the queue with lookups for addresses that
// match nothing. They depend only on the caller, never on the address.
const (
	// resendClientWindow and resendClientMax allow a few retries from one
	// caller, far more than a customer recovering a license needs.
	resendClientWindow = 15 * time.Minute
	resendClientMax    = 5
	// resendClientTableMax bounds the tracked callers. When it is full and no
	// entry has expired, new callers share one overflow allowance instead of
	// being tracked, so the table cannot grow without limit and filling it
	// cannot lock every new caller out.
	resendClientTableMax = 10000
	// resendOverflowMax is the shared allowance per window for callers that
	// arrive while the table is full.
	resendOverflowMax = 60
)

type resendClientWindowState struct {
	start time.Time
	count int
}

type resendClientLimiter struct {
	mu       sync.Mutex
	clients  map[string]*resendClientWindowState
	overflow resendClientWindowState
	// nextExpiry is the earliest time any tracked window can expire. A full
	// table is swept only once it passes, so new callers do not each pay for
	// a scan of every entry.
	nextExpiry time.Time
}

func newResendClientLimiter() *resendClientLimiter {
	return &resendClientLimiter{clients: make(map[string]*resendClientWindowState)}
}

// allow reports whether client may submit another request at now.
func (l *resendClientLimiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.clients[client]; ok {
		if now.Sub(st.start) >= resendClientWindow {
			st.start, st.count = now, 0
		}
		if st.count >= resendClientMax {
			return false
		}
		st.count++
		return true
	}
	if len(l.clients) >= resendClientTableMax && !now.Before(l.nextExpiry) {
		l.nextExpiry = time.Time{}
		for key, st := range l.clients {
			if now.Sub(st.start) >= resendClientWindow {
				delete(l.clients, key)
				continue
			}
			if exp := st.start.Add(resendClientWindow); l.nextExpiry.IsZero() || exp.Before(l.nextExpiry) {
				l.nextExpiry = exp
			}
		}
	}
	if len(l.clients) >= resendClientTableMax {
		if now.Sub(l.overflow.start) >= resendClientWindow {
			l.overflow.start, l.overflow.count = now, 0
		}
		if l.overflow.count >= resendOverflowMax {
			return false
		}
		l.overflow.count++
		return true
	}
	l.clients[client] = &resendClientWindowState{start: now, count: 1}
	if exp := now.Add(resendClientWindow); l.nextExpiry.IsZero() || exp.Before(l.nextExpiry) {
		l.nextExpiry = exp
	}
	return true
}

// resendClientAddress identifies the caller for the per-client limit.
func (s *Server) resendClientAddress(r *http.Request) string {
	if h := s.cfg.SelfServeResendClientIPHeader; h != "" {
		// The ingress appends; the caller controls anything before it,
		// including earlier header lines, so take the very last value.
		if values := r.Header.Values(h); len(values) > 0 {
			parts := strings.Split(values[len(values)-1], ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// handleLicenseResend accepts a JSON body {"email": "..."} or an HTML form
// field "email". Every request that can be read gets the same response, and
// the work happens on the background worker.
func (s *Server) handleLicenseResend(w http.ResponseWriter, r *http.Request) {
	if !s.clients.allow(s.resendClientAddress(r), s.now()) {
		w.Header().Set("Retry-After", strconv.Itoa(int(resendClientWindow/time.Second)))
		http.Error(w, "too many requests, try again later", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxResendBody+1))
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	if len(body) > maxResendBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	isForm := mediaType == "application/x-www-form-urlencoded"
	var email string
	switch {
	case isForm:
		values, err := url.ParseQuery(string(body))
		if err != nil {
			http.Error(w, "invalid form body", http.StatusBadRequest)
			return
		}
		email = values.Get("email")
	case mediaType == "application/json":
		var req struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		email = req.Email
	default:
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}

	if strings.TrimSpace(email) != "" {
		if !s.resend.enqueue(email) {
			// Busy is a statement about load or shutdown, the same for every
			// address.
			s.log.Warn().Msg("self-serve resend queue full or closed; request refused")
			w.Header().Set("Retry-After", "60")
			http.Error(w, "busy, try again shortly", http.StatusServiceUnavailable)
			return
		}
	}

	if isForm && s.cfg.SelfServeResendReturnURL != "" {
		http.Redirect(w, r, s.cfg.SelfServeResendReturnURL, http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if isForm {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, resendAcceptedMessage+"\n")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "message": resendAcceptedMessage})
}
