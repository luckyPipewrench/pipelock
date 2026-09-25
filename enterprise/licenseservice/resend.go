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
	"net/http"
	"net/url"
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
	// The customer base is small; a real recovery burst stays far below this.
	resendGlobalHourlyMax = 60

	// resendQueueSize bounds pending requests. When full, new requests are
	// dropped and still receive the same accepted response.
	resendQueueSize = 32
	// maxResendBody caps the request body. An email address fits in far less.
	maxResendBody = 4 << 10
	// resendJobTimeout bounds one lookup plus delivery.
	resendJobTimeout = 60 * time.Second

	// AuditLicenseResent records a self-serve resend delivered to the address
	// on record. AuditLicenseResendThrottled records a matching request the
	// limiter refused.
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

// ResendableSubscriptionIDsForEmail returns the entitlements whose stored
// customer address normalizes to normalizedEmail and whose last license is
// active and unexpired at now. Stored addresses are compared after
// normalization, the same way the trial-slot count compares them.
func (e *EntitlementDB) ResendableSubscriptionIDsForEmail(ctx context.Context, normalizedEmail string, now time.Time) ([]string, error) {
	const query = `
	SELECT subscription_id, customer_email FROM entitlements
	WHERE status = ? AND last_license_id != '' AND last_license_expires_at > ?
	ORDER BY subscription_id ASC
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

// AdmitLicenseResend records one send to normalizedEmail if the per-address
// and global limits allow it, and returns ErrResendThrottled otherwise. The
// check and the insert share one transaction so two processes on the same
// database cannot both admit the last available send.
func (e *EntitlementDB) AdmitLicenseResend(ctx context.Context, normalizedEmail string, now time.Time) (err error) {
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
		`SELECT COUNT(*) FROM license_resend_requests WHERE requested_at > ?`, now.Add(-time.Hour)).Scan(&global); err != nil {
		return fmt.Errorf("count global resends: %w", err)
	}
	if global >= resendGlobalHourlyMax {
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
		`INSERT INTO license_resend_requests (email_sha256, requested_at) VALUES (?, ?)`, key, now); err != nil {
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
	sent := 0
	err = h.db.withTrialSupportLock(ctx, func() error {
		h.processMu.Lock()
		defer h.processMu.Unlock()

		if err := h.db.AdmitLicenseResend(ctx, normalized, now); err != nil {
			if errors.Is(err, ErrResendThrottled) {
				_ = h.ledger.Log(AuditEntry{
					Event:         AuditLicenseResendThrottled,
					CustomerEmail: normalized,
					Detail:        resendReasonSelfServe,
				})
			}
			return err
		}
		revoked, err := h.revokedLicenseIDs(ctx)
		if err != nil {
			return err
		}
		var firstErr error
		for _, subID := range ids {
			ok, err := h.resendOneLicense(ctx, subID, normalized, revoked, now)
			if err != nil {
				h.log.Error().Err(err).Str("subscription_id", subID).Msg("self-serve license resend")
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if ok {
				sent++
			}
		}
		return firstErr
	})
	return sent, err
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

// resendOneLicense re-checks one entitlement under the lock and delivers its
// existing token. It reports false without error when the entitlement stopped
// qualifying between the lookup and now.
func (h *WebhookHandler) resendOneLicense(ctx context.Context, subID, normalized string, revoked map[string]bool, now time.Time) (bool, error) {
	ent, err := h.db.GetBySubscriptionID(ctx, subID)
	if err != nil {
		return false, fmt.Errorf("reload entitlement for resend: %w", err)
	}
	if ent == nil || ent.Status != statusActive || ent.LastLicenseID == "" || revoked[ent.LastLicenseID] {
		return false, nil
	}
	if ent.LastLicenseExpiresAt == nil || !now.Before(*ent.LastLicenseExpiresAt) {
		return false, nil
	}
	// The address is compared again because the entitlement row may have been
	// rewritten by a webhook between the lookup and this reload.
	if canonical, nerr := NormalizeEmail(ent.CustomerEmail); nerr != nil || canonical != normalized {
		return false, nil
	}
	// Only a token whose issuance was durably recorded is re-sent, the same
	// requirement the operator resend enforces.
	issuances, err := h.db.ListUnexpiredLicenseIssuances(ctx, subID, now)
	if err != nil {
		return false, fmt.Errorf("verify persisted issuance: %w", err)
	}
	matched := false
	for _, issuance := range issuances {
		if issuance.LicenseID == ent.LastLicenseID {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}
	token, err := h.regenerateToken(ent)
	if err != nil {
		return false, err
	}
	if ent.Tier == tierEnterpriseEval {
		err = h.deliverEvalToken(ctx, ent, token)
	} else {
		err = h.deliverLicenseEmail(ctx, ent, token, ent.LastLicenseTier, now)
	}
	if err != nil {
		return false, fmt.Errorf("deliver license: %w", err)
	}
	updated, err := h.db.GetBySubscriptionID(ctx, subID)
	if err != nil {
		return false, fmt.Errorf("confirm delivery status: %w", err)
	}
	if updated == nil || updated.LastDeliveryStatus != "sent" {
		return false, fmt.Errorf("license %s email delivery failed", ent.LastLicenseID)
	}
	if err := h.ledger.Log(AuditEntry{
		Event:          AuditLicenseResent,
		SubscriptionID: ent.SubscriptionID,
		CustomerEmail:  ent.CustomerEmail,
		LicenseID:      ent.LastLicenseID,
		Tier:           ent.LastLicenseTier,
		ExpiresAt:      formatAuditExpiry(ent.LastLicenseExpiresAt),
		Detail:         resendReasonSelfServe,
	}); err != nil {
		h.log.Error().Err(err).Str("subscription_id", ent.SubscriptionID).Msg("record license resend")
	}
	return true, nil
}

// resendWorker runs self-serve resend jobs off the request path.
type resendWorker struct {
	queue  chan string
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func (s *Server) startResendWorker() {
	ctx, cancel := context.WithCancel(context.Background())
	w := &resendWorker{
		queue:  make(chan string, resendQueueSize),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	s.resend = w
	go func() {
		defer close(w.done)
		for {
			select {
			case <-ctx.Done():
				return
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

func (s *Server) stopResendWorker() {
	if s.resend == nil {
		return
	}
	s.resend.once.Do(func() {
		s.resend.cancel()
		<-s.resend.done
	})
}

// handleLicenseResend accepts a JSON body {"email": "..."} or an HTML form
// field "email". Every request that can be read gets the same response, and
// the work happens on the background worker.
func (s *Server) handleLicenseResend(w http.ResponseWriter, r *http.Request) {
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
		select {
		case s.resend.queue <- email:
		default:
			s.log.Warn().Msg("self-serve resend queue full; request dropped")
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
