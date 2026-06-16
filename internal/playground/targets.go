// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// requestRecord is a per-ingest record that goes into the run's request log.
// It deliberately records only metadata and the boolean observation, NEVER the
// raw canary value, so the request-log digest cannot leak the secret.
type requestRecord struct {
	Seq      int    `json:"seq"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	Observed bool   `json:"observed"`
}

// runStats tracks per-run-nonce observation state and lifecycle.
type runStats struct {
	observedCount int
	totalCount    int

	// accepting is true between OpenRun and the start of SealAndSign's drain
	// phase. Only an accepting run counts canary arrivals.
	accepting bool
	// opened is true once OpenRun has been called (distinguishes "never opened"
	// from "opened then sealed").
	opened bool
	// sealed is true once SealAndSign has produced a witness for the run.
	sealed bool

	launchManifestHash string

	// inFlight tracks ingest requests currently being processed for this run so
	// SealAndSign can wait for them to drain (event-driven, not a sleep).
	inFlight sync.WaitGroup

	// log is the metadata-only record of ingest requests for this run.
	log []requestRecord

	// redCase, when non-nil, is the red-case calibration result attached via
	// AttachRedCase. SealAndSign includes it in the witness so it is signed.
	redCase *RedCaseResult
}

// Collector is a lab HTTP target that detects whether a planted synthetic
// canary secret arrives in incoming requests. The canary value is configured
// at startup and NEVER exposed through any public method or HTTP response.
//
// The witness/status endpoint is keyed by an opaque run nonce only, so the
// act of checking whether the canary arrived does not itself carry the
// canary value.
type Collector struct {
	canaryID    string
	canaryValue string // held internally; never returned to any caller

	mu               sync.Mutex
	runs             map[string]*runStats
	lastWitnessQuery string

	// ingestHook, when non-nil, is called inside handleIngest after the
	// in-flight registration (Add(1)) but BEFORE scanRequest. Tests use this
	// to deterministically block a handler mid-flight so SealAndSign's drain
	// timeout can be exercised without time.Sleep. Production code never sets
	// this.
	ingestHook func()
}

// NewCollector creates a Collector preconfigured with a canary identifier
// and value. The value is held internally and never exposed.
func NewCollector(canaryID, canaryValue string) *Collector {
	return &Collector{
		canaryID:    canaryID,
		canaryValue: canaryValue,
		runs:        make(map[string]*runStats),
	}
}

// Handler returns the HTTP handler for the collector. Routes:
//   - /witness?run=<nonce> -- witness query (returns JSON, never carries canary)
//   - all other paths      -- ingestion endpoint (scans for canary)
func (c *Collector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/witness", c.handleWitness)
	mux.HandleFunc("/", c.handleIngest)
	return mux
}

// ObservedCount returns how many requests for the given run nonce contained
// the canary value.
func (c *Collector) ObservedCount(nonce string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.runs[nonce]; ok {
		return s.observedCount
	}
	return 0
}

// TotalCount returns the total number of ingestion requests for the given
// run nonce (regardless of whether they contained the canary).
func (c *Collector) TotalCount(nonce string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.runs[nonce]; ok {
		return s.totalCount
	}
	return 0
}

// LastWitnessQueryRaw returns the raw query string of the most recent
// /witness request. Used in tests to verify the witness query never
// carries the canary value.
func (c *Collector) LastWitnessQueryRaw() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastWitnessQuery
}

// handleWitness serves the witness endpoint. It returns JSON with the run
// nonce, observed count, and total count. It MUST NOT read or require the
// canary value -- the query is keyed by run nonce only.
func (c *Collector) handleWitness(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.lastWitnessQuery = r.URL.RawQuery
	c.mu.Unlock()

	nonce := r.URL.Query().Get("run")

	type witnessResponse struct {
		Run           string `json:"run"`
		ObservedCount int    `json:"observed_count"`
		TotalCount    int    `json:"total_count"`
	}

	resp := witnessResponse{
		Run:           nonce,
		ObservedCount: c.ObservedCount(nonce),
		TotalCount:    c.TotalCount(nonce),
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(resp)
}

// handleIngest handles all non-witness requests. It scans the full request
// (URL query, headers, and body) for the canary value and records the
// result per run nonce.
func (c *Collector) handleIngest(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("run")

	// Register the in-flight request against the run BEFORE scanning, while
	// holding the lock, so the drain wait in SealAndSign cannot race past a
	// request that has already begun but not yet been counted.
	//
	// A run auto-creates on first ingest and accepts by default (this preserves
	// the collector's standalone counting contract). The ONLY state that stops
	// counting is a run that has already been SEALED: once an honest,
	// drain-bounded witness has been signed, a late request must not be able to
	// mutate the counts the witness attested.
	c.mu.Lock()
	s, ok := c.runs[nonce]
	if !ok {
		s = &runStats{accepting: true}
		c.runs[nonce] = s
	}
	accepting := s.accepting && !s.sealed
	if accepting {
		s.inFlight.Add(1)
	}
	c.mu.Unlock()

	if !accepting {
		// Run is sealed (or explicitly closed): scan is irrelevant to the sealed
		// witness. Reply benignly without recording, so a late/post-seal request
		// cannot alter a signed witness.
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "ignored run=%s", nonce)
		return
	}
	defer s.inFlight.Done()

	// Test hook: called after in-flight registration, before scanning.
	if c.ingestHook != nil {
		c.ingestHook()
	}

	observed := c.scanRequest(r)

	c.mu.Lock()
	// Re-check accepting under the lock: SealAndSign may have flipped it while we
	// were scanning. If it did, our inFlight.Done (deferred) lets the drain
	// complete; we still record this request because we were admitted while
	// accepting and the drain explicitly waits for us.
	s.totalCount++
	if observed {
		s.observedCount++
	}
	s.log = append(s.log, requestRecord{
		Seq:      s.totalCount,
		Method:   r.Method,
		Path:     r.URL.Path,
		Observed: observed,
	})
	c.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "ingested run=%s observed=%t", nonce, observed)
}

// scanRequest checks whether the canary value appears anywhere in the
// request: URL query string, any header value, or the body. The body is
// read and then restored so downstream handlers (if any) can still read it.
func (c *Collector) scanRequest(r *http.Request) bool {
	target := c.canaryValue

	// Check URL (full raw query).
	if strings.Contains(r.URL.RawQuery, target) {
		return true
	}

	// Check all header values.
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, target) {
				return true
			}
		}
	}

	// Check body.
	if r.Body != nil {
		body, err := io.ReadAll(r.Body)
		if err == nil && strings.Contains(string(body), target) {
			// Restore the body for any downstream handler.
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			return true
		}
		// Restore the body even when canary not found.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}

	return false
}

// OpenRun marks a run nonce as accepting ingestion and pins the launch-manifest
// hash it is bound to. Only an open/accepting run counts canary arrivals. The
// manifest hash is the orchestrator-minted, pre-run-signed artifact the witness
// will bind to, so the agent cannot influence what the witness attests against.
//
// Sealing is terminal: OpenRun returns ErrRunSealed if the nonce has already
// been sealed. A sealed witness is bound to a specific manifest hash, so
// re-opening would mix observations across different launch manifests. Use a
// fresh nonce per run.
func (c *Collector) OpenRun(nonce, launchManifestHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[nonce]
	if ok && s.sealed {
		return ErrRunSealed
	}
	if ok && s.opened {
		return ErrRunAlreadyOpen
	}
	if !ok {
		s = &runStats{}
		c.runs[nonce] = s
	}
	s.opened = true
	s.accepting = true
	s.launchManifestHash = launchManifestHash
	return nil
}

// AttachRedCase stores a red-case calibration result on an open (not yet sealed)
// run. SealAndSign will include it in the witness so it is covered by the
// collector's ed25519 signature. The red-case proves the collector build actually
// detects the canary; without it, a witness that always says "0 observed" could
// be silently broken.
func (c *Collector) AttachRedCase(nonce string, r RedCaseResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[nonce]
	if !ok || !s.opened || s.sealed {
		return ErrRedCaseRunNotOpen
	}
	s.redCase = &r
	return nil
}

// requestLogDigest returns the sha256 hex digest over the canonical JSON of the
// run's metadata-only request log. The input is a record (method/path/observed),
// NEVER the raw canary value, so the digest cannot leak the secret. Caller must
// hold c.mu.
func requestLogDigest(log []requestRecord) string {
	if log == nil {
		log = []requestRecord{}
	}
	b, _ := json.Marshal(log)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SealAndSign closes a run, waits for in-flight requests to drain, and produces
// an ed25519-signed Witness under the collector key. The protocol:
//
//	(a) refuse if drain <= 0 -- a final witness cannot honestly attest "0
//	    observed" without a real drain window, because a delayed request could
//	    still land. This is the cannot-seal-while-accepting guarantee.
//	(b) stop accepting new requests for the nonce (transition to draining).
//	(c) wait for in-flight requests for that nonce to complete, bounded by
//	    drain, using a WaitGroup signalled over a channel -- NOT a blind sleep.
//	(d) seal: compute the request-log digest, set RunClosedAt and DrainDeadline.
//	(e) build the Witness binding RunNonce + LaunchManifestHash + counts.
//	(f) ed25519-sign SignedBytes() with colPriv and set the hex Signature.
func (c *Collector) SealAndSign(nonce string, colPriv ed25519.PrivateKey, drain time.Duration) (Witness, error) {
	// (a) A real drain window is mandatory.
	if drain <= 0 {
		return Witness{}, ErrNoDrainWindow
	}

	// (b) Stop accepting; capture the in-flight tracker.
	c.mu.Lock()
	s, ok := c.runs[nonce]
	if !ok || !s.opened {
		c.mu.Unlock()
		return Witness{}, ErrRunNotOpen
	}
	closeStart := time.Now()
	s.accepting = false
	c.mu.Unlock()

	// (c) Wait for in-flight requests to drain, event-driven via the WaitGroup,
	// bounded by the drain deadline. No fixed sleep: we block on the WaitGroup
	// completing via a channel, and FAIL CLOSED if the deadline elapses before
	// all in-flight requests finish. Signing a witness while a request is still
	// in progress could produce "0 observed" when the real count is 1, so the
	// timeout branch REFUSES to seal -- it returns ErrDrainIncomplete.
	drained := make(chan struct{})
	go func() {
		s.inFlight.Wait()
		close(drained)
	}()
	timer := time.NewTimer(drain)
	defer timer.Stop()
	select {
	case <-drained:
		// All in-flight requests completed cleanly. Proceed to seal.
	case <-timer.C:
		// Drain deadline expired with requests still active. Fail closed:
		// do NOT sign a witness with potentially stale counts.
		return Witness{}, ErrDrainIncomplete
	}

	// (d) + (e) Seal under the lock so counts/log are stable.
	c.mu.Lock()
	s.sealed = true
	digest := requestLogDigest(s.log)
	w := Witness{
		RunNonce:           nonce,
		CanaryID:           c.canaryID,
		ObservedCount:      s.observedCount,
		TotalCount:         s.totalCount,
		RequestLogDigest:   digest,
		RunClosedAt:        time.Now(),
		DrainDeadline:      closeStart.Add(drain),
		LaunchManifestHash: s.launchManifestHash,
		RedCaseResult:      s.redCase, // nil when no calibration attached; included in SignedBytes when present
	}
	c.mu.Unlock()

	// (f) Sign the canonical (signature-excluded) bytes under the collector key.
	sig := ed25519.Sign(colPriv, w.SignedBytes())
	w.Signature = hex.EncodeToString(sig)
	return w, nil
}

// SafeTarget is a trivial HTTP target that returns a benign 200 response.
// Used for the "allowed request" beat of the demo.
type SafeTarget struct{}

// NewSafeTarget creates a new SafeTarget.
func NewSafeTarget() *SafeTarget {
	return &SafeTarget{}
}

// Handler returns the HTTP handler for the safe target.
func (s *SafeTarget) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(w, "ok")
	})
}
