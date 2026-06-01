// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package svid is a self-contained, vendor-neutral substrate for validating
// X.509-SVIDs offline against a pinned history of trust bundles.
//
// It answers exactly one question, fail-closed: "Is this X.509-SVID a genuine
// credential from a configured trust domain, valid at a given point in time,
// chaining to a bundle we have pinned?" It knows nothing about receipts,
// proof-of-possession, attestation payloads, or fleet membership; those are
// built on top of it by separate packages.
//
// Three properties distinguish this from a plain SPIFFE Workload-API client:
//
//  1. Offline. Validation runs entirely against operator-pinned trust bundles.
//     There is no live SPIRE / Workload-API fetch and no network access.
//  2. Point-in-time. Validity is checked against a caller-supplied time, not
//     "now". A historical credential that was valid when an action occurred
//     still validates for that action time even though it is expired today.
//  3. Bundle history. Trust domains rotate their bundles. An SVID issued under
//     pinned generation N still validates against generation N after the
//     domain rotates to N+1. The pinned history is append-only; validation is
//     read-only and never auto-accepts a new root.
package svid

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unicode"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Failure classes. Callers (e.g. an AARP verifier or Conductor membership
// check) map these to their own result contracts. Compare with errors.Is.
var (
	// ErrMalformedInput covers structurally invalid input: bad PEM, a
	// truncated or non-SVID X.509 certificate, an empty trust bundle, a zero
	// validation time, an empty/invalid trust domain, or a nil history. None
	// of these ever panic.
	ErrMalformedInput = errors.New("svid: malformed input")

	// ErrTrustDomainMismatch means the SVID's own trust domain does not match
	// the trust domain the caller asked it to be validated against.
	ErrTrustDomainMismatch = errors.New("svid: trust domain mismatch")

	// ErrUntrustedChain means the SVID does not chain to the pinned bundle
	// authoritative for the validation time (wrong key, forged or forked root).
	ErrUntrustedChain = errors.New("svid: chain does not validate to a pinned bundle")

	// ErrExpiredAtTime means the SVID (or its chain) is outside its validity
	// window at the requested validation time — either expired or not yet
	// valid relative to that time.
	ErrExpiredAtTime = errors.New("svid: not valid at the requested time")

	// ErrStaleOrForkedBundle means the pinned history does not authoritatively
	// cover the validation time, or a pin attempt diverged from already-pinned
	// history (no silent re-pin, no auto-accepted new root).
	ErrStaleOrForkedBundle = errors.New("svid: bundle diverges from pinned history")
)

// Generation is one pinned trust-bundle generation: a set of X.509 authorities
// that was authoritative for a trust domain during [NotBefore, NotAfter).
// A zero NotAfter marks the current, open-ended generation.
//
// A Generation is trust-domain-agnostic; binding to a domain happens when it is
// added to a TrustBundleHistory.
type Generation struct {
	NotBefore   time.Time
	NotAfter    time.Time
	authorities []*x509.Certificate
}

// NewGeneration builds a generation from parsed X.509 authorities. It rejects
// an empty authority set and an inverted window. A zero notAfter is allowed and
// means "open-ended / current".
func NewGeneration(notBefore, notAfter time.Time, authorities []*x509.Certificate) (Generation, error) {
	if err := validateGenerationWindow(notBefore, notAfter); err != nil {
		return Generation{}, err
	}
	if len(authorities) == 0 {
		return Generation{}, fmt.Errorf("%w: generation has no trust authorities", ErrMalformedInput)
	}
	cp := make([]*x509.Certificate, 0, len(authorities))
	for _, c := range authorities {
		if c == nil {
			return Generation{}, fmt.Errorf("%w: nil authority certificate", ErrMalformedInput)
		}
		if err := validateAuthority(c); err != nil {
			return Generation{}, err
		}
		clone, err := cloneCertificate(c)
		if err != nil {
			return Generation{}, err
		}
		cp = append(cp, clone)
	}
	// Defensive clone so later mutation of the caller's slice or certificate
	// values cannot alter pinned state.
	return Generation{NotBefore: notBefore, NotAfter: notAfter, authorities: cp}, nil
}

// NewGenerationPEM builds a generation from a PEM bundle of one or more
// CERTIFICATE blocks (the common operator-pinned form).
func NewGenerationPEM(notBefore, notAfter time.Time, authoritiesPEM []byte) (Generation, error) {
	certs, err := parseCertChainPEM(authoritiesPEM)
	if err != nil {
		return Generation{}, err
	}
	return NewGeneration(notBefore, notAfter, certs)
}

// pinnedGen is a generation already bound to a trust domain and compiled into a
// go-spiffe bundle for chain verification.
type pinnedGen struct {
	notBefore time.Time
	notAfter  time.Time
	bundle    *x509bundle.Bundle
}

// TrustBundleHistory is an append-only, time-ordered set of pinned bundle
// generations for a single trust domain. It is the unit of pinned trust the
// validator works against. Construction and Pin enforce that the timeline is
// monotonic and non-overlapping; a divergent pin is rejected as a fork.
//
// It is safe for concurrent use: Pin (write) and validation reads are guarded,
// so a fleet operator may rotate a domain's bundle at runtime while validations
// are in flight. The trust domain itself is immutable after construction.
type TrustBundleHistory struct {
	td   spiffeid.TrustDomain
	mu   sync.RWMutex
	gens []pinnedGen
}

// NewTrustBundleHistory binds one or more generations to a trust domain in
// chronological order. trustDomain is a SPIFFE trust domain name (e.g.
// "example.org") — IP literals and malformed names are rejected.
func NewTrustBundleHistory(trustDomain string, gens ...Generation) (*TrustBundleHistory, error) {
	td, err := parseTrustDomain(trustDomain)
	if err != nil {
		return nil, err
	}
	if len(gens) == 0 {
		return nil, fmt.Errorf("%w: trust bundle history needs at least one generation", ErrMalformedInput)
	}
	h := &TrustBundleHistory{td: td}
	for i, g := range gens {
		if err := h.appendGen(g); err != nil {
			return nil, fmt.Errorf("generation %d: %w", i, err)
		}
	}
	return h, nil
}

// Pin appends a new generation to the history. A legitimate forward rotation
// closes the current open-ended generation at the new generation's NotBefore.
// A generation that would rewrite or overlap already-pinned history is rejected
// as a fork (ErrStaleOrForkedBundle) — the history never silently re-pins.
func (h *TrustBundleHistory) Pin(g Generation) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.appendGen(g)
}

// appendGen appends one generation, enforcing the append-only/non-overlap
// invariant. Callers must hold h.mu for writing (Pin does); NewTrustBundleHistory
// calls it during construction before the value is shared.
func (h *TrustBundleHistory) appendGen(g Generation) error {
	// A Generation can only carry authorities via NewGeneration/NewGenerationPEM,
	// which validate authorities. Its exported time fields can still be mutated
	// after construction, so re-check the window at the append boundary.
	if err := validateGenerationWindow(g.NotBefore, g.NotAfter); err != nil {
		return err
	}
	if len(g.authorities) == 0 {
		return fmt.Errorf("%w: generation has no trust authorities", ErrMalformedInput)
	}

	if len(h.gens) > 0 {
		last := &h.gens[len(h.gens)-1]
		// New generation must begin strictly after the previous one began.
		if !g.NotBefore.After(last.notBefore) {
			return fmt.Errorf("%w: generation starts at or before the previous generation", ErrStaleOrForkedBundle)
		}
		if last.notAfter.IsZero() {
			// Previous generation was open-ended: legitimate rotation closes it
			// at the new generation's start.
			last.notAfter = g.NotBefore
		} else if g.NotBefore.Before(last.notAfter) {
			// Previous generation was already closed: a new generation starting
			// before its end would overlap pinned history.
			return fmt.Errorf("%w: generation overlaps a closed generation", ErrStaleOrForkedBundle)
		}
	}

	h.gens = append(h.gens, pinnedGen{
		notBefore: g.NotBefore,
		notAfter:  g.NotAfter,
		bundle:    x509bundle.FromX509Authorities(h.td, g.authorities),
	})
	return nil
}

func validateGenerationWindow(notBefore, notAfter time.Time) error {
	if notBefore.IsZero() {
		return fmt.Errorf("%w: generation notBefore must be set", ErrMalformedInput)
	}
	if !notAfter.IsZero() && !notAfter.After(notBefore) {
		return fmt.Errorf("%w: generation notAfter must be after notBefore", ErrMalformedInput)
	}
	return nil
}

func validateAuthority(c *x509.Certificate) error {
	if !c.IsCA {
		return fmt.Errorf("%w: trust authority certificate is not a CA", ErrMalformedInput)
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: trust authority certificate lacks cert-sign key usage", ErrMalformedInput)
	}
	return nil
}

func cloneCertificate(c *x509.Certificate) (*x509.Certificate, error) {
	if len(c.Raw) == 0 {
		return nil, fmt.Errorf("%w: trust authority certificate has no DER encoding", ErrMalformedInput)
	}
	raw := append([]byte(nil), c.Raw...)
	clone, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: trust authority certificate DER is invalid: %w", ErrMalformedInput, err)
	}
	return clone, nil
}

// TrustDomain returns the trust domain name this history is pinned for.
func (h *TrustBundleHistory) TrustDomain() string {
	return h.td.String()
}

// bundleAt returns the bundle authoritative at t, or false if no pinned
// generation covers t.
func (h *TrustBundleHistory) bundleAt(t time.Time) (*x509bundle.Bundle, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for i := range h.gens {
		g := &h.gens[i]
		if t.Before(g.notBefore) {
			continue
		}
		if g.notAfter.IsZero() || t.Before(g.notAfter) {
			return g.bundle, true
		}
	}
	return nil, false
}

// Options configures a single ValidateSVID call.
type Options struct {
	// TrustDomain is the trust domain the SVID is expected to belong to. It
	// must match History's trust domain and the SVID's own trust domain.
	TrustDomain string
	// History is the pinned trust-bundle history for TrustDomain.
	History *TrustBundleHistory
	// At is the point in time to validate against. It is REQUIRED and must be
	// non-zero: a zero value would silently fall back to the wall clock inside
	// crypto/x509, defeating point-in-time validation of historical credentials.
	At time.Time
}

// Validated is the result of a successful validation.
type Validated struct {
	// SPIFFEID is the canonical SPIFFE ID from the SVID's URI SAN.
	SPIFFEID string
	// Leaf is the parsed leaf certificate (the SVID itself).
	Leaf *x509.Certificate
}

// ValidateSVID validates an X.509-SVID (PEM, leaf first, optional intermediates)
// against opts.History's pinned bundle authoritative at opts.At, for
// opts.TrustDomain. It never reaches the network and never consults the wall
// clock. Every failure returns one of the package's typed error classes and
// never panics.
func ValidateSVID(svidPEM []byte, opts Options) (Validated, error) {
	if opts.At.IsZero() {
		return Validated{}, fmt.Errorf("%w: validation time (At) is required and must be non-zero", ErrMalformedInput)
	}
	if opts.History == nil {
		return Validated{}, fmt.Errorf("%w: pinned trust bundle history is required", ErrMalformedInput)
	}
	wantTD, err := parseTrustDomain(opts.TrustDomain)
	if err != nil {
		return Validated{}, err
	}
	if opts.History.td != wantTD {
		return Validated{}, fmt.Errorf("%w: options trust domain %q does not match history trust domain %q",
			ErrMalformedInput, wantTD.String(), opts.History.td.String())
	}

	certs, err := parseCertChainPEM(svidPEM)
	if err != nil {
		return Validated{}, err
	}
	leaf := certs[0]

	// Extract the SPIFFE ID up front so we can return a precise trust-domain
	// error before doing any chain work. A certificate without exactly one
	// well-formed SPIFFE URI SAN is not an SVID at all.
	id, err := x509svid.IDFromCert(leaf)
	if err != nil {
		return Validated{}, fmt.Errorf("%w: leaf is not an X.509-SVID: %w", ErrMalformedInput, err)
	}
	if id.TrustDomain() != wantTD {
		return Validated{}, fmt.Errorf("%w: SVID trust domain %q, expected %q",
			ErrTrustDomainMismatch, id.TrustDomain().String(), wantTD.String())
	}

	bundle, ok := opts.History.bundleAt(opts.At)
	if !ok {
		return Validated{}, fmt.Errorf("%w: no pinned bundle authoritative at %s", ErrStaleOrForkedBundle, opts.At.UTC().Format(time.RFC3339Nano))
	}

	if _, _, err := x509svid.Verify(certs, bundle, x509svid.WithTime(opts.At)); err != nil {
		return Validated{}, classifyVerifyError(err)
	}

	return Validated{SPIFFEID: id.String(), Leaf: leaf}, nil
}

// classifyVerifyError maps a go-spiffe / crypto/x509 verification failure to a
// typed error class. A validity-window failure (expired or not-yet-valid at the
// requested time) becomes ErrExpiredAtTime; everything else (unknown authority,
// CA-flagged or otherwise malformed leaf, key-usage violations) is treated as
// an untrusted chain.
func classifyVerifyError(err error) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return fmt.Errorf("%w: %w", ErrExpiredAtTime, err)
	}
	return fmt.Errorf("%w: %w", ErrUntrustedChain, err)
}

// parseTrustDomain parses a SPIFFE trust domain name and rejects IP literals.
// SPIFFE-ID §2 requires the trust domain to be a DNS name; go-spiffe's parser
// accepts IP literals, so a numeric host could otherwise be used to impersonate
// a domain. This mirrors internal/envelope's IsValidTrustDomain.
func parseTrustDomain(s string) (spiffeid.TrustDomain, error) {
	td, err := spiffeid.TrustDomainFromString(s)
	if err != nil {
		return spiffeid.TrustDomain{}, fmt.Errorf("%w: invalid trust domain %q: %w", ErrMalformedInput, s, err)
	}
	if net.ParseIP(td.String()) != nil {
		return spiffeid.TrustDomain{}, fmt.Errorf("%w: trust domain must be a DNS name, not an IP address: %q", ErrMalformedInput, s)
	}
	return td, nil
}

// parseCertChainPEM decodes a PEM blob into an ordered certificate chain. The
// input must be CERTIFICATE blocks only, with nothing but whitespace between or
// after them. Any other block type, an unparseable body, trailing non-PEM data,
// or zero certificates is ErrMalformedInput. Strict parsing matters here: an
// operator who appended a second authority that failed to encode must learn the
// bundle is malformed rather than have it silently truncated to what parsed.
func parseCertChainPEM(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: empty SVID PEM", ErrMalformedInput)
	}
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		rest = bytes.TrimLeftFunc(rest, unicode.IsSpace)
		if len(rest) == 0 {
			break
		}
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, fmt.Errorf("%w: leading non-whitespace before PEM block", ErrMalformedInput)
		}
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("%w: malformed PEM block", ErrMalformedInput)
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: unexpected PEM block type %q", ErrMalformedInput, block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedInput, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no certificates in PEM", ErrMalformedInput)
	}
	return certs, nil
}
