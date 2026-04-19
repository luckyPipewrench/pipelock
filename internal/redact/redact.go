// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import "fmt"

// Class identifies a semantic class for a redacted value.
// Placeholders preserve the class so the upstream model retains type
// information ("<pl:aws-access-key:1>" rather than an opaque token).
type Class string

// Standard redaction classes. Callers may use any string. The first block is
// the built-in matcher surface shipped with v1. The second block reserves
// stable class labels for future profiles that are not matched by the v1
// built-in regex registry yet.
const (
	ClassIPv4          Class = "ipv4"
	ClassIPv6          Class = "ipv6"
	ClassCIDR          Class = "cidr"
	ClassFQDN          Class = "fqdn"
	ClassEmail         Class = "email"
	ClassAWSAccessKey  Class = "aws-access-key"
	ClassGoogleAPIKey  Class = "google-api-key"
	ClassGitHubToken   Class = "github-token"
	ClassSlackToken    Class = "slack-token"
	ClassJWT           Class = "jwt"
	ClassHashMD5       Class = "hash-md5"
	ClassHashSHA1      Class = "hash-sha1"
	ClassHashSHA256    Class = "hash-sha256"
	ClassHashSHA512    Class = "hash-sha512"
	ClassMAC           Class = "mac"
	ClassSSN           Class = "ssn"
	ClassCreditCard    Class = "credit-card"
	ClassSSHPrivateKey Class = "ssh-private-key"
	ClassADUser        Class = "ad-user"
)

// Reserved class labels for future profiles or operator-defined use.
const (
	ClassAWSSecretKey Class = "aws-secret-key"
	ClassBearer       Class = "bearer"
	ClassHashNTLM     Class = "hash-ntlm"
	ClassCredential   Class = "credential"
)

// Redactor manages per-request redaction state: sequence numbering per class
// and value-level deduplication. A fresh Redactor must be created per request.
// Across requests, placeholder numbers restart from 1 per class — no
// cross-request correlation is exposed upstream (redaction-v1 spec §5.3).
//
// Not goroutine-safe. DLP scans a request body on a single goroutine and the
// Redactor is scoped to that scan. Callers that need concurrent use must wrap
// externally.
type Redactor struct {
	counters map[Class]int
	dedup    map[Class]map[string]string
	total    int
}

// NewRedactor returns a fresh per-request Redactor.
func NewRedactor() *Redactor {
	return &Redactor{
		counters: make(map[Class]int),
		dedup:    make(map[Class]map[string]string),
	}
}

// Placeholder returns the typed placeholder for (class, original). First call
// for a (class, original) pair generates a new numbered placeholder of the
// form "<pl:CLASS:N>". Subsequent calls for the same pair return the same
// placeholder (per-request dedup). Sequence numbers are per-class, starting
// at 1.
func (r *Redactor) Placeholder(class Class, original string) string {
	bucket, ok := r.dedup[class]
	if !ok {
		bucket = make(map[string]string)
		r.dedup[class] = bucket
	}
	if existing, found := bucket[original]; found {
		return existing
	}
	r.counters[class]++
	ph := fmt.Sprintf("<pl:%s:%d>", string(class), r.counters[class])
	bucket[original] = ph
	r.total++
	return ph
}

// Total returns the count of unique redactions applied so far — every dedup
// hit counts once, regardless of how many times the same value appeared.
func (r *Redactor) Total() int {
	return r.total
}

func (r *Redactor) seen(class Class, original string) bool {
	if r == nil {
		return false
	}
	bucket, ok := r.dedup[class]
	if !ok {
		return false
	}
	_, ok = bucket[original]
	return ok
}

// ByClass returns a copy of per-class unique-redaction counts. Safe for the
// caller to retain: mutating the returned map does not affect internal state.
func (r *Redactor) ByClass() map[Class]int {
	out := make(map[Class]int, len(r.counters))
	for k, v := range r.counters {
		out[k] = v
	}
	return out
}
