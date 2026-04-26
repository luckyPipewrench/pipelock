// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	"github.com/luckyPipewrench/pipelock/internal/contract"
)

// Decision is the per-field outcome from Enforcer.Apply.
type Decision uint8

const (
	// DecisionEmit passes the value through unchanged. Used for public-class
	// fields and (after redaction) the salted-hash form of internal/sensitive.
	DecisionEmit Decision = iota
	// DecisionRedact replaces the value with a salted HMAC-SHA256 hex digest.
	// The original value is not retained.
	DecisionRedact
	// DecisionRequireOptIn signals that a sensitive-class field was observed
	// without the operator's explicit allow_sensitive opt-in. The recorder
	// must drop the field entirely (no clear, no hash).
	DecisionRequireOptIn
	// DecisionBlock signals that the field must not be emitted in any form.
	// Used for regulated class, missing-salt internal class, and unknown
	// data classes (defensive fail-closed).
	DecisionBlock
)

// Reason strings. Centralised so call sites and tests share canonical text.
const (
	reasonInternalNeedsSalt = "internal class requires salt"
	reasonSensitiveOptIn    = "sensitive class requires allow_sensitive=true"
	reasonRegulatedBlocked  = "regulated class is never emitted"
	reasonInvalidClass      = "invalid data_class"
)

// FieldOutcome bundles the decision with the rewritten field bytes.
//
// Rewritten holds the value the recorder should emit:
//   - DecisionEmit:         the original value (may be empty)
//   - DecisionRedact:       the lowercase hex HMAC-SHA256 digest
//   - DecisionRequireOptIn: empty (caller drops the field)
//   - DecisionBlock:        empty (caller drops the field, increments counter)
//
// Reason is human-readable and non-empty for every non-Emit decision.
// DataClass is the class the enforcer applied (echo of the input for
// observability, since callers may want to log it alongside the metric).
type FieldOutcome struct {
	Decision  Decision
	Rewritten string
	Reason    string
	DataClass contract.DataClass
}

// Enforcer applies the data-class taxonomy to a single observation field.
// Created once at startup with NewEnforcer; safe for concurrent use; the
// salt is never exposed via accessor or method.
type Enforcer struct {
	salt []byte
}

// NewEnforcer constructs an Enforcer from a resolved salt. Empty salt is
// allowed (the enforcer rejects any internal-class field with
// DecisionBlock rather than emitting plaintext); operators set
// learn.privacy.salt_source to enable internal-class observations.
//
// The provided slice is retained by reference. Callers must not mutate it
// after passing it to NewEnforcer.
func NewEnforcer(salt []byte) *Enforcer {
	return &Enforcer{salt: salt}
}

// Apply classifies a single observation field by its declared data class.
// AllowSensitive must be true for sensitive-class fields to redact-and-emit;
// otherwise sensitive returns DecisionRequireOptIn.
//
// Apply is pure relative to the enforcer's salt. It does not log, increment
// counters, or mutate state; the caller (recorder integration in a later
// commit) emits the corresponding pipelock_learn_*_total metric.
func (e *Enforcer) Apply(value string, fieldClass contract.DataClass, allowSensitive bool) FieldOutcome {
	switch fieldClass {
	case contract.DataClassPublic:
		return FieldOutcome{
			Decision:  DecisionEmit,
			Rewritten: value,
			DataClass: fieldClass,
		}
	case contract.DataClassInternal:
		if len(e.salt) == 0 {
			return FieldOutcome{
				Decision:  DecisionBlock,
				Reason:    reasonInternalNeedsSalt,
				DataClass: fieldClass,
			}
		}
		return FieldOutcome{
			Decision:  DecisionRedact,
			Rewritten: e.hash(value),
			DataClass: fieldClass,
		}
	case contract.DataClassSensitive:
		if !allowSensitive {
			return FieldOutcome{
				Decision:  DecisionRequireOptIn,
				Reason:    reasonSensitiveOptIn,
				DataClass: fieldClass,
			}
		}
		if len(e.salt) == 0 {
			return FieldOutcome{
				Decision:  DecisionBlock,
				Reason:    reasonInternalNeedsSalt,
				DataClass: fieldClass,
			}
		}
		return FieldOutcome{
			Decision:  DecisionRedact,
			Rewritten: e.hash(value),
			DataClass: fieldClass,
		}
	case contract.DataClassRegulated:
		return FieldOutcome{
			Decision:  DecisionBlock,
			Reason:    reasonRegulatedBlocked,
			DataClass: fieldClass,
		}
	default:
		// Defensive fail-closed for unknown / not-yet-enumerated classes.
		// Callers should validate before calling Apply, but the enforcer
		// blocks rather than emit when validation is skipped.
		return FieldOutcome{
			Decision:  DecisionBlock,
			Reason:    reasonInvalidClass,
			DataClass: fieldClass,
		}
	}
}

// hash returns the lowercase hex HMAC-SHA256 of value under the enforcer's
// salt. HMAC is the correct construction for keyed hashing; bare
// sha256(salt || value) is length-extension-vulnerable and not used here.
func (e *Enforcer) hash(value string) string {
	mac := hmac.New(sha256.New, e.salt)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}
