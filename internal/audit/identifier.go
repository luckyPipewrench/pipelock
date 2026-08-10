// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/contract/privacy"
)

const identifierDiscriminatorPrefix = "hmac-sha256:"

type identifierRedactor struct {
	enforcer *privacy.Enforcer
}

var processIdentifierRedactor struct {
	mu       sync.Mutex
	redactor *identifierRedactor
}

func sharedIdentifierRedactor() (*identifierRedactor, error) {
	processIdentifierRedactor.mu.Lock()
	defer processIdentifierRedactor.mu.Unlock()
	if processIdentifierRedactor.redactor != nil {
		return processIdentifierRedactor.redactor, nil
	}
	redactor, err := newIdentifierRedactor()
	if err != nil {
		return nil, err
	}
	processIdentifierRedactor.redactor = redactor
	return redactor, nil
}

type lazyIdentifierRedactor struct {
	mu       sync.Mutex
	redactor *identifierRedactor
	source   func() (*identifierRedactor, error)
}

func newLazyIdentifierRedactor(source func() (*identifierRedactor, error)) *lazyIdentifierRedactor {
	return &lazyIdentifierRedactor{source: source}
}

func (r *lazyIdentifierRedactor) discriminator(value string) (string, error) {
	if r == nil || value == "" {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.redactor == nil {
		redactor, err := r.source()
		if err != nil {
			return "", err
		}
		r.redactor = redactor
	}
	return r.redactor.discriminator(value), nil
}

func newIdentifierRedactor() (*identifierRedactor, error) {
	return newIdentifierRedactorFrom(rand.Reader)
}

func newIdentifierRedactorFrom(source io.Reader) (*identifierRedactor, error) {
	var salt [32]byte
	if _, err := io.ReadFull(source, salt[:]); err != nil {
		return nil, fmt.Errorf("initialize audit identifier redaction: %w", err)
	}
	return newIdentifierRedactorWithSalt(salt[:]), nil
}

func newIdentifierRedactorWithSalt(salt []byte) *identifierRedactor {
	return &identifierRedactor{enforcer: privacy.NewEnforcer(salt)}
}

func (r *identifierRedactor) discriminator(value string) string {
	if r == nil || r.enforcer == nil || value == "" {
		return ""
	}
	outcome := r.enforcer.Apply(value, contract.DataClassInternal, false)
	if outcome.Decision != privacy.DecisionRedact {
		return ""
	}
	return identifierDiscriminatorPrefix + outcome.Rewritten
}
