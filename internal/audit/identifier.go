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
	once     sync.Once
	redactor *identifierRedactor
	err      error
}

func sharedIdentifierRedactor() (*identifierRedactor, error) {
	processIdentifierRedactor.once.Do(func() {
		processIdentifierRedactor.redactor, processIdentifierRedactor.err = newIdentifierRedactor()
	})
	return processIdentifierRedactor.redactor, processIdentifierRedactor.err
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
