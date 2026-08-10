// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	scannerpkg "github.com/luckyPipewrench/pipelock/internal/scanner"
)

type failingIdentifierReader struct{}

func (failingIdentifierReader) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestIdentifierRedactorStableAndNonRevealing(t *testing.T) {
	r := newIdentifierRedactorWithSalt([]byte("test-only-audit-redaction-key"))
	first := r.discriminator("configured-agent|198.51.100.7")
	second := r.discriminator("configured-agent|198.51.100.7")
	other := r.discriminator("configured-agent|198.51.100.8")

	if first != second {
		t.Fatalf("same subject produced different discriminators: %q != %q", first, second)
	}
	if first == other {
		t.Fatalf("different subjects produced the same discriminator: %q", first)
	}
	if !strings.HasPrefix(first, identifierDiscriminatorPrefix) {
		t.Fatalf("discriminator = %q, want %q prefix", first, identifierDiscriminatorPrefix)
	}
	if strings.Contains(first, "198.51.100.7") || strings.Contains(first, "configured-agent") {
		t.Fatalf("discriminator leaked raw subject: %q", first)
	}
	if got := r.discriminator(""); got != "" {
		t.Fatalf("empty subject discriminator = %q, want empty", got)
	}
	if got := newIdentifierRedactorWithSalt(nil).discriminator("raw-subject"); got != "" {
		t.Fatalf("saltless discriminator = %q, want empty", got)
	}
}

func TestNewIdentifierRedactorFailsClosedWithoutEntropy(t *testing.T) {
	redactor, err := newIdentifierRedactorFrom(failingIdentifierReader{})
	if err == nil {
		t.Fatal("expected identifier redactor initialization to fail without entropy")
	}
	if got := redactor.discriminator("raw-subject"); got != "" {
		t.Fatalf("failed redactor emitted %q, want no discriminator", got)
	}
}

func TestAuditLoggersShareProcessDiscriminator(t *testing.T) {
	first, err := NewNop().identifierRedactor.discriminator("same-subject")
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewNop().identifierRedactor.discriminator("same-subject")
	if err != nil {
		t.Fatal(err)
	}
	if first == "" || first != second {
		t.Fatalf("process discriminators differ: first=%q second=%q", first, second)
	}
}

func TestNewWithStreamUsesProvidedWriter(t *testing.T) {
	var stream bytes.Buffer
	logger, err := NewWithStream("json", "stdout", "", false, true, &stream)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := NewMCPLogContext("MCP", "tool", "_default")
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(ctx.WithDoWAttribution("_default", "default"), "denial_of_wallet", "limit exceeded")
	if !strings.Contains(stream.String(), `"subject_trust":"default"`) {
		t.Fatalf("provided stream missing audit event: %s", stream.String())
	}
}

func TestNewWithStreamRejectsNilWriter(t *testing.T) {
	if _, err := NewWithStream("json", "stdout", "", false, true, nil); err == nil {
		t.Fatal("expected nil stream writer error")
	}
}

func TestNewWithIdentifierEntropyDefersFailure(t *testing.T) {
	var stream bytes.Buffer
	logger, err := NewWithIdentifierEntropy(IdentifierEntropyLoggerOpts{
		Format:         "json",
		Output:         "stdout",
		IncludeBlocked: true,
		Stream:         &stream,
		Entropy:        failingIdentifierReader{},
	})
	if err != nil {
		t.Fatalf("construct logger with unavailable entropy: %v", err)
	}
	ctx, err := NewMCPLogContext("MCP", "safe-tool", "configured-agent")
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(ctx.WithDoWAttribution("raw-subject", "agent"), scannerpkg.ScannerDenialOfWallet, "limit exceeded")
	if !strings.Contains(stream.String(), `"method":"audit_identifier_redaction"`) {
		t.Fatalf("entropy failure not surfaced: %s", stream.String())
	}
	if strings.Contains(stream.String(), "raw-subject") || strings.Contains(stream.String(), `"subject_discriminator"`) {
		t.Fatalf("entropy failure leaked subject data: %s", stream.String())
	}
}

func TestNewWithIdentifierEntropyDefersNilEntropyFailure(t *testing.T) {
	var stream bytes.Buffer
	logger, err := NewWithIdentifierEntropy(IdentifierEntropyLoggerOpts{
		Format:         "json",
		Output:         "stdout",
		IncludeBlocked: true,
		Stream:         &stream,
	})
	if err != nil {
		t.Fatalf("construct logger with nil entropy: %v", err)
	}
	ctx, err := NewMCPLogContext("MCP", "safe-tool", "configured-agent")
	if err != nil {
		t.Fatal(err)
	}
	logger.LogBlocked(ctx.WithDoWAttribution("raw-subject", "agent"), scannerpkg.ScannerDenialOfWallet, "limit exceeded")
	if !strings.Contains(stream.String(), `"method":"audit_identifier_redaction"`) {
		t.Fatalf("nil entropy failure not surfaced: %s", stream.String())
	}
	if strings.Contains(stream.String(), "raw-subject") || strings.Contains(stream.String(), `"subject_discriminator"`) {
		t.Fatalf("nil entropy failure leaked subject data: %s", stream.String())
	}
}

func TestNewLoggerDefersIdentifierEntropyFailureAndRecovers(t *testing.T) {
	wantErr := errors.New("entropy unavailable")
	var stream bytes.Buffer
	calls := 0
	logger, err := newLogger(loggerOpts{
		IdentifierEntropyLoggerOpts: IdentifierEntropyLoggerOpts{
			Format:         "json",
			Output:         "stdout",
			IncludeBlocked: true,
			Stream:         &stream,
		},
		identifierSource: func() (*identifierRedactor, error) {
			calls++
			if calls == 1 {
				return nil, wantErr
			}
			return newIdentifierRedactorWithSalt([]byte("recovered-test-entropy")), nil
		},
	})
	if err != nil {
		t.Fatalf("newLogger error = %v, want logger availability", err)
	}
	if calls != 0 {
		t.Fatalf("entropy source called %d times during logger construction, want 0", calls)
	}
	ctx, err := NewMCPLogContext("MCP", "safe-tool", "configured-agent")
	if err != nil {
		t.Fatal(err)
	}
	ctx = ctx.WithDoWAttribution("raw-principal|198.51.100.7", "principal")
	logger.LogBlocked(ctx, scannerpkg.ScannerDenialOfWallet, "limit exceeded")
	first := stream.String()
	for _, want := range []string{
		`"event":"error"`,
		`"method":"audit_identifier_redaction"`,
		`"agent":"configured-agent"`,
		`"subject_trust":"principal"`,
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("degraded audit output missing %q: %s", want, first)
		}
	}
	if strings.Contains(first, `"subject_discriminator"`) || strings.Contains(first, "raw-principal") || strings.Contains(first, "198.51.100.7") {
		t.Fatalf("degraded audit output exposed subject data: %s", first)
	}

	logger.LogBlocked(ctx, scannerpkg.ScannerDenialOfWallet, "limit exceeded again")
	if calls != 2 {
		t.Fatalf("entropy source calls = %d, want retry after failure", calls)
	}
	if !strings.Contains(stream.String(), `"subject_discriminator":"hmac-sha256:`) {
		t.Fatalf("recovered audit output missing discriminator: %s", stream.String())
	}
}
