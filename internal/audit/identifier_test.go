// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
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
	first := NewNop().identifierRedactor.discriminator("same-subject")
	second := NewNop().identifierRedactor.discriminator("same-subject")
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

func TestNewLoggerPropagatesIdentifierEntropyFailure(t *testing.T) {
	wantErr := errors.New("entropy unavailable")
	_, err := newLogger("json", "stdout", "", false, true, io.Discard, func() (*identifierRedactor, error) {
		return nil, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("newLogger error = %v, want %v", err, wantErr)
	}
}
