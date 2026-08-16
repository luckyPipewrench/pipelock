// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateCanaryTokensRejectsWeakAndDuplicate(t *testing.T) {
	t.Parallel()

	if err := validateCanaryTokens(nil); err != nil {
		t.Fatalf("nil cfg = %v, want nil", err)
	}

	value := "AKIA" + "IOSFODNN7" + "CANARY1"
	other := "AKIA" + "IOSFODNN7" + "CANARY2"

	short := Defaults()
	short.Internal = nil
	short.CanaryTokens.Tokens = []CanaryToken{{Name: "short", Value: "abc"}}
	if err := validateCanaryTokens(short); err == nil || !strings.Contains(err.Error(), "at least 8 characters") {
		t.Fatalf("short value err = %v", err)
	}

	dupName := Defaults()
	dupName.Internal = nil
	dupName.CanaryTokens.Tokens = []CanaryToken{
		{Name: "aws_canary", Value: value},
		{Name: "AWS_CANARY", Value: other},
	}
	if err := validateCanaryTokens(dupName); err == nil || !strings.Contains(err.Error(), "is duplicated") {
		t.Fatalf("duplicate name err = %v", err)
	}

	dupValue := Defaults()
	dupValue.Internal = nil
	dupValue.CanaryTokens.Tokens = []CanaryToken{
		{Name: "one", Value: value},
		{Name: "two", Value: value},
	}
	if err := validateCanaryTokens(dupValue); err == nil || !strings.Contains(err.Error(), "value is duplicated") {
		t.Fatalf("duplicate value err = %v", err)
	}

	ok := Defaults()
	ok.Internal = nil
	ok.CanaryTokens.Tokens = []CanaryToken{{Name: "aws_canary", Value: value, EnvVar: "AWS_CANARY_KEY"}}
	if err := validateCanaryTokens(ok); err != nil {
		t.Fatalf("valid token: %v", err)
	}
}
