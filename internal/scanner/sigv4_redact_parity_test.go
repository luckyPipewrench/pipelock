// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

func TestParseSigV4CredentialAndRedactorScopeParity(t *testing.T) {
	key := "AK" + "IA" + strings.Repeat("Q", 16)
	tooLong := strings.Repeat("a", 65)
	tests := []struct {
		name  string
		scope string
		want  bool
	}{
		{name: "application autoscaling", scope: "20260912/us-east-1/application-autoscaling/aws4_request", want: true},
		{name: "execute api", scope: "20260912/us-east-1/execute-api/aws4_request", want: true},
		{name: "s3", scope: "20260912/us-east-1/s3/aws4_request", want: true},
		{name: "sts", scope: "20260912/us-east-1/sts/aws4_request", want: true},
		{name: "64 character component", scope: "20260912/us-east-1/" + strings.Repeat("a", 64) + "/aws4_request", want: true},
		{name: "uppercase component", scope: "20260912/us-east-1/S3/aws4_request", want: false},
		{name: "empty component", scope: "20260912/us-east-1//aws4_request", want: false},
		{name: "65 character component", scope: "20260912/us-east-1/" + tooLong + "/aws4_request", want: false},
		{name: "slash containing component", scope: "20260912/us-east-1/s3/extra/aws4_request", want: false},
		{name: "missing terminator", scope: "20260912/us-east-1/s3/aws3_request", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, scannerAccepted := parseSigV4Credential(key + "/" + tt.scope)
			if scannerAccepted != tt.want {
				t.Fatalf("scanner parser acceptance = %v, want %v", scannerAccepted, tt.want)
			}
			for _, tail := range []string{"/" + tt.scope, "%2F" + strings.ReplaceAll(tt.scope, "/", "%2F")} {
				if redactorAccepted := redact.IsSigV4CredentialScopeTail(tail); redactorAccepted != scannerAccepted {
					t.Fatalf("redactor acceptance for %q = %v, scanner parser = %v", tail, redactorAccepted, scannerAccepted)
				}
			}
		})
	}
}
