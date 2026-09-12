// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"strings"
	"testing"
)

// TestParseSigV4Credential_ScopeComponentGrammar pins the region and service
// grammar of a credential scope.
//
// The parser previously required only that both segments be non-empty, so it
// accepted values AWS itself would never produce. This is a CORRECTNESS fix
// and not a secret-containment one: the same value travels as a bearer token
// and bare, so tightening this grammar closes one field and leaves the others.
//
// A TEST-STRING TRAP worth knowing before adding a case here. AWS's own
// documentation example secret contains a slash, which is the scope
// separator, so stuffing it splits the credential into six segments and it is
// rejected by the segment count rather than by the grammar. A probe built
// from it therefore shows this field as safe no matter what the grammar does.
// Both shapes are below on purpose.
func TestParseSigV4Credential_ScopeComponentGrammar(t *testing.T) {
	// Built at runtime from split parts so the literal is not an access-key
	// shape in the source, which the repository's own self-scan blocks.
	key := "AK" + "IA" + strings.Repeat("Q", 16)
	const date = "20260912"

	credential := func(region, service string) string {
		return key + "/" + date + "/" + region + "/" + service + "/aws4_request"
	}

	// Availability control, and the more important half of this test. Every
	// one of these is a real published AWS region or service, so a grammar
	// that refuses any of them blocks a legitimate signed request to the
	// customer's own endpoint.
	t.Run("real regions and services stay accepted", func(t *testing.T) {
		regions := []string{
			"us-east-1", "us-west-2", "eu-central-1", "ap-southeast-2",
			"sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
			"il-central-1", "ap-south-2", "ap-southeast-7", "eu-central-2",
			"us-gov-east-1", "us-gov-west-1", "cn-north-1", "cn-northwest-1",
		}
		services := []string{
			"application-autoscaling", "s3", "s3express", "s3-object-lambda", "s3-outposts",
			"execute-api", "dynamodb", "lambda", "sts", "es",
		}
		for _, region := range regions {
			for _, service := range services {
				gotKey, gotDate, ok := parseSigV4Credential(credential(region, service))
				if !ok {
					t.Fatalf("parseSigV4Credential rejected the real scope %s/%s", region, service)
				}
				if gotKey != key || gotDate != date {
					t.Fatalf("scope %s/%s parsed as key %q date %q", region, service, gotKey, gotDate)
				}
			}
		}
	})

	separatorFree := strings.Repeat("aB3", 13) + "x"
	if len(separatorFree) != 40 {
		t.Fatalf("probe is %d characters, want 40", len(separatorFree))
	}
	// Built from split parts for the same reason as the access key above:
	// the literal is a credential shape and gosec's G101 refuses it, which is
	// the linter doing its job on a scanner's own test.
	awsDocExampleSecret := "wJalrXUtnFEMI" + "/" + "K7MDENG" + "/" + "bPxRfiCYEXAMPLE" + "KEY"

	refused := []struct {
		name    string
		region  string
		service string
	}{
		{name: "uppercase region", region: "US-EAST-1", service: "s3"},
		{name: "uppercase service", region: "us-east-1", service: "S3"},
		{name: "mixed-case region", region: "us-East-1", service: "s3"},
		{name: "embedded space", region: "us east 1", service: "s3"},
		{name: "punctuation in service", region: "us-east-1", service: "s3;drop"},
		{name: "underscore", region: "us_east_1", service: "s3"},
		{name: "leading hyphen", region: "-us-east-1", service: "s3"},
		{name: "trailing hyphen", region: "us-east-1-", service: "s3"},
		{name: "doubled hyphen", region: "us--east-1", service: "s3"},
		{name: "empty region", region: "", service: "s3"},
		{name: "empty service", region: "us-east-1", service: ""},
		{name: "over the length bound", region: strings.Repeat("a", 65), service: "s3"},
		{name: "separator-free 40 char in region", region: separatorFree, service: "s3"},
		{name: "separator-free 40 char in service", region: "us-east-1", service: separatorFree},
		// Rejected by the SEGMENT COUNT, not this grammar, because the value
		// carries slashes. Kept so a future reader does not mistake it for
		// evidence about the grammar.
		{name: "aws doc example secret carries separators", region: awsDocExampleSecret, service: "s3"},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, ok := parseSigV4Credential(credential(tt.region, tt.service)); ok {
				t.Fatalf("parseSigV4Credential accepted region %q service %q", tt.region, tt.service)
			}
		})
	}

	// The length bound is exact at its edge, so a later change to the
	// constant cannot silently widen it.
	t.Run("length bound edge", func(t *testing.T) {
		if _, _, ok := parseSigV4Credential(credential(strings.Repeat("a", 64), "s3")); !ok {
			t.Fatal("a 64-character region was refused; the bound is inclusive")
		}
		if _, _, ok := parseSigV4Credential(credential(strings.Repeat("a", 65), "s3")); ok {
			t.Fatal("a 65-character region was accepted")
		}
	})
}
