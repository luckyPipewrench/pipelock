// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateRequestPolicyException(t *testing.T) {
	base := func() RequestPolicyRule {
		return RequestPolicyRule{
			Name:   "block-move",
			Action: ActionBlock,
			Route: RequestPolicyRoute{
				Hosts:        []string{"api.service.example.com"},
				Methods:      []string{"POST"},
				PathPatterns: []string{`/messages/.+/move$`},
			},
			Except: &RequestPolicyException{Field: "destinationId", Values: []string{"archive"}},
		}
	}
	for _, tc := range []struct {
		name string
		edit func(*RequestPolicyRule)
		want string
	}{
		{"valid", func(*RequestPolicyRule) {}, ""},
		{"QUERY method", func(r *RequestPolicyRule) { r.Route.Methods = []string{methodQuery} }, ""},
		{"warn rule", func(r *RequestPolicyRule) { r.Action = ActionWarn }, "requires an enforced block rule"},
		{"shadow rule", func(r *RequestPolicyRule) { r.Shadow = true }, "requires an enforced block rule"},
		{"no host", func(r *RequestPolicyRule) { r.Route.Hosts = nil }, "scoped by host"},
		{"no method", func(r *RequestPolicyRule) { r.Route.Methods = nil }, "scoped by host"},
		{"GET method", func(r *RequestPolicyRule) { r.Route.Methods = []string{"GET"} }, "body-carrying HTTP method"},
		{"no path", func(r *RequestPolicyRule) { r.Route.PathPatterns = nil }, "scoped by host"},
		{"combined discriminator", func(r *RequestPolicyRule) {
			r.Discriminator = &RequestPolicyDiscriminator{Field: "action", ValuePatterns: []string{"^send$"}}
		}, "without another predicate"},
		{"empty field", func(r *RequestPolicyRule) { r.Except.Field = " " }, "requires a field"},
		{"empty values", func(r *RequestPolicyRule) { r.Except.Values = nil }, "at least one"},
		{"empty value", func(r *RequestPolicyRule) { r.Except.Values = []string{""} }, "non-empty exact strings"},
		{"padded value", func(r *RequestPolicyRule) { r.Except.Values = []string{" archive"} }, "non-empty exact strings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.edit(&r)
			_, err := enabledPolicy(r).ValidateWithWarnings()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error = %v, want %q", err, tc.want)
			}
		})
	}
}
