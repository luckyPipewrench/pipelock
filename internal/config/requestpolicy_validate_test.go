// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func enabledPolicy(rules ...RequestPolicyRule) *Config {
	c := Defaults()
	c.RequestPolicy = RequestPolicy{
		Enabled:           true,
		OnParseError:      ActionBlock,
		OnOpaqueOperation: ActionBlock,
		Rules:             rules,
	}
	return c
}

func TestValidateRequestPolicy_ValidAndNormalizes(t *testing.T) {
	c := enabledPolicy(RequestPolicyRule{
		Name:   "api-writes",
		Action: ActionBlock,
		Route: RequestPolicyRoute{
			Methods:      []string{"post"},
			PathPrefixes: []string{"/api/write"},
			ContentTypes: []string{"Application/JSON; Charset=UTF-8"},
		},
		Reason: "destructive operation",
	})
	if _, err := c.ValidateWithWarnings(); err != nil {
		t.Fatalf("valid request_policy rejected: %v", err)
	}
	got := c.RequestPolicy.Rules[0].Route
	if got.Methods[0] != "POST" {
		t.Errorf("method not uppercased: %q", got.Methods[0])
	}
	if got.ContentTypes[0] != "application/json" {
		t.Errorf("content type not lowercased: %q", got.ContentTypes[0])
	}
}

func TestValidateRequestPolicy_Errors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "enabled with no rules",
			cfg:  enabledPolicy(),
			want: "no rules",
		},
		{
			name: "missing name",
			cfg:  enabledPolicy(RequestPolicyRule{Action: ActionBlock, Route: RequestPolicyRoute{Hosts: []string{"api.service.example.com"}}}),
			want: "missing name",
		},
		{
			name: "bad name charset",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "bad name!", Action: ActionBlock, Route: RequestPolicyRoute{Methods: []string{"POST"}}}),
			want: "metric label",
		},
		{
			name: "invalid action",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: "redirect", Route: RequestPolicyRoute{Methods: []string{"POST"}}}),
			want: "must be block or warn",
		},
		{
			name: "invalid parse error action",
			cfg: func() *Config {
				c := enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Methods: []string{"POST"}}})
				c.RequestPolicy.OnParseError = "retry"
				return c
			}(),
			want: "on_parse_error",
		},
		{
			name: "invalid opaque operation action",
			cfg: func() *Config {
				c := enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Methods: []string{"POST"}}})
				c.RequestPolicy.OnOpaqueOperation = "retry"
				return c
			}(),
			want: "on_opaque_operation",
		},
		{
			name: "no route constraint",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock}),
			want: "no route constraints",
		},
		{
			name: "invalid method",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Methods: []string{"FOO"}}}),
			want: "not a valid HTTP method",
		},
		{
			name: "invalid path pattern",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{PathPatterns: []string{"("}}}),
			want: "invalid path_pattern",
		},
		{
			name: "empty path prefix",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{PathPrefixes: []string{"  "}}}),
			want: "empty path_prefix",
		},
		{
			name: "empty path pattern",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{PathPatterns: []string{"  "}}}),
			want: "empty path_pattern",
		},
		{
			name: "empty content type",
			cfg:  enabledPolicy(RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{ContentTypes: []string{" ; charset=utf-8"}}}),
			want: "empty content_type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.ValidateWithWarnings()
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// Disabled sections are still structurally validated so dormant bad config
// cannot activate silently on reload.
func TestValidateRequestPolicy_DormantValidation(t *testing.T) {
	c := Defaults()
	c.RequestPolicy = RequestPolicy{
		Enabled:           false,
		OnParseError:      ActionBlock,
		OnOpaqueOperation: ActionBlock,
		Rules:             []RequestPolicyRule{{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{PathPatterns: []string{"("}}}},
	}
	if _, err := c.ValidateWithWarnings(); err == nil {
		t.Fatal("disabled section with invalid regex should still error")
	}
}

func TestApplyDefaults_RequestPolicyFailureActions(t *testing.T) {
	c := Defaults()
	c.RequestPolicy.OnParseError = ""
	c.RequestPolicy.OnOpaqueOperation = ""
	c.ApplyDefaults()
	if c.RequestPolicy.OnParseError != ActionBlock {
		t.Fatalf("OnParseError = %q, want %q", c.RequestPolicy.OnParseError, ActionBlock)
	}
	if c.RequestPolicy.OnOpaqueOperation != ActionBlock {
		t.Fatalf("OnOpaqueOperation = %q, want %q", c.RequestPolicy.OnOpaqueOperation, ActionBlock)
	}
}

func TestValidateRequestPolicy_DisabledEmitsNoVisibilityWarning(t *testing.T) {
	c := Defaults() // tls_interception disabled by default
	c.RequestPolicy = RequestPolicy{
		Enabled:           false,
		OnParseError:      ActionBlock,
		OnOpaqueOperation: ActionBlock,
		Rules:             []RequestPolicyRule{{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Hosts: []string{"api.service.example.com"}, Methods: []string{"POST"}}}},
	}
	warnings, err := c.ValidateWithWarnings()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, w := range warnings {
		if strings.Contains(w.Field, "request_policy") {
			t.Fatalf("disabled section must not emit visibility warning, got %+v", w)
		}
	}
}

func TestWarnRequestPolicyVisibility(t *testing.T) {
	rule := &RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Hosts: []string{"api.service.example.com"}, Methods: []string{"POST"}}}

	t.Run("tls interception off", func(t *testing.T) {
		c := &Config{}
		var warnings []Warning
		c.warnRequestPolicyVisibility(rule, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "tls_interception is disabled") {
			t.Fatalf("want tls-disabled warning, got %+v", warnings)
		}
	})

	t.Run("hostless inner-http rule warns when tls interception off", func(t *testing.T) {
		c := &Config{}
		hostless := &RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Methods: []string{"POST"}}}
		var warnings []Warning
		c.warnRequestPolicyVisibility(hostless, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "no host constraint") {
			t.Fatalf("want hostless tls-disabled warning, got %+v", warnings)
		}
	})

	t.Run("host-only graphql rule warns when tls interception off", func(t *testing.T) {
		c := &Config{}
		hostOnlyGraphQL := &RequestPolicyRule{
			Name:    "r",
			Action:  ActionBlock,
			Route:   RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
			GraphQL: &RequestPolicyGraphQL{OperationTypes: []string{"mutation"}},
		}
		var warnings []Warning
		c.warnRequestPolicyVisibility(hostOnlyGraphQL, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "tls_interception is disabled") {
			t.Fatalf("want graphql tls-disabled warning, got %+v", warnings)
		}
	})

	t.Run("passthrough host", func(t *testing.T) {
		c := &Config{}
		c.TLSInterception.Enabled = true
		c.TLSInterception.PassthroughDomains = []string{"api.service.example.com"}
		var warnings []Warning
		c.warnRequestPolicyVisibility(rule, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "passthrough_domains") {
			t.Fatalf("want passthrough warning, got %+v", warnings)
		}
	})

	t.Run("wildcard passthrough host", func(t *testing.T) {
		c := &Config{}
		c.TLSInterception.Enabled = true
		c.TLSInterception.PassthroughDomains = []string{"*.service.example.com"}
		var warnings []Warning
		c.warnRequestPolicyVisibility(rule, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "passthrough_domains") {
			t.Fatalf("want passthrough warning for wildcard match, got %+v", warnings)
		}
	})

	t.Run("host-only graphql rule warns on passthrough host", func(t *testing.T) {
		c := &Config{}
		c.TLSInterception.Enabled = true
		c.TLSInterception.PassthroughDomains = []string{"api.service.example.com"}
		hostOnlyGraphQL := &RequestPolicyRule{
			Name:    "r",
			Action:  ActionBlock,
			Route:   RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
			GraphQL: &RequestPolicyGraphQL{RootFieldPatterns: []string{`(?i)delete`}},
		}
		var warnings []Warning
		c.warnRequestPolicyVisibility(hostOnlyGraphQL, &warnings)
		if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "passthrough_domains") {
			t.Fatalf("want graphql passthrough warning, got %+v", warnings)
		}
	})

	t.Run("visible host emits nothing", func(t *testing.T) {
		c := &Config{}
		c.TLSInterception.Enabled = true
		c.TLSInterception.PassthroughDomains = []string{"other.example.com"}
		var warnings []Warning
		c.warnRequestPolicyVisibility(rule, &warnings)
		if len(warnings) != 0 {
			t.Fatalf("visible host should emit no warning, got %+v", warnings)
		}
	})

	t.Run("host-only rule emits nothing", func(t *testing.T) {
		c := &Config{}
		hostOnly := &RequestPolicyRule{Name: "r", Action: ActionBlock, Route: RequestPolicyRoute{Hosts: []string{"api.service.example.com"}}}
		var warnings []Warning
		c.warnRequestPolicyVisibility(hostOnly, &warnings)
		if len(warnings) != 0 {
			t.Fatalf("host-only rule is visible at CONNECT boundary and should not warn, got %+v", warnings)
		}
	})
}

func TestValidateRequestPolicy_GraphQL(t *testing.T) {
	t.Run("valid predicate normalizes operation types", func(t *testing.T) {
		c := enabledPolicy(RequestPolicyRule{
			Name:   "gql",
			Action: ActionBlock,
			Route:  RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
			GraphQL: &RequestPolicyGraphQL{
				OperationTypes:    []string{"Mutation"},
				RootFieldPatterns: []string{"  (?i)delete  "},
			},
		})
		if _, err := c.ValidateWithWarnings(); err != nil {
			t.Fatalf("valid graphql predicate rejected: %v", err)
		}
		gql := c.RequestPolicy.Rules[0].GraphQL
		if got := gql.OperationTypes[0]; got != "mutation" {
			t.Errorf("operation type not lowercased: %q", got)
		}
		if got := gql.RootFieldPatterns[0]; got != "(?i)delete" {
			t.Errorf("root_field_pattern not trimmed/persisted: %q", got)
		}
	})

	tests := []struct {
		name string
		gql  *RequestPolicyGraphQL
		want string
	}{
		{"empty predicate", &RequestPolicyGraphQL{}, "must set operation_types or root_field_patterns"},
		{"bad operation type", &RequestPolicyGraphQL{OperationTypes: []string{"delete"}}, "must be query, mutation, or subscription"},
		{"empty root field pattern", &RequestPolicyGraphQL{RootFieldPatterns: []string{"  "}}, "empty graphql root_field_pattern"},
		{"invalid root field pattern", &RequestPolicyGraphQL{RootFieldPatterns: []string{"("}}, "invalid graphql root_field_pattern"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := enabledPolicy(RequestPolicyRule{
				Name:    "gql",
				Action:  ActionBlock,
				Route:   RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
				GraphQL: tc.gql,
			})
			_, err := c.ValidateWithWarnings()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}
