// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestMCPPullRequestReadsAfterExternalExposure(t *testing.T) {
	for _, prefix := range []string{"", "mcp__github__", "github.", "github:"} {
		for _, tool := range []string{"list_pull_requests", "search_pull_requests", "pull_request_read", "pullRequestRead", "pull-request-read"} {
			for _, method := range []string{"get", "get_diff", "get_status", "get_files", "get_commits", "get_review_comments", "get_reviews", "get_comments", "get_check_runs"} {
				t.Run(prefix+tool+"/"+method, func(t *testing.T) {
					args := `{"owner":"example","repo":"example","pullNumber":1,"method":"` + method + `"}`
					got := session.ClassifyMCPToolCallWithOptions(prefix+tool, args, nil, nil, session.ClassificationOptions{})
					if got.Class != session.ActionClassRead || got.Confident {
						t.Fatalf("got %+v, want low-confidence read", got)
					}
					for _, profile := range []string{"balanced", "strict", "permissive"} {
						d := (session.PolicyMatrix{Profile: profile}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{ClassificationConfident: got.Confident})
						if d.Decision != session.PolicyAllow || d.Reason != "taint_safe_read_only_action" {
							t.Fatalf("%s: got %+v, want safe read allow", profile, d)
						}
					}
				})
			}
		}
	}
}

func TestMCPPullRequestReadConservativeBoundary(t *testing.T) {
	tests := []struct {
		tool, args string
		want       session.ActionClass
	}{
		{"pull_request_read", `{}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":"unknown"}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":"GET"}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":" get "}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":null}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":1}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":["get"]}`, session.ActionClassPublish},
		{"pull_request_read", `{"Method":"get"}`, session.ActionClassPublish},
		{"pull_request_read", `{"nested":{"method":"get"}}`, session.ActionClassPublish},
		{"pull_request_read", `[{"method":"get"}]`, session.ActionClassPublish},
		{"pull_request_read", `null`, session.ActionClassPublish},
		{"pull_request_read", `"get"`, session.ActionClassPublish},
		{"pull_request_read", `{"method":"get"`, session.ActionClassPublish},
		{"pull_request_read", "", session.ActionClassPublish},
		{"pull_request_read", `{"method":"get","nested":{"payload":"x"}}`, session.ActionClassPublish},
		{"pull_request_read", `{"method":"get","path":"/repo/file","content":"x"}`, session.ActionClassWrite},
		{"request_copilot_review", `{"method":"get"}`, session.ActionClassPublish},
		{"send_message", `{}`, session.ActionClassPublish},
	}
	for _, key := range []string{"endpoint", "webhook", "request_body", "form_data", "upload"} {
		tests = append(tests, struct {
			tool, args string
			want       session.ActionClass
		}{"pull_request_read", `{"method":"get","` + key + `":"x"}`, session.ActionClassPublish})
	}
	for _, name := range []string{"pullrequestread", "pull_request_read_extra", "pull_request_read2", "read_pull_request_extra", "get_and_open_pull_request", "pull_request_read_and_send", "mcp__post__pull_request_read", "mcp__request__pull_request_read", "mcp__service__post__pull_request_read", "post.pull_request_read", "publish:pull_request_read", "mcp__input__pull_request_read", "github::pull_request_read", "github. pull_request_read"} {
		tests = append(tests, struct {
			tool, args string
			want       session.ActionClass
		}{name, `{"method":"get"}`, session.ActionClassPublish})
	}
	for _, tool := range []string{"list_pull_requests", "search_pull_requests", "pull_request_read"} {
		for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "QUERY"} {
			for _, args := range []string{`{"method":"` + method + `"}`, `{"method":"get","nested":[{"method":" ` + method + ` "}]}`, `{"method":"` + method + `"`} {
				tests = append(tests, struct {
					tool, args string
					want       session.ActionClass
				}{tool, args, session.ActionClassPublish})
			}
		}
	}
	for _, tt := range tests {
		t.Run(tt.tool+"/"+tt.args, func(t *testing.T) {
			for _, failSafe := range []bool{false, true} {
				got := session.ClassifyMCPToolCallWithOptions(tt.tool, tt.args, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
				if got.Class != tt.want {
					t.Fatalf("failSafe=%v: got %+v, want %v", failSafe, got, tt.want)
				}
				if tt.want == session.ActionClassPublish {
					d := (session.PolicyMatrix{}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
					if d.Decision != session.PolicyAsk {
						t.Fatalf("mutation allowed: %+v", d)
					}
				}
			}
		})
	}
}

func TestMCPPullRequestReadFailSafeConfidence(t *testing.T) {
	for _, profile := range []string{"balanced", "strict", "permissive"} {
		for _, failSafe := range []bool{false, true} {
			got := session.ClassifyMCPToolCallWithOptions("pull_request_read", `{"method":"get"}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
			d := (session.PolicyMatrix{Profile: profile}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
			want := session.PolicyAllow
			if failSafe && profile != "permissive" {
				want = session.PolicyAsk
			}
			if got.Class != session.ActionClassRead || got.Confident || d.Decision != want {
				t.Fatalf("%s/failSafe=%v: %+v / %+v", profile, failSafe, got, d)
			}
		}
	}
}
