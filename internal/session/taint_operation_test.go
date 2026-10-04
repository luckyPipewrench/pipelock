// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestMCPBoundedOperationEvidence(t *testing.T) {
	for _, prefix := range []string{"", "mcp__service__", "service.", "service:"} {
		for _, tool := range []string{"list_thread_pull_requests", "list_posts", "get_input", "listPosts", "getInput", "listThreadPullRequests"} {
			for _, failSafe := range []bool{false, true} {
				t.Run(prefix+tool+map[bool]string{false: "/off", true: "/on"}[failSafe], func(t *testing.T) {
					got := session.ClassifyMCPToolCallWithOptions(prefix+tool, `{}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
					if got.Class != session.ActionClassRead || got.Confident {
						t.Fatalf("got %+v, want low-confidence read", got)
					}
					want := session.SensitivityNormal
					if failSafe {
						want = session.SensitivityProtected
					}
					if got.Sensitivity != want {
						t.Fatalf("got %+v, want sensitivity %v", got, want)
					}
					decision := (session.PolicyMatrix{}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
					expected := session.PolicyAllow
					if failSafe {
						expected = session.PolicyAsk
					}
					if decision.Decision != expected {
						t.Fatalf("got %+v, want %v", decision, expected)
					}
				})
			}
		}
	}
}

func TestMCPMutationEvidencePrecedesReads(t *testing.T) {
	tests := []struct{ tool, args string }{
		{"post_message", `{}`},
		{"read_post", `{}`},
		{"get_put", `{}`},
		{"request", `{}`},
		{"mcp__service__request", `{}`},
		{"service.request", `{}`},
		{"http_get", `{}`},
		{"mcp__publish__list_posts", `{}`},
		{"publishList", `{}`},
		{"mcp__post__nested__list_posts", `{}`},
		{"list_posts", `{"nested":{"payload":"x"}}`},
		{"list_posts", `{ "nested": { "request_body": "x" }`},
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "QUERY"} {
		tests = append(tests, struct{ tool, args string }{"list_thread_pull_requests", `{"nested":[{"method":" ` + method + ` "}]}`}, struct{ tool, args string }{"get_input", `{ "nested": { "method" : "` + method + `" }`})
	}
	for _, tt := range tests {
		t.Run(tt.tool+tt.args, func(t *testing.T) {
			got := session.ClassifyMCPToolCallWithOptions(tt.tool, tt.args, nil, nil, session.ClassificationOptions{})
			wantClass := session.ActionClassPublish
			if tt.tool == "get_put" {
				wantClass = session.ActionClassWrite
			}
			if got.Class != wantClass {
				t.Fatalf("mutation lost: %+v", got)
			}
			decision := (session.PolicyMatrix{Profile: "strict"}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{ClassificationConfident: got.Confident})
			wantDecision := session.PolicyAsk
			if tt.tool == "get_put" {
				wantDecision = session.PolicyAllow
			}
			if decision.Decision != wantDecision {
				t.Fatalf("publication allowed: %+v", decision)
			}
		})
	}
}

func TestMCPConservativeMutationEvidence(t *testing.T) {
	for _, name := range []string{"link_pull_request", "watch_pull_request", "linkPullRequest", "watchPullRequest", "mcp__service__watch_pull_request", "linkpullrequest", "watchpullrequest", "get_pull_post", "get_pull_put", "list_pull_send", "get_or_open_pull_request", "get_and_open_pull_request", "link_and_open_pull_request", "get_and_forward_posts", "get_and_share_posts", "get_and_set_input", "get_and_deploy_input", "mcp__posts__list_items", "mcp__input__get_status", "mcp__pull_request__list_things", "getReQuest", "listPoSt", "readSeNd", "getPuT", "getHtTp", "getWebHook", "listPubLish", "postcomment", "postmessage", "submitpost", "putobject", "repost", "webpost", "xpostx", "post1", "post2_message", "merge_pull_request", "approve_pull_request", "make_request", "payment_request", "api_request", "mcp__service__nested__request", "service.nested.request", "service::request", "service. request"} {
		for _, failSafe := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "/off", true: "/on"}[failSafe], func(t *testing.T) {
				got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
				wantClass := session.ActionClassPublish
				if name == "get_pull_put" {
					wantClass = session.ActionClassWrite
				}
				if got.Class != wantClass {
					t.Fatalf("mutation lost: %+v", got)
				}
				decision := (session.PolicyMatrix{Profile: "strict"}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
				wantDecision := session.PolicyAsk
				if name == "get_pull_put" && !failSafe {
					wantDecision = session.PolicyAllow
				}
				if decision.Decision != wantDecision {
					t.Fatalf("publication allowed after taint: %+v", decision)
				}
			})
		}
	}
}

func TestMCPReadOperationObjects(t *testing.T) {
	for _, name := range []string{"get_comment", "get_merge_status", "get_merge_base", "check_push_status", "get_reply", "show_posts", "query_posts", "describe_pull_request", "check_pull_request"} {
		got := session.ClassifyMCPToolCallWithOptions(name, `{}`, nil, nil, session.ClassificationOptions{})
		if got.Class == session.ActionClassPublish || got.Class == session.ActionClassWrite {
			t.Fatalf("%s: read object classified as mutation: %+v", name, got)
		}
	}
}

func TestMCPWatchMutationWithIdentifierArguments(t *testing.T) {
	for _, name := range []string{"watch_pull_request", "link_pull_request", "mcp__service__watch_pull_request"} {
		for _, failSafe := range []bool{false, true} {
			got := session.ClassifyMCPToolCallWithOptions(name, `{"project_key":"example","repo_slug":"example","pr_id":1}`, nil, nil, session.ClassificationOptions{FailSafe: failSafe})
			if got.Class != session.ActionClassPublish {
				t.Fatalf("%s: mutation lost: %+v", name, got)
			}
			decision := (session.PolicyMatrix{}).EvaluateWithOptions(session.TaintExternalUntrusted, got.Class, got.Sensitivity, session.AuthorityUserBroad, session.PolicyEvaluateOptions{FailSafeClassification: failSafe, ClassificationConfident: got.Confident})
			if decision.Decision != session.PolicyAsk {
				t.Fatalf("%s: mutation allowed: %+v", name, decision)
			}
		}
	}
}
