// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/http"
	"testing"
)

func TestClassifyHTTP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		want   ActionType
	}{
		{name: "GET", method: http.MethodGet, want: ActionRead},
		{name: "HEAD", method: http.MethodHead, want: ActionRead},
		{name: "OPTIONS", method: http.MethodOptions, want: ActionRead},
		{name: "TRACE", method: http.MethodTrace, want: ActionRead},
		{name: "CONNECT", method: http.MethodConnect, want: ActionRead},
		{name: "POST", method: http.MethodPost, want: ActionWrite},
		{name: "PUT", method: http.MethodPut, want: ActionWrite},
		{name: "PATCH", method: http.MethodPatch, want: ActionWrite},
		{name: "DELETE", method: http.MethodDelete, want: ActionWrite},
		{name: "custom_method", method: "CUSTOM", want: ActionUnclassified},
		{name: "empty_method", method: "", want: ActionUnclassified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyHTTP(tc.method)
			if got != tc.want {
				t.Errorf("ClassifyHTTP(%q) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestSideEffectFromMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		want   SideEffectClass
	}{
		{name: "GET", method: http.MethodGet, want: SideEffectExternalRead},
		{name: "HEAD", method: http.MethodHead, want: SideEffectExternalRead},
		{name: "OPTIONS", method: http.MethodOptions, want: SideEffectExternalRead},
		{name: "TRACE", method: http.MethodTrace, want: SideEffectExternalRead},
		{name: "CONNECT", method: http.MethodConnect, want: SideEffectExternalRead},
		{name: "POST", method: http.MethodPost, want: SideEffectExternalWrite},
		{name: "PUT", method: http.MethodPut, want: SideEffectExternalWrite},
		{name: "PATCH", method: http.MethodPatch, want: SideEffectExternalWrite},
		{name: "DELETE", method: http.MethodDelete, want: SideEffectExternalWrite},
		{name: "custom_method", method: "CUSTOM", want: SideEffectNone},
		{name: "empty_method", method: "", want: SideEffectNone},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := SideEffectFromMethod(tc.method)
			if got != tc.want {
				t.Errorf("SideEffectFromMethod(%q) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestReversibilityFromMethod(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		want   Reversibility
	}{
		{name: "GET", method: http.MethodGet, want: ReversibilityFull},
		{name: "HEAD", method: http.MethodHead, want: ReversibilityFull},
		{name: "OPTIONS", method: http.MethodOptions, want: ReversibilityFull},
		{name: "TRACE", method: http.MethodTrace, want: ReversibilityFull},
		{name: "CONNECT", method: http.MethodConnect, want: ReversibilityFull},
		{name: "DELETE", method: http.MethodDelete, want: ReversibilityIrreversible},
		{name: "POST", method: http.MethodPost, want: ReversibilityCompensatable},
		{name: "PUT", method: http.MethodPut, want: ReversibilityCompensatable},
		{name: "PATCH", method: http.MethodPatch, want: ReversibilityCompensatable},
		{name: "custom_method", method: "CUSTOM", want: ReversibilityUnknown},
		{name: "empty_method", method: "", want: ReversibilityUnknown},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ReversibilityFromMethod(tc.method)
			if got != tc.want {
				t.Errorf("ReversibilityFromMethod(%q) = %q, want %q", tc.method, got, tc.want)
			}
		})
	}
}

func TestClassifyMCPTool(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		toolName  string
		mcpMethod string
		want      ActionType
	}{
		// Listing methods are reads
		{name: "tools_list", toolName: "", mcpMethod: "tools/list", want: ActionRead},
		{name: "resources_list", toolName: "", mcpMethod: "resources/list", want: ActionRead},
		{name: "resources_read", toolName: "", mcpMethod: "resources/read", want: ActionRead},
		{name: "prompts_list", toolName: "", mcpMethod: "prompts/list", want: ActionRead},
		{name: "prompts_get", toolName: "", mcpMethod: "prompts/get", want: ActionRead},

		// tools/call with read-like names
		{name: "tools_call_getUsers", toolName: "getUsers", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_listItems", toolName: "listItems", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_readFile", toolName: "readFile", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_searchDocs", toolName: "searchDocs", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_findUser", toolName: "findUser", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_queryDB", toolName: "queryDB", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_fetchData", toolName: "fetchData", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_showInfo", toolName: "showInfo", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_describeTable", toolName: "describeTable", mcpMethod: "tools/call", want: ActionRead},
		{name: "tools_call_checkStatus", toolName: "checkStatus", mcpMethod: "tools/call", want: ActionRead},

		// tools/call with write-like names
		{name: "tools_call_createFile", toolName: "createFile", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_updateRecord", toolName: "updateRecord", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_deleteItem", toolName: "deleteItem", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_removeEntry", toolName: "removeEntry", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_writeFile", toolName: "writeFile", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_setConfig", toolName: "setConfig", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_addUser", toolName: "addUser", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_modifySettings", toolName: "modifySettings", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_editDoc", toolName: "editDoc", mcpMethod: "tools/call", want: ActionWrite},
		{name: "tools_call_patchRecord", toolName: "patchRecord", mcpMethod: "tools/call", want: ActionWrite},

		// tools/call with delegate-like names
		{name: "tools_call_runCommand", toolName: "runCommand", mcpMethod: "tools/call", want: ActionDelegate},
		{name: "tools_call_execScript", toolName: "execScript", mcpMethod: "tools/call", want: ActionDelegate},
		{name: "tools_call_executeTask", toolName: "executeTask", mcpMethod: "tools/call", want: ActionDelegate},
		{name: "tools_call_spawnProcess", toolName: "spawnProcess", mcpMethod: "tools/call", want: ActionDelegate},
		{name: "tools_call_invokeAPI", toolName: "invokeAPI", mcpMethod: "tools/call", want: ActionDelegate},
		{name: "tools_call_callService", toolName: "callService", mcpMethod: "tools/call", want: ActionDelegate},

		// tools/call unclassified
		{name: "tools_call_unknownTool", toolName: "unknownTool", mcpMethod: "tools/call", want: ActionUnclassified},
		{name: "tools_call_empty_name", toolName: "", mcpMethod: "tools/call", want: ActionUnclassified},
		{name: "tools_call_ambiguous", toolName: "doSomething", mcpMethod: "tools/call", want: ActionUnclassified},

		// Unknown MCP method
		{name: "unknown_mcp_method", toolName: "foo", mcpMethod: "custom/method", want: ActionUnclassified},
		{name: "empty_mcp_method", toolName: "foo", mcpMethod: "", want: ActionUnclassified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyMCPTool(tc.toolName, tc.mcpMethod)
			if got != tc.want {
				t.Errorf("ClassifyMCPTool(%q, %q) = %q, want %q",
					tc.toolName, tc.mcpMethod, got, tc.want)
			}
		})
	}
}

func TestHasPrefix_EdgeCases(t *testing.T) {
	t.Parallel()

	// Test hasPrefix indirectly via ClassifyMCPTool with tools/call.
	tests := []struct {
		name     string
		toolName string
		want     ActionType
	}{
		// camelCase separator (uppercase letter after prefix)
		{name: "camelCase_getUsers", toolName: "getUsers", want: ActionRead},
		// underscore separator
		{name: "underscore_get_users", toolName: "get_users", want: ActionRead},
		// hyphen separator
		{name: "hyphen_get-users", toolName: "get-users", want: ActionRead},
		// exact match (no separator needed)
		{name: "exact_get", toolName: "get", want: ActionRead},
		// prefix without separator does not match
		{name: "no_separator_getaway", toolName: "getaway", want: ActionUnclassified},
		// case insensitive prefix
		{name: "case_insensitive_GetUsers", toolName: "GetUsers", want: ActionRead},
		{name: "case_insensitive_GET_items", toolName: "GET_items", want: ActionRead},
		// short name that is shorter than any prefix
		{name: "short_name_go", toolName: "go", want: ActionUnclassified},
		// single char
		{name: "single_char", toolName: "g", want: ActionUnclassified},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ClassifyMCPTool(tc.toolName, "tools/call")
			if got != tc.want {
				t.Errorf("ClassifyMCPTool(%q, \"tools/call\") = %q, want %q",
					tc.toolName, got, tc.want)
			}
		})
	}
}
