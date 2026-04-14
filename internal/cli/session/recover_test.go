// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

// stubRecoverServer returns a canned inspect/explain response on any
// request. Release/terminate return success so the dispatcher's real
// paths also exercise cleanly when the flag-based tests hit them.
func stubRecoverServer(t *testing.T) *rootFlags {
	t.Helper()
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/explain"):
			writeJSONResponse(w, http.StatusOK, makeExplanation())
		case strings.HasSuffix(r.URL.Path, "/airlock"):
			writeJSONResponse(w, http.StatusOK, airlockResponse{
				Key: testKeyIdent, NewTier: tierNone, Changed: true,
			})
		case strings.HasSuffix(r.URL.Path, "/terminate"):
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"key": testKeyIdent, "terminated": true,
			})
		default:
			writeJSONResponse(w, http.StatusOK, makeDetail())
		}
	}))
	return flags
}

// withStubDispatcher installs a stub recoverDispatcher for the duration
// of the test and returns a handle so the test can assert.
func withStubDispatcher(t *testing.T) *stubRecoverDispatcher {
	t.Helper()
	stub := &stubRecoverDispatcher{}
	orig := recoverDispatcherFn
	t.Cleanup(func() { recoverDispatcherFn = orig })
	recoverDispatcherFn = func() recoverDispatcher { return stub }
	return stub
}

func TestRecoverCmd_ChoiceReleaseNone(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	stub := withStubDispatcher(t)

	out, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "release-none")
	if err != nil {
		t.Fatal(err)
	}
	if stub.inspectCalls != 1 || stub.explainCalls != 1 || stub.releaseCalls != 1 {
		t.Errorf("call counts: inspect=%d explain=%d release=%d",
			stub.inspectCalls, stub.explainCalls, stub.releaseCalls)
	}
	if stub.lastReleaseTo != tierNone {
		t.Errorf("release target: got %q, want none", stub.lastReleaseTo)
	}
	if !strings.Contains(out, "inspect") || !strings.Contains(out, "explain") {
		t.Errorf("output missing section headers: %s", out)
	}
}

func TestRecoverCmd_ChoiceReleaseSoft(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	stub := withStubDispatcher(t)

	if _, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "release-soft"); err != nil {
		t.Fatal(err)
	}
	if stub.lastReleaseTo != tierSoft {
		t.Errorf("release target: got %q, want soft", stub.lastReleaseTo)
	}
}

func TestRecoverCmd_ChoiceTerminate(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	stub := withStubDispatcher(t)

	if _, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "terminate"); err != nil {
		t.Fatal(err)
	}
	if stub.terminateCalls != 1 {
		t.Errorf("terminate calls: got %d, want 1", stub.terminateCalls)
	}
}

func TestRecoverCmd_ChoiceLeave(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	stub := withStubDispatcher(t)

	out, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "leave")
	if err != nil {
		t.Fatal(err)
	}
	if stub.releaseCalls != 0 || stub.terminateCalls != 0 {
		t.Errorf("leave should not dispatch: release=%d terminate=%d",
			stub.releaseCalls, stub.terminateCalls)
	}
	if !strings.Contains(out, "unchanged") {
		t.Errorf("leave should print unchanged: %s", out)
	}
}

func TestRecoverCmd_BadChoice(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	withStubDispatcher(t)

	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "eat-it")
	if err == nil {
		t.Error("expected error for bogus choice")
	}
}

func TestRecoverCmd_InteractiveStdin(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	stub := withStubDispatcher(t)

	cmd := recoverCmd()
	cmd.SetIn(strings.NewReader("1\n"))
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{testKeyIdent})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v; out=%s", err, buf.String())
	}
	if stub.lastReleaseTo != tierNone {
		t.Errorf("interactive '1' should map to release-none: got %q", stub.lastReleaseTo)
	}
}

func TestRecoverCmd_InteractiveStdin_InvalidInput(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	withStubDispatcher(t)

	cmd := recoverCmd()
	cmd.SetIn(strings.NewReader("xyz\n"))
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{testKeyIdent})

	if err := cmd.Execute(); err == nil {
		t.Error("expected error for unrecognized stdin input")
	}
}

func TestValidateRecoverChoice(t *testing.T) {
	good := []string{"release-none", "release-soft", "terminate", "leave"}
	for _, g := range good {
		if err := validateRecoverChoice(g); err != nil {
			t.Errorf("validateRecoverChoice(%q): %v", g, err)
		}
	}
	if err := validateRecoverChoice("nope"); err == nil {
		t.Error("expected error for bad input")
	}
}

func TestHTTPDispatcher_Inspect(t *testing.T) {
	// Exercise the httpDispatcher path (not the stub) so production code
	// gets test coverage too.
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	// No stub — uses httpDispatcher{}.

	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "leave")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestHTTPDispatcher_Release_Real(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	// No stub — uses httpDispatcher{}.

	if _, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "release-none"); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

func TestHTTPDispatcher_Terminate_Real(t *testing.T) {
	flags := stubRecoverServer(t)
	overrideClientFactory(t, flags)
	// No stub — uses httpDispatcher{}.

	if _, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "terminate"); err != nil {
		t.Fatalf("execute: %v", err)
	}
}

// errorServer returns an HTTP status on every request, exercising the
// httpDispatcher error-return branches for inspect/explain/release/terminate.
func errorServer(t *testing.T, status int) *rootFlags {
	t.Helper()
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fail", status)
	}))
	return flags
}

func TestHTTPDispatcher_InspectPropagatesError(t *testing.T) {
	flags := errorServer(t, http.StatusNotFound)
	overrideClientFactory(t, flags)
	// No stub — uses httpDispatcher.

	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "leave")
	if err == nil {
		t.Error("expected error from inspect 404")
	}
}

// errorServerExplain returns inspect success (so dispatch proceeds past
// the inspect step) then fails on every subsequent call. Exercises the
// Explain/Release/Terminate error branches in httpDispatcher.
func errorServerExplain(t *testing.T) *rootFlags {
	t.Helper()
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/explain") && !strings.Contains(r.URL.Path, "/airlock") && !strings.Contains(r.URL.Path, "/terminate") {
			writeJSONResponse(w, http.StatusOK, makeDetail())
			return
		}
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	return flags
}

func TestHTTPDispatcher_ExplainPropagatesError(t *testing.T) {
	flags := errorServerExplain(t)
	overrideClientFactory(t, flags)
	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "leave")
	if err == nil {
		t.Error("expected error from explain 500")
	}
}

func TestHTTPDispatcher_ReleasePropagatesError(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/explain"):
			writeJSONResponse(w, http.StatusOK, makeExplanation())
		case strings.HasSuffix(r.URL.Path, "/airlock"):
			http.Error(w, "fail", http.StatusInternalServerError)
		default:
			writeJSONResponse(w, http.StatusOK, makeDetail())
		}
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "release-none")
	if err == nil {
		t.Error("expected error from release 500")
	}
}

func TestHTTPDispatcher_TerminatePropagatesError(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/explain"):
			writeJSONResponse(w, http.StatusOK, makeExplanation())
		case strings.HasSuffix(r.URL.Path, "/terminate"):
			http.Error(w, "fail", http.StatusInternalServerError)
		default:
			writeJSONResponse(w, http.StatusOK, makeDetail())
		}
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(recoverCmd(), testKeyIdent, "--choice", "terminate")
	if err == nil {
		t.Error("expected error from terminate 500")
	}
}

func TestPromptRecoveryChoice_AllNumbers(t *testing.T) {
	cases := []struct {
		in   string
		want recoveryChoice
	}{
		{"1\n", choiceReleaseNone},
		{"2\n", choiceReleaseSoft},
		{"3\n", choiceTerminate},
		{"4\n", choiceLeave},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := promptRecoveryChoice(strings.NewReader(c.in), &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestPromptRecoveryChoice_NamedAliases(t *testing.T) {
	cases := map[string]recoveryChoice{
		"release-none\n": choiceReleaseNone,
		"release-soft\n": choiceReleaseSoft,
		"terminate\n":    choiceTerminate,
		"leave\n":        choiceLeave,
	}
	for in, want := range cases {
		got, err := promptRecoveryChoice(strings.NewReader(in), &bytes.Buffer{})
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestDispatchRecoveryChoice_UnknownChoice(t *testing.T) {
	stub := &stubRecoverDispatcher{}
	err := dispatchRecoveryChoice(t.Context(), stub, nil, testKeyIdent, recoveryChoice("fuzz"), &bytes.Buffer{})
	if err == nil {
		t.Error("expected error for unknown choice")
	}
}
