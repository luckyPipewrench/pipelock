// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestFly(srv *httptest.Server) *FlyMachines {
	return &FlyMachines{
		AppName: "playground-pool",
		Token:   "fly_test_token",
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
	}
}

func TestFlyCreateMachine(t *testing.T) {
	var gotAuth, gotMethod, gotPath, gotCT string
	var gotBody flyCreateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"148ed123","state":"created","private_ip":"fdaa:0:1::3"}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	m, err := fly.CreateMachine(context.Background(), MachineSpec{
		Image:    "registry.fly.io/playground:tip",
		Env:      map[string]string{"PLAYGROUND_LISTEN": "0.0.0.0:8080"},
		Region:   "ord",
		MemoryMB: 512,
		CPUs:     1,
	})
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if m.ID != "148ed123" || m.State != "created" || m.PrivateIP != "fdaa:0:1::3" {
		t.Fatalf("unexpected machine: %+v", m)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/apps/playground-pool/machines" {
		t.Errorf("path = %s", gotPath)
	}
	if gotAuth != "Bearer fly_test_token" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q", gotCT)
	}
	if gotBody.Config.Image != "registry.fly.io/playground:tip" {
		t.Errorf("body image = %q", gotBody.Config.Image)
	}
	if !gotBody.Config.AutoDestroy {
		t.Error("auto_destroy should be true (one-shot per-visitor VM)")
	}
	if gotBody.Config.Restart.Policy != "no" {
		t.Errorf("restart policy = %q, want no", gotBody.Config.Restart.Policy)
	}
	if gotBody.Config.Guest.MemoryMB != 512 || gotBody.Config.Guest.CPUKind != "shared" {
		t.Errorf("guest = %+v", gotBody.Config.Guest)
	}
	if gotBody.Region != "ord" {
		t.Errorf("region = %q", gotBody.Region)
	}
	// Verify the playground role metadata tag is set.
	if gotBody.Config.Metadata == nil {
		t.Fatal("metadata is nil; want playground role tag")
	}
	if gotBody.Config.Metadata[playgroundRoleKey] != playgroundRoleVal {
		t.Errorf("metadata[%s] = %q, want %q", playgroundRoleKey, gotBody.Config.Metadata[playgroundRoleKey], playgroundRoleVal)
	}
}

func TestFlyCreateMachineDefaultsGuest(t *testing.T) {
	var gotBody flyCreateRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		_, _ = w.Write([]byte(`{"id":"x","state":"created"}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	if _, err := fly.CreateMachine(context.Background(), MachineSpec{Image: "img"}); err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	if gotBody.Config.Guest.CPUs != 1 || gotBody.Config.Guest.MemoryMB != 512 {
		t.Errorf("guest defaults not applied: %+v", gotBody.Config.Guest)
	}
}

func TestFlyCreateMachineEmptyImage(t *testing.T) {
	fly := &FlyMachines{AppName: "a", Token: "t"}
	if _, err := fly.CreateMachine(context.Background(), MachineSpec{}); err == nil {
		t.Fatal("want error for empty image")
	}
}

func TestFlyHTTPClientTimeoutCoversWaitReady(t *testing.T) {
	fly := &FlyMachines{AppName: "a", Token: "t"}
	if got, want := fly.httpClient().Timeout, defaultWaitTimeout+5*time.Second; got != want {
		t.Fatalf("default client timeout = %s, want %s", got, want)
	}

	shortWait := &FlyMachines{AppName: "a", Token: "t", WaitTimeout: 10 * time.Second}
	if got, want := shortWait.httpClient().Timeout, 30*time.Second; got != want {
		t.Fatalf("short-wait client timeout = %s, want floor %s", got, want)
	}

	customHTTP := &http.Client{Timeout: time.Second}
	withCustomHTTP := &FlyMachines{AppName: "a", Token: "t", HTTP: customHTTP}
	if got := withCustomHTTP.httpClient(); got != customHTTP {
		t.Fatal("custom HTTP client was not preserved")
	}
}

func TestFlyWaitReady(t *testing.T) {
	var gotPath, gotState, gotTimeout string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotState = r.URL.Query().Get("state")
		gotTimeout = r.URL.Query().Get("timeout")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	if err := fly.WaitReady(context.Background(), "148ed123"); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if gotPath != "/apps/playground-pool/machines/148ed123/wait" {
		t.Errorf("path = %s", gotPath)
	}
	if gotState != "started" {
		t.Errorf("state = %q", gotState)
	}
	wantTimeout := strconv.Itoa(int(defaultWaitTimeout.Seconds()))
	if gotTimeout != wantTimeout {
		t.Errorf("timeout = %q, want %q", gotTimeout, wantTimeout)
	}
}

func TestFlyDestroyMachine(t *testing.T) {
	var gotMethod, gotForce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotForce = r.URL.Query().Get("force")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	if err := fly.DestroyMachine(context.Background(), "148ed123"); err != nil {
		t.Fatalf("DestroyMachine: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %s, want DELETE", gotMethod)
	}
	if gotForce != "true" {
		t.Errorf("force = %q", gotForce)
	}
}

func TestFlyDestroyMachineIdempotentOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"machine not found"}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	if err := fly.DestroyMachine(context.Background(), "gone"); err != nil {
		t.Fatalf("DestroyMachine on 404 should be nil (idempotent), got %v", err)
	}
}

func TestFlyNon2xxIsAPIError(t *testing.T) {
	const fakeRequestID = "req-abc123"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(flyRequestIDHeader, fakeRequestID)
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"bad config"}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	_, err := fly.CreateMachine(context.Background(), MachineSpec{Image: "img"})
	if err == nil {
		t.Fatal("want error on 422")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *apiError, got %T: %v", err, err)
	}
	if apiErr.status != http.StatusUnprocessableEntity {
		t.Errorf("status = %d", apiErr.status)
	}
	errStr := err.Error()
	// Error must include status code and path (non-sensitive diagnostics).
	if !strings.Contains(errStr, "422") {
		t.Errorf("error should contain HTTP status code: %s", errStr)
	}
	if !strings.Contains(errStr, "/apps/playground-pool/machines") {
		t.Errorf("error should contain request path: %s", errStr)
	}
	// Error must include the Fly request ID for operator debugging.
	if !strings.Contains(errStr, fakeRequestID) {
		t.Errorf("error should contain Fly-Request-Id: %s", errStr)
	}
	// Error must NOT include the response body (may contain echoed secrets).
	if strings.Contains(errStr, "bad config") {
		t.Errorf("error must NOT contain response body: %s", errStr)
	}
}

func TestFlyAPIErrorOmitsResponseBody(t *testing.T) {
	// Fly error responses can echo back parts of the submitted request, which
	// includes VM environment secrets (model API keys, invite codes). Verify
	// the error string never surfaces the response body. Build the fake
	// credential at runtime (gosec G101).
	fakeSecret := "AKIA" + "IOSFODNN7EXAMPLE"
	const wantRequestID = "req-trace-deadbeef"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(flyRequestIDHeader, wantRequestID)
		w.WriteHeader(http.StatusBadRequest)
		// Simulate Fly echoing back env secrets in the error response.
		_, _ = w.Write([]byte(`{"error":"invalid config","env":{"MODEL_KEY":"` + fakeSecret + `"}}`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	_, err := fly.CreateMachine(context.Background(), MachineSpec{Image: "img"})
	if err == nil {
		t.Fatal("want error on 400")
	}

	errStr := err.Error()

	// Must NOT contain the fake secret (response body content).
	if strings.Contains(errStr, fakeSecret) {
		t.Fatalf("error string contains response-body secret: %s", errStr)
	}
	if strings.Contains(errStr, "invalid config") {
		t.Fatalf("error string contains response-body text: %s", errStr)
	}

	// Must contain non-sensitive diagnostics: status, method, path, request-id.
	if !strings.Contains(errStr, "400") {
		t.Errorf("error missing HTTP status code: %s", errStr)
	}
	if !strings.Contains(errStr, http.MethodPost) {
		t.Errorf("error missing HTTP method: %s", errStr)
	}
	if !strings.Contains(errStr, "/apps/playground-pool/machines") {
		t.Errorf("error missing request path: %s", errStr)
	}
	if !strings.Contains(errStr, wantRequestID) {
		t.Errorf("error missing Fly-Request-Id: %s", errStr)
	}
}

func TestFlyAPIErrorWithoutRequestID(t *testing.T) {
	// When the Fly API does not return a request ID header, the error should
	// still be well-formed and contain status/method/path.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`internal error`))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	err := fly.WaitReady(context.Background(), "some-id")
	if err == nil {
		t.Fatal("want error on 500")
	}
	errStr := err.Error()
	if !strings.Contains(errStr, "500") {
		t.Errorf("error missing status code: %s", errStr)
	}
	if !strings.Contains(errStr, "/wait") {
		t.Errorf("error missing path: %s", errStr)
	}
	// Must not contain the response body.
	if strings.Contains(errStr, "internal error") {
		t.Errorf("error must not contain response body: %s", errStr)
	}
	// Must not contain "request-id" when header is absent.
	if strings.Contains(errStr, "request-id") {
		t.Errorf("error should omit request-id field when header is absent: %s", errStr)
	}
}

func TestFlyListManagedMachines(t *testing.T) {
	// Return a mix of machines: one tagged, one untagged, one with foreign
	// metadata. Only the tagged one should appear.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body := `[
			{
				"id": "m-tagged",
				"state": "started",
				"created_at": "2026-06-25T10:00:00Z",
				"config": {"metadata": {"pipelock_role": "playground-vm"}}
			},
			{
				"id": "m-untagged",
				"state": "started",
				"created_at": "2026-06-25T10:00:00Z",
				"config": {}
			},
			{
				"id": "m-foreign",
				"state": "started",
				"created_at": "2026-06-25T10:00:00Z",
				"config": {"metadata": {"pipelock_role": "something-else"}}
			},
			{
				"id": "m-no-metadata",
				"state": "started",
				"created_at": "",
				"config": {"metadata": null}
			}
		]`
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	machines, err := fly.ListManagedMachines(context.Background())
	if err != nil {
		t.Fatalf("ListManagedMachines: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("got %d machines, want 1 (only the tagged one)", len(machines))
	}
	if machines[0].ID != "m-tagged" {
		t.Errorf("machine ID = %q, want m-tagged", machines[0].ID)
	}
	if machines[0].State != "started" {
		t.Errorf("state = %q, want started", machines[0].State)
	}
	wantCreated := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	if !machines[0].CreatedAt.Equal(wantCreated) {
		t.Errorf("CreatedAt = %v, want %v", machines[0].CreatedAt, wantCreated)
	}
}

func TestFlyListManagedMachinesPagedObjectResponse(t *testing.T) {
	var cursors []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if got := r.URL.Query().Get("summary"); got != "true" {
			t.Fatalf("summary query = %q, want true", got)
		}
		if got := r.URL.Query().Get("limit"); got != "200" {
			t.Fatalf("limit query = %q, want 200", got)
		}
		cursor := r.URL.Query().Get("cursor")
		cursors = append(cursors, cursor)
		w.Header().Set("Content-Type", "application/json")
		switch cursor {
		case "":
			_, _ = w.Write([]byte(`{
				"machines": [
					{"id": "m-page-1", "state": "started", "created_at": "2026-06-25T10:00:00Z", "config": {"metadata": {"pipelock_role": "playground-vm"}}}
				],
				"response_metadata": {"next_cursor": "next-page"}
			}`))
		case "next-page":
			_, _ = w.Write([]byte(`{
				"machines": [
					{"id": "m-foreign", "state": "started", "created_at": "2026-06-25T10:00:00Z", "config": {"metadata": {"pipelock_role": "other"}}},
					{"id": "m-page-2", "state": "started", "created_at": "2026-06-25T10:01:00Z", "config": {"metadata": {"pipelock_role": "playground-vm"}}}
				]
			}`))
		default:
			t.Fatalf("unexpected cursor %q", cursor)
		}
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	machines, err := fly.ListManagedMachines(context.Background())
	if err != nil {
		t.Fatalf("ListManagedMachines: %v", err)
	}
	if len(cursors) != 2 || cursors[0] != "" || cursors[1] != "next-page" {
		t.Fatalf("cursors = %#v, want initial request then next-page", cursors)
	}
	if len(machines) != 2 {
		t.Fatalf("got %d managed machines, want 2", len(machines))
	}
	if machines[0].ID != "m-page-1" || machines[1].ID != "m-page-2" {
		t.Fatalf("machine IDs = %q, %q; want m-page-1, m-page-2", machines[0].ID, machines[1].ID)
	}
}

func TestFlyListManagedMachinesUnparseableCreatedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		body := `[{"id": "m1", "state": "started", "created_at": "not-a-date", "config": {"metadata": {"pipelock_role": "playground-vm"}}}]`
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	fly := newTestFly(srv)
	machines, err := fly.ListManagedMachines(context.Background())
	if err != nil {
		t.Fatalf("ListManagedMachines: %v", err)
	}
	if len(machines) != 1 {
		t.Fatalf("got %d machines, want 1", len(machines))
	}
	if !machines[0].CreatedAt.IsZero() {
		t.Errorf("CreatedAt should be zero for unparseable date, got %v", machines[0].CreatedAt)
	}
}

func TestFlyValidate(t *testing.T) {
	tests := []struct {
		name string
		fly  *FlyMachines
	}{
		{"no app", &FlyMachines{Token: "t"}},
		{"no token", &FlyMachines{AppName: "a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.fly.CreateMachine(context.Background(), MachineSpec{Image: "i"}); err == nil {
				t.Error("CreateMachine: want validation error")
			}
			if err := tt.fly.WaitReady(context.Background(), "x"); err == nil {
				t.Error("WaitReady: want validation error")
			}
			if err := tt.fly.DestroyMachine(context.Background(), "x"); err == nil {
				t.Error("DestroyMachine: want validation error")
			}
		})
	}
}
