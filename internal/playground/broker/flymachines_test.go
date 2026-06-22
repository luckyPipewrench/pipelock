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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	if !strings.Contains(err.Error(), "bad config") {
		t.Errorf("error should carry body: %v", err)
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
