// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// defaultFlyBaseURL is the Fly Machines API base. Override via FlyMachines.BaseURL
// in tests (httptest server).
const defaultFlyBaseURL = "https://api.machines.dev/v1"

// playgroundRoleKey and playgroundRoleVal are the metadata tag set on every
// per-visitor VM so the orphan reaper can distinguish them from the broker's own
// machine and unrelated infra. ListManagedMachines filters on this tag.
const (
	playgroundRoleKey = "pipelock_role"
	playgroundRoleVal = "playground-vm"
)

// defaultWaitTimeout bounds a single WaitReady call's server-side wait.
const defaultWaitTimeout = 60 * time.Second

// flyMaxBodyBytes caps how much of a Fly API response body is read, so a
// misbehaving/huge response cannot exhaust broker memory.
const flyMaxBodyBytes = 1 << 20 // 1 MiB

// flyListPageSize caps the per-page machine count in ListManagedMachines. It is
// kept well under the Fly API maximum so a full (non-summary) machine page stays
// under flyMaxBodyBytes even during a large orphan event; the cursor loop handles
// the extra pages. See ListManagedMachines for why summary mode is not used.
const flyListPageSize = 50

// flyRequestIDHeader is the Fly API response header that carries a per-request
// trace identifier. Including it in error messages lets operators debug failures
// with Fly support without exposing potentially secret response-body content.
const flyRequestIDHeader = "Fly-Request-Id"

// FlyMachines is the Fly Machines API adapter for MachineProvider. It leases one
// ephemeral, internal-only Firecracker microVM per visitor: the machine has no
// public service (the broker reaches it over the app's private 6PN network on
// the internal port), auto-destroys when it stops, and never restarts (a
// one-shot per-session VM). It holds the Fly API token; it is never exposed to a
// leased VM.
type FlyMachines struct {
	// AppName is the Fly app the per-visitor machines are created under.
	AppName string
	// Token is the Fly API token (Bearer). Required.
	Token string
	// BaseURL overrides the Machines API base (tests point this at httptest).
	// Empty uses defaultFlyBaseURL.
	BaseURL string
	// HTTP is the client used for API calls. Nil uses a client with a sane
	// timeout. The WaitReady call uses a longer per-request deadline via context.
	HTTP *http.Client
	// WaitTimeout bounds the server-side wait per WaitReady call. Zero uses
	// defaultWaitTimeout.
	WaitTimeout time.Duration
}

// machineConfig and friends mirror the Fly Machines API request/response JSON.
// Only the fields the broker sets/reads are modeled.
type flyGuest struct {
	CPUKind  string `json:"cpu_kind"`
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memory_mb"`
}

type flyRestart struct {
	Policy string `json:"policy"`
}

type flyMachineConfig struct {
	Image       string            `json:"image"`
	Env         map[string]string `json:"env,omitempty"`
	Guest       flyGuest          `json:"guest"`
	AutoDestroy bool              `json:"auto_destroy"`
	Restart     flyRestart        `json:"restart"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type flyCreateRequest struct {
	Config flyMachineConfig `json:"config"`
	Region string           `json:"region,omitempty"`
}

type flyMachineResponse struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	PrivateIP string `json:"private_ip"`
}

func (f *FlyMachines) baseURL() string {
	if f.BaseURL != "" {
		return strings.TrimRight(f.BaseURL, "/")
	}
	return defaultFlyBaseURL
}

func (f *FlyMachines) httpClient() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	timeout := 30 * time.Second
	if waitTimeout := f.waitTimeout() + 5*time.Second; waitTimeout > timeout {
		timeout = waitTimeout
	}
	return &http.Client{Timeout: timeout}
}

func (f *FlyMachines) waitTimeout() time.Duration {
	if f.WaitTimeout > 0 {
		return f.WaitTimeout
	}
	return defaultWaitTimeout
}

// CreateMachine provisions an internal-only, auto-destroying, no-restart microVM
// from spec.
func (f *FlyMachines) CreateMachine(ctx context.Context, spec MachineSpec) (*Machine, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(spec.Image) == "" {
		return nil, errors.New("fly: machine spec image is empty")
	}

	guest := flyGuest{CPUKind: "shared", CPUs: spec.CPUs, MemoryMB: spec.MemoryMB}
	if guest.CPUs <= 0 {
		guest.CPUs = 1
	}
	if guest.MemoryMB <= 0 {
		guest.MemoryMB = 512
	}
	reqBody := flyCreateRequest{
		Config: flyMachineConfig{
			Image: spec.Image,
			Env:   spec.Env,
			Guest: guest,
			// One-shot per-visitor VM: destroy it when its process stops, and
			// never restart it. The broker also force-destroys explicitly.
			AutoDestroy: true,
			Restart:     flyRestart{Policy: "no"},
			// Tag the VM so the orphan reaper can distinguish per-visitor VMs
			// from the broker's own machine and unrelated infra.
			Metadata: map[string]string{playgroundRoleKey: playgroundRoleVal},
		},
		Region: spec.Region,
	}

	path := fmt.Sprintf("/apps/%s/machines", url.PathEscape(f.AppName))
	respBody, err := f.do(ctx, http.MethodPost, path, nil, reqBody)
	if err != nil {
		return nil, err
	}
	var m flyMachineResponse
	if uerr := json.Unmarshal(respBody, &m); uerr != nil {
		return nil, fmt.Errorf("fly: parse create response: %w", uerr)
	}
	if m.ID == "" {
		return nil, errors.New("fly: create response missing machine id")
	}
	return &Machine{ID: m.ID, State: m.State, PrivateIP: m.PrivateIP}, nil
}

// WaitReady waits for the machine to reach the started state. The server-side
// wait is bounded by waitTimeout; the call also respects ctx cancellation.
func (f *FlyMachines) WaitReady(ctx context.Context, id string) error {
	if err := f.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("fly: WaitReady empty machine id")
	}
	q := url.Values{}
	q.Set("state", "started")
	q.Set("timeout", strconv.Itoa(int(f.waitTimeout().Seconds())))
	path := fmt.Sprintf("/apps/%s/machines/%s/wait", url.PathEscape(f.AppName), url.PathEscape(id))
	if _, err := f.do(ctx, http.MethodGet, path, q, nil); err != nil {
		return err
	}
	return nil
}

// DestroyMachine force-destroys the machine. It is idempotent: a 404 (already
// gone) is treated as success so teardown never wedges on a half-failed lease.
func (f *FlyMachines) DestroyMachine(ctx context.Context, id string) error {
	if err := f.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(id) == "" {
		return errors.New("fly: DestroyMachine empty machine id")
	}
	q := url.Values{}
	q.Set("force", "true")
	path := fmt.Sprintf("/apps/%s/machines/%s", url.PathEscape(f.AppName), url.PathEscape(id))
	_, err := f.do(ctx, http.MethodDelete, path, q, nil)
	if err != nil {
		var apiErr *apiError
		if errors.As(err, &apiErr) && apiErr.status == http.StatusNotFound {
			return nil // already gone
		}
		return err
	}
	return nil
}

// flyListMachine mirrors the Fly Machines API list-machines response fields that
// the broker reads. Only the fields needed for orphan reaping are modeled.
type flyListMachine struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
	Config    struct {
		Metadata map[string]string `json:"metadata"`
	} `json:"config"`
}

type flyListMachinesPage struct {
	Machines         []flyListMachine `json:"machines"`
	NextCursor       string           `json:"next_cursor"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// ListManagedMachines returns only per-visitor VMs (those tagged with
// pipelock_role == playground-vm). The broker's own machine and unrelated infra
// are excluded. A machine whose created_at is missing or unparseable gets a zero
// CreatedAt (the reaper treats zero as "unknown age, spare it").
func (f *FlyMachines) ListManagedMachines(ctx context.Context) ([]Machine, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	path := fmt.Sprintf("/apps/%s/machines", url.PathEscape(f.AppName))
	// Do NOT set summary=true: Fly's summary list response strips config.metadata
	// to null, and this reaper filters managed machines on the
	// pipelock_role=playground-vm metadata tag. With summary=true the filter drops
	// EVERY machine, ListManagedMachines returns empty, and the reaper silently
	// reaps nothing while per-visitor VMs accumulate forever (observed live:
	// 14 orphaned VMs after a week). The full list response carries both
	// config.metadata and created_at, which the reaper's tag filter and grace
	// check require.
	//
	// Page size is kept modest (not the API max): full machine objects are
	// larger than summary rows, and the response body is capped at flyMaxBodyBytes
	// (1 MiB) in do(). A too-large page could exceed that cap during a large
	// orphan event, fail to parse, and stall cleanup exactly when it matters most.
	// More pages of a bounded size is the safer trade; the cursor loop below
	// handles pagination.
	query := url.Values{"limit": []string{strconv.Itoa(flyListPageSize)}}
	var raw []flyListMachine
	for {
		respBody, err := f.do(ctx, http.MethodGet, path, query, nil)
		if err != nil {
			return nil, err
		}
		page, next, err := parseFlyListMachines(respBody)
		if err != nil {
			return nil, err
		}
		raw = append(raw, page...)
		if next == "" {
			break
		}
		query.Set("cursor", next)
	}
	var managed []Machine
	for _, m := range raw {
		if m.Config.Metadata[playgroundRoleKey] != playgroundRoleVal {
			continue
		}
		created, _ := time.Parse(time.RFC3339, m.CreatedAt)
		managed = append(managed, Machine{
			ID:        m.ID,
			State:     m.State,
			CreatedAt: created,
		})
	}
	return managed, nil
}

func parseFlyListMachines(respBody []byte) ([]flyListMachine, string, error) {
	var raw []flyListMachine
	if err := json.Unmarshal(respBody, &raw); err == nil {
		return raw, "", nil
	}
	var page flyListMachinesPage
	if err := json.Unmarshal(respBody, &page); err != nil {
		return nil, "", fmt.Errorf("fly: parse list machines response: %w", err)
	}
	next := strings.TrimSpace(page.NextCursor)
	if next == "" {
		next = strings.TrimSpace(page.ResponseMetadata.NextCursor)
	}
	return page.Machines, next, nil
}

func (f *FlyMachines) validate() error {
	if strings.TrimSpace(f.AppName) == "" {
		return errors.New("fly: AppName is empty")
	}
	if strings.TrimSpace(f.Token) == "" {
		return errors.New("fly: Token is empty")
	}
	return nil
}

// apiError carries a non-2xx Fly API response for typed handling (e.g. 404 on
// destroy is status-based). The response body is deliberately excluded: Fly
// error responses can echo back parts of the submitted request, which may
// contain VM environment secrets (model API keys, invite codes, etc.). Only
// non-sensitive diagnostics (status, method, path, request ID) are surfaced.
type apiError struct {
	status    int
	method    string
	path      string
	requestID string // Fly-Request-Id header for operator debugging
}

func (e *apiError) Error() string {
	if e.requestID != "" {
		return fmt.Sprintf("fly: %s %s: HTTP %d (request-id: %s)", e.method, e.path, e.status, e.requestID)
	}
	return fmt.Sprintf("fly: %s %s: HTTP %d", e.method, e.path, e.status)
}

// do performs a Fly API request and returns the response body for 2xx, or an
// *apiError for non-2xx. body is JSON-encoded when non-nil.
func (f *FlyMachines) do(ctx context.Context, method, path string, query url.Values, body any) ([]byte, error) {
	u := f.baseURL() + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("fly: marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, fmt.Errorf("fly: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.Token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fly: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, flyMaxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("fly: read %s %s response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &apiError{
			status:    resp.StatusCode,
			method:    method,
			path:      path,
			requestID: resp.Header.Get(flyRequestIDHeader),
		}
	}
	return respBody, nil
}
