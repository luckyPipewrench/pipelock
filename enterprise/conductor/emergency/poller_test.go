//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

type fakeRemoteKillClient struct {
	status  int
	body    string
	request *http.Request
	err     error
}

func (f *fakeRemoteKillClient) Do(req *http.Request) (*http.Response, error) {
	f.request = req
	if f.err != nil {
		return nil, f.err
	}
	return &http.Response{
		StatusCode: f.status,
		Body:       io.NopCloser(strings.NewReader(f.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestRemoteKillPollerAppliesMessage(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal(msg): %v", err)
	}
	ks := &captureKillSwitch{}
	client := &fakeRemoteKillClient{status: http.StatusOK, body: string(body)}
	poller := newTestRemoteKillPoller(t, client, resolver, ks)

	if err := poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if client.request == nil {
		t.Fatal("client request = nil")
	}
	if got := client.request.URL.Path; got != RemoteKillPath {
		t.Fatalf("request path = %q, want %q", got, RemoteKillPath)
	}
	if got := client.request.Method; got != http.MethodGet {
		t.Fatalf("request method = %q, want GET", got)
	}
	if got := client.request.Header.Get("Accept"); got != remoteKillPollerAcceptedCT {
		t.Fatalf("Accept = %q, want %q", got, remoteKillPollerAcceptedCT)
	}
	if !ks.active || ks.message != msg.Reason {
		t.Fatalf("kill switch = active=%v message=%q, want applied active message", ks.active, ks.message)
	}
}

func TestRemoteKillPollerNoContentIsNoop(t *testing.T) {
	_, resolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	ks := &captureKillSwitch{}
	poller := newTestRemoteKillPoller(t, &fakeRemoteKillClient{status: http.StatusNoContent}, resolver, ks)

	if err := poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce(204) error = %v", err)
	}
	if ks.active || ks.message != "" {
		t.Fatalf("kill switch changed on 204: active=%v message=%q", ks.active, ks.message)
	}
}

func TestRemoteKillPollerRejectsBadResponses(t *testing.T) {
	_, resolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	tests := []struct {
		name    string
		status  int
		body    string
		maxBody int64
		want    string
	}{
		{name: "non_200", status: http.StatusForbidden, want: "status=403"},
		{name: "bad_json", status: http.StatusOK, body: "{", want: "decode"},
		{name: "trailing_json", status: http.StatusOK, body: `{"schema_version":1}{}`, want: "trailing JSON document"},
		{name: "too_large", status: http.StatusOK, body: strings.Repeat("x", 9), maxBody: 8, want: "body exceeds"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			poller := newTestRemoteKillPoller(t, &fakeRemoteKillClient{status: tc.status, body: tc.body}, resolver, &captureKillSwitch{})
			if tc.maxBody > 0 {
				poller.maxResponseBytes = tc.maxBody
			}
			err := poller.PollOnce(t.Context())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("PollOnce() error = %v, want substring %q", err, tc.want)
			}
			if !errors.Is(err, ErrRemoteKillPollResponse) && tc.status != http.StatusOK {
				t.Fatalf("PollOnce() error = %v, want ErrRemoteKillPollResponse", err)
			}
		})
	}
}

func TestNewRemoteKillPollerValidationAndDefaults(t *testing.T) {
	applier := &RemoteKillApplier{}
	client := &fakeRemoteKillClient{status: http.StatusNoContent}
	poller, err := NewRemoteKillPoller(RemoteKillPollerConfig{
		BaseURL: "https://conductor.example",
		Client:  client,
		Applier: applier,
	})
	if err != nil {
		t.Fatalf("NewRemoteKillPoller(defaults) error = %v", err)
	}
	if poller.pollInterval != defaultRemoteKillPollInterval {
		t.Fatalf("pollInterval = %s, want %s", poller.pollInterval, defaultRemoteKillPollInterval)
	}
	if poller.maxResponseBytes != defaultRemoteKillResponseBytes {
		t.Fatalf("maxResponseBytes = %d, want %d", poller.maxResponseBytes, defaultRemoteKillResponseBytes)
	}

	tests := []struct {
		name         string
		cfg          RemoteKillPollerConfig
		want         string
		wantRequired bool
	}{
		{name: "nil_client", cfg: RemoteKillPollerConfig{BaseURL: "https://conductor.example", Applier: applier}, want: "HTTP client", wantRequired: true},
		{name: "nil_applier", cfg: RemoteKillPollerConfig{BaseURL: "https://conductor.example", Client: client}, want: "applier", wantRequired: true},
		{name: "short_interval", cfg: RemoteKillPollerConfig{BaseURL: "https://conductor.example", Client: client, Applier: applier, PollInterval: time.Millisecond}, want: "poll interval"},
		{name: "negative_max_response", cfg: RemoteKillPollerConfig{BaseURL: "https://conductor.example", Client: client, Applier: applier, MaxResponseBytes: -1}, want: "max response bytes"},
		{name: "bad_url_parse", cfg: RemoteKillPollerConfig{BaseURL: "://bad", Client: client, Applier: applier}, want: "parse conductor remote kill base URL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRemoteKillPoller(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewRemoteKillPoller() error = %v, want substring %q", err, tc.want)
			}
			if tc.wantRequired && !errors.Is(err, ErrRemoteKillPollerRequired) {
				t.Fatalf("NewRemoteKillPoller() error = %v, want ErrRemoteKillPollerRequired", err)
			}
		})
	}
}

func TestRemoteKillPollerEndpointValidation(t *testing.T) {
	msg, resolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	applier := &RemoteKillApplier{
		OrgID:      msg.OrgID,
		FleetID:    msg.FleetID,
		InstanceID: "pl-prod-1",
		Resolver:   resolver,
		KillSwitch: &captureKillSwitch{},
		StatePath:  filepath.Join(t.TempDir(), "state.json"),
		Now:        func() time.Time { return testNow },
	}
	tests := []struct {
		name string
		base string
		ok   bool
	}{
		{name: "valid", base: "https://conductor.example", ok: true},
		{name: "valid_slash", base: "https://conductor.example/", ok: true},
		{name: "http", base: "http://conductor.example"},
		{name: "path", base: "https://conductor.example/base"},
		{name: "query", base: "https://conductor.example?debug=true"},
		{name: "userinfo", base: "https://user@conductor.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			poller, err := NewRemoteKillPoller(RemoteKillPollerConfig{
				BaseURL:      tc.base,
				Client:       &fakeRemoteKillClient{status: http.StatusNoContent},
				Applier:      applier,
				PollInterval: time.Second,
			})
			if tc.ok {
				if err != nil {
					t.Fatalf("NewRemoteKillPoller() error = %v", err)
				}
				if poller.endpoint != "https://conductor.example"+RemoteKillPath {
					t.Fatalf("endpoint = %q", poller.endpoint)
				}
				return
			}
			if err == nil {
				t.Fatal("NewRemoteKillPoller() error = nil, want error")
			}
		})
	}
}

func TestRemoteKillPollerNilAndRequestErrors(t *testing.T) {
	var nilPoller *RemoteKillPoller
	if err := nilPoller.Run(t.Context()); !errors.Is(err, ErrRemoteKillPollerRequired) {
		t.Fatalf("Run(nil) error = %v, want ErrRemoteKillPollerRequired", err)
	}
	if err := nilPoller.PollOnce(t.Context()); !errors.Is(err, ErrRemoteKillPollerRequired) {
		t.Fatalf("PollOnce(nil) error = %v, want ErrRemoteKillPollerRequired", err)
	}
	poller := &RemoteKillPoller{
		client:           &fakeRemoteKillClient{status: http.StatusNoContent},
		applier:          &RemoteKillApplier{},
		endpoint:         "http://[::1",
		pollInterval:     time.Second,
		maxResponseBytes: defaultRemoteKillResponseBytes,
	}
	if err := poller.PollOnce(t.Context()); err == nil || !strings.Contains(err.Error(), "create conductor remote kill poll request") {
		t.Fatalf("PollOnce(bad endpoint) error = %v, want request creation error", err)
	}
}

func TestRemoteKillPollerLogsErrors(t *testing.T) {
	var logs bytes.Buffer
	poller := &RemoteKillPoller{
		logger: slog.New(slog.NewJSONHandler(&logs, nil)),
	}
	poller.logPollError(errors.New("boom"))
	if !strings.Contains(logs.String(), "conductor_remote_kill_poll_error") || !strings.Contains(logs.String(), "boom") {
		t.Fatalf("logs = %s, want poll error event", logs.String())
	}
}

type retryDeadlineRemoteKillClient struct {
	cancel context.CancelFunc
	calls  int
}

func (c *retryDeadlineRemoteKillClient) Do(req *http.Request) (*http.Response, error) {
	c.calls++
	if c.calls == 1 {
		return nil, context.DeadlineExceeded
	}
	c.cancel()
	return &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestRemoteKillPollerRetriesTransientDeadlineExceeded(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	client := &retryDeadlineRemoteKillClient{cancel: cancel}
	poller := &RemoteKillPoller{
		client:           client,
		applier:          &RemoteKillApplier{},
		endpoint:         "https://conductor.example" + RemoteKillPath,
		pollInterval:     time.Millisecond,
		maxResponseBytes: defaultRemoteKillResponseBytes,
	}

	err := poller.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if client.calls < 2 {
		t.Fatalf("client calls = %d, want retry after transient deadline", client.calls)
	}
}

func TestRemoteKillPollerRunStopsOnContextCancel(t *testing.T) {
	_, resolver := signedRemoteKill(t, 11, conductor.KillSwitchActive)
	poller := newTestRemoteKillPoller(t, &fakeRemoteKillClient{status: http.StatusNoContent}, resolver, &captureKillSwitch{})
	poller.pollInterval = time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- poller.Run(ctx)
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not stop after context cancel")
	}
}

func newTestRemoteKillPoller(t *testing.T, client HTTPDoer, resolver conductor.SignatureKeyResolver, ks *captureKillSwitch) *RemoteKillPoller {
	t.Helper()
	poller, err := NewRemoteKillPoller(RemoteKillPollerConfig{
		BaseURL: "https://conductor.example",
		Client:  client,
		Applier: &RemoteKillApplier{
			OrgID:      "org-main",
			FleetID:    "prod",
			InstanceID: "pl-prod-1",
			Resolver:   resolver,
			KillSwitch: ks,
			StatePath:  filepath.Join(t.TempDir(), "state.json"),
			Now:        func() time.Time { return testNow },
		},
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewRemoteKillPoller() error = %v", err)
	}
	return poller
}
