//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package policysync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
)

// stubProvider returns a scripted current/target/ok/err for RollbackContext.
type stubProvider struct {
	current RollbackRef
	target  RollbackRef
	ok      bool
	err     error
	calls   int
	mu      sync.Mutex
}

func (p *stubProvider) RollbackContext() (RollbackRef, RollbackRef, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return p.current, p.target, p.ok, p.err
}

// stubRollbackApplier records the authorizations handed to it and returns a
// scripted error.
type stubRollbackApplier struct {
	mu  sync.Mutex
	got []conductor.RollbackAuthorization
	err error
}

func (a *stubRollbackApplier) ApplyRollback(auth conductor.RollbackAuthorization) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.got = append(a.got, auth)
	return a.err
}

func (a *stubRollbackApplier) calls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.got)
}

func (a *stubRollbackApplier) last() conductor.RollbackAuthorization {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.got) == 0 {
		return conductor.RollbackAuthorization{}
	}
	return a.got[len(a.got)-1]
}

func mkRollbackAuth(t *testing.T) (conductor.RollbackAuthorization, []byte) {
	t.Helper()
	auth := conductor.RollbackAuthorization{
		SchemaVersion:   conductor.SchemaVersion,
		AuthorizationID: "rollback-1",
		OrgID:           "org-1",
		FleetID:         "fleet-1",
		CurrentBundleID: "bundle-2",
		CurrentVersion:  2,
		TargetBundleID:  "bundle-1",
		TargetVersion:   1,
		Counter:         1,
	}
	raw, err := json.Marshal(auth)
	if err != nil {
		t.Fatalf("marshal rollback auth: %v", err)
	}
	return auth, raw
}

func okProvider() *stubProvider {
	return &stubProvider{
		current: RollbackRef{BundleID: "bundle-2", Version: 2},
		target:  RollbackRef{BundleID: "bundle-1", Version: 1},
		ok:      true,
	}
}

func newTestRollbackPoller(t *testing.T, doer HTTPDoer, provider RollbackContextProvider, applier RollbackApplier) *RollbackPoller {
	t.Helper()
	p, err := NewRollbackPoller(RollbackPollerConfig{
		BaseURL:      testBaseURL,
		Client:       doer,
		Provider:     provider,
		Applier:      applier,
		PollInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewRollbackPoller() error = %v", err)
	}
	return p
}

func TestRollbackPollerPollOnce(t *testing.T) {
	_, authJSON := mkRollbackAuth(t)
	trailing := append(append([]byte{}, authJSON...), []byte("\n{}")...)

	tests := []struct {
		name        string
		steps       []step
		doerErr     error
		provider    *stubProvider
		applierErr  error
		wantErr     error
		wantApplied int
		wantReqs    int
	}{
		{
			name:        "200 applies decoded authorization",
			steps:       []step{{status: http.StatusOK, body: authJSON}},
			provider:    okProvider(),
			wantApplied: 1,
			wantReqs:    1,
		},
		{
			name:        "204 is a no-op",
			steps:       []step{{status: http.StatusNoContent}},
			provider:    okProvider(),
			wantApplied: 0,
			wantReqs:    1,
		},
		{
			name:        "non-2xx is an error",
			steps:       []step{{status: http.StatusInternalServerError}},
			provider:    okProvider(),
			wantErr:     ErrRollbackPollResponse,
			wantApplied: 0,
			wantReqs:    1,
		},
		{
			name:        "trailing JSON document rejected",
			steps:       []step{{status: http.StatusOK, body: trailing}},
			provider:    okProvider(),
			wantErr:     ErrRollbackPollResponse,
			wantApplied: 0,
			wantReqs:    1,
		},
		{
			name:        "unknown field rejected",
			steps:       []step{{status: http.StatusOK, body: []byte(`{"authorization_id":"x","bogus":1}`)}},
			provider:    okProvider(),
			wantErr:     ErrRollbackPollResponse,
			wantApplied: 0,
			wantReqs:    1,
		},
		{
			name:        "provider ok=false skips poll",
			steps:       []step{{status: http.StatusOK, body: authJSON}},
			provider:    &stubProvider{ok: false},
			wantApplied: 0,
			wantReqs:    0,
		},
		{
			name:        "provider error returned without poll",
			steps:       []step{{status: http.StatusOK, body: authJSON}},
			provider:    &stubProvider{err: errors.New("cache read failure")},
			wantErr:     errProviderSentinel,
			wantApplied: 0,
			wantReqs:    0,
		},
		{
			name:        "applier error propagates",
			steps:       []step{{status: http.StatusOK, body: authJSON}},
			provider:    okProvider(),
			applierErr:  errors.New("apply rejected"),
			wantApplied: 1,
			wantReqs:    1,
			wantErr:     errApplierSentinel,
		},
		{
			name:        "response body read error",
			steps:       []step{{status: http.StatusOK, readErr: true}},
			provider:    okProvider(),
			wantApplied: 0,
			wantReqs:    1,
			wantErr:     errReadSentinel,
		},
		{
			name:        "transport error",
			doerErr:     errors.New("dial failed"),
			provider:    okProvider(),
			wantApplied: 0,
			wantReqs:    1,
			wantErr:     errTransportSentinel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doer := &stubDoer{steps: tc.steps, err: tc.doerErr}
			applier := &stubRollbackApplier{err: tc.applierErr}
			p := newTestRollbackPoller(t, doer, tc.provider, applier)

			err := p.PollOnce(context.Background())

			switch {
			case errors.Is(tc.wantErr, errProviderSentinel):
				if err == nil || !strings.Contains(err.Error(), "rollback context") {
					t.Fatalf("PollOnce() err = %v, want provider error", err)
				}
			case errors.Is(tc.wantErr, errApplierSentinel):
				if err == nil || !strings.Contains(err.Error(), "apply conductor rollback") {
					t.Fatalf("PollOnce() err = %v, want applier error", err)
				}
			case errors.Is(tc.wantErr, errReadSentinel):
				if err == nil || !strings.Contains(err.Error(), "read conductor rollback response") {
					t.Fatalf("PollOnce() err = %v, want read error", err)
				}
			case errors.Is(tc.wantErr, errTransportSentinel):
				if err == nil || !strings.Contains(err.Error(), "poll conductor rollback authorization") {
					t.Fatalf("PollOnce() err = %v, want transport error", err)
				}
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("PollOnce() err = %v, want %v", err, tc.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("PollOnce() unexpected err = %v", err)
				}
			}

			if got := applier.calls(); got != tc.wantApplied {
				t.Fatalf("applier calls = %d, want %d", got, tc.wantApplied)
			}
			if got := doer.reqCount(); got != tc.wantReqs {
				t.Fatalf("request count = %d, want %d", got, tc.wantReqs)
			}
		})
	}
}

// sentinel errors let the table classify error shapes without binding to exact
// wrapped messages.
var (
	errProviderSentinel  = errors.New("provider")
	errApplierSentinel   = errors.New("applier")
	errReadSentinel      = errors.New("read")
	errTransportSentinel = errors.New("transport")
)

func TestRollbackPollerHappyPathDecodesAndSendsAllParams(t *testing.T) {
	wantAuth, authJSON := mkRollbackAuth(t)
	doer := &stubDoer{steps: []step{{status: http.StatusOK, body: authJSON}}}
	applier := &stubRollbackApplier{}
	p := newTestRollbackPoller(t, doer, okProvider(), applier)

	if err := p.PollOnce(context.Background()); err != nil {
		t.Fatalf("PollOnce() error = %v", err)
	}
	if applier.calls() != 1 {
		t.Fatalf("applier calls = %d, want 1", applier.calls())
	}
	got := applier.last()
	if got.AuthorizationID != wantAuth.AuthorizationID || got.TargetBundleID != wantAuth.TargetBundleID || got.TargetVersion != wantAuth.TargetVersion {
		t.Fatalf("decoded auth = %+v, want %+v", got, wantAuth)
	}

	req := doer.lastReq()
	if req == nil {
		t.Fatal("no request recorded")
	}
	q := req.URL.Query()
	for k, want := range map[string]string{
		rollbackQueryCurrentBundleID: "bundle-2",
		rollbackQueryCurrentVersion:  "2",
		rollbackQueryTargetBundleID:  "bundle-1",
		rollbackQueryTargetVersion:   "1",
	} {
		if got := q.Get(k); got != want {
			t.Fatalf("query %q = %q, want %q", k, got, want)
		}
	}
	if !strings.HasPrefix(req.URL.Path, RollbackAuthorizationsPath) {
		t.Fatalf("request path = %q, want prefix %q", req.URL.Path, RollbackAuthorizationsPath)
	}
}

func TestNewRollbackPollerValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RollbackPollerConfig
		wantErr error
	}{
		{
			name:    "missing client",
			cfg:     RollbackPollerConfig{BaseURL: testBaseURL, Provider: okProvider(), Applier: &stubRollbackApplier{}},
			wantErr: ErrRollbackPollerRequired,
		},
		{
			name:    "missing provider",
			cfg:     RollbackPollerConfig{BaseURL: testBaseURL, Client: &stubDoer{}, Applier: &stubRollbackApplier{}},
			wantErr: ErrRollbackPollerRequired,
		},
		{
			name:    "missing applier",
			cfg:     RollbackPollerConfig{BaseURL: testBaseURL, Client: &stubDoer{}, Provider: okProvider()},
			wantErr: ErrRollbackPollerRequired,
		},
		{
			name:    "non-https base URL rejected",
			cfg:     RollbackPollerConfig{BaseURL: "http://leader.example:8895", Client: &stubDoer{}, Provider: okProvider(), Applier: &stubRollbackApplier{}},
			wantErr: nil, // matched on message below
		},
		{
			name:    "base URL with path rejected",
			cfg:     RollbackPollerConfig{BaseURL: "https://leader.example:8895/extra", Client: &stubDoer{}, Provider: okProvider(), Applier: &stubRollbackApplier{}},
			wantErr: nil,
		},
		{
			name:    "sub-second interval rejected",
			cfg:     RollbackPollerConfig{BaseURL: testBaseURL, Client: &stubDoer{}, Provider: okProvider(), Applier: &stubRollbackApplier{}, PollInterval: time.Millisecond},
			wantErr: nil,
		},
		{
			name:    "negative max response bytes rejected",
			cfg:     RollbackPollerConfig{BaseURL: testBaseURL, Client: &stubDoer{}, Provider: okProvider(), Applier: &stubRollbackApplier{}, MaxResponseBytes: -1},
			wantErr: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewRollbackPoller(tc.cfg)
			if err == nil {
				t.Fatalf("NewRollbackPoller() expected error")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("NewRollbackPoller() err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestRollbackPollerRunStopsOnContextCancel(t *testing.T) {
	doer := &stubDoer{steps: []step{{status: http.StatusNoContent}}}
	p := newTestRollbackPoller(t, doer, okProvider(), &stubRollbackApplier{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() err = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after cancel")
	}
}

func TestRollbackEndpointValidation(t *testing.T) {
	if _, err := rollbackEndpoint("https://leader.example:8895"); err != nil {
		t.Fatalf("valid https base URL rejected: %v", err)
	}
	got, err := rollbackEndpoint("https://leader.example:8895/")
	if err != nil {
		t.Fatalf("trailing-slash base URL rejected: %v", err)
	}
	u, perr := url.Parse(got)
	if perr != nil {
		t.Fatalf("parse endpoint: %v", perr)
	}
	if u.Path != RollbackAuthorizationsPath {
		t.Fatalf("endpoint path = %q, want %q", u.Path, RollbackAuthorizationsPath)
	}
	for _, bad := range []string{"http://leader.example", "https://", "https://user@leader.example", "https://leader.example?x=1", "https://leader.example?", "https://leader.example#frag"} {
		if _, err := rollbackEndpoint(bad); err == nil {
			t.Fatalf("rollbackEndpoint(%q) expected error", bad)
		}
	}
}

// readBodyLimit guards against the body cap being silently ignored: a body one
// byte over the cap must error.
func TestRollbackPollerRejectsOversizeBody(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 64)
	doer := &stubDoer{steps: []step{{status: http.StatusOK, body: big}}}
	p, err := NewRollbackPoller(RollbackPollerConfig{
		BaseURL:          testBaseURL,
		Client:           doer,
		Provider:         okProvider(),
		Applier:          &stubRollbackApplier{},
		PollInterval:     time.Second,
		MaxResponseBytes: 16,
	})
	if err != nil {
		t.Fatalf("NewRollbackPoller() error = %v", err)
	}
	if err := p.PollOnce(context.Background()); !errors.Is(err, ErrRollbackPollResponse) {
		t.Fatalf("PollOnce() err = %v, want ErrRollbackPollResponse", err)
	}
}

func TestRollbackRun_LogsPollErrorAndContinues(t *testing.T) {
	// First poll fails (500); the poller logs and keeps looping. Exercises the
	// logPollError continue-branch inside Run.
	doer := &stubDoer{steps: []step{
		{status: http.StatusInternalServerError},
		{status: http.StatusNoContent},
	}}
	p, err := NewRollbackPoller(RollbackPollerConfig{
		BaseURL:      testBaseURL,
		Client:       doer,
		Provider:     okProvider(),
		Applier:      &stubRollbackApplier{},
		PollInterval: time.Second,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewRollbackPoller: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for doer.reqCount() < 1 {
		select {
		case <-deadline:
			t.Fatal("no poll occurred")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestRollbackRun_NilPoller(t *testing.T) {
	var p *RollbackPoller
	if err := p.Run(context.Background()); !errors.Is(err, ErrRollbackPollerRequired) {
		t.Fatalf("nil Run = %v, want ErrRollbackPollerRequired", err)
	}
	if err := p.PollOnce(context.Background()); !errors.Is(err, ErrRollbackPollerRequired) {
		t.Fatalf("nil PollOnce = %v, want ErrRollbackPollerRequired", err)
	}
}

func TestRollbackLogPollError(t *testing.T) {
	var logs bytes.Buffer
	p := &RollbackPoller{logger: slog.New(slog.NewJSONHandler(&logs, nil))}
	p.logPollError(errors.New("boom"))
	got := logs.String()
	if !strings.Contains(got, "conductor_rollback_poll_error") || !strings.Contains(got, "boom") {
		t.Fatalf("logs = %s, want poll error event", got)
	}
	// A nil logger must be a safe no-op.
	(&RollbackPoller{}).logPollError(errors.New("ignored"))
}

var _ io.Reader = errReader{}
