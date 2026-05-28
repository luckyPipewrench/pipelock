//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

func TestNegotiateCapabilities(t *testing.T) {
	resp := validHandshakeCapabilitiesResponse()
	resp.MaxCreatedSkewSeconds = 120

	got, err := NegotiateCapabilities(resp, LocalFollowerCapabilities{
		MaxCreatedSkew:  60 * time.Second,
		MaxThreshold:    3,
		EmergencyStream: true,
	})
	if err != nil {
		t.Fatalf("NegotiateCapabilities() error = %v", err)
	}
	if got.ConductorID != resp.ConductorID {
		t.Fatalf("ConductorID = %q, want %q", got.ConductorID, resp.ConductorID)
	}
	if got.SchemaVersion != SchemaVersion {
		t.Fatalf("SchemaVersion = %d, want %d", got.SchemaVersion, SchemaVersion)
	}
	if got.AuditSchemaVersion != SchemaVersion {
		t.Fatalf("AuditSchemaVersion = %d, want %d", got.AuditSchemaVersion, SchemaVersion)
	}
	if got.CreatedSkew != 60*time.Second {
		t.Fatalf("CreatedSkew = %s, want 60s", got.CreatedSkew)
	}
	if !got.EmergencyStream {
		t.Fatal("EmergencyStream = false, want true")
	}
}

func TestNegotiateCapabilitiesRejectsAboveLocalThresholdCap(t *testing.T) {
	resp := validHandshakeCapabilitiesResponse()
	resp.RemoteKillThreshold = 4

	_, err := NegotiateCapabilities(resp, LocalFollowerCapabilities{MaxThreshold: 3})
	if !errors.Is(err, ErrCapabilityNegotiation) {
		t.Fatalf("NegotiateCapabilities() = %v, want ErrCapabilityNegotiation", err)
	}
	if !errors.Is(err, ErrThresholdRequired) {
		t.Fatalf("NegotiateCapabilities() = %v, want ErrThresholdRequired", err)
	}
}

func TestCapabilitiesClientHandshake(t *testing.T) {
	resp := validHandshakeCapabilitiesResponse()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != CapabilitiesPath {
			t.Errorf("path = %q, want %q", r.URL.Path, CapabilitiesPath)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	client, err := NewCapabilitiesClient(srv.URL, srv.Client(), LocalFollowerCapabilities{EmergencyStream: true})
	if err != nil {
		t.Fatalf("NewCapabilitiesClient() error = %v", err)
	}
	got, err := client.Handshake(context.Background())
	if err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}
	if got.ConductorID != resp.ConductorID {
		t.Fatalf("ConductorID = %q, want %q", got.ConductorID, resp.ConductorID)
	}
}

func TestNewCapabilitiesClientRejectsNilHTTPClient(t *testing.T) {
	_, err := NewCapabilitiesClient("https://conductor.example", nil, LocalFollowerCapabilities{})
	if !errors.Is(err, ErrCapabilityNegotiation) {
		t.Fatalf("NewCapabilitiesClient() = %v, want ErrCapabilityNegotiation", err)
	}
}

func TestCapabilitiesClientHandshakeAddsDeadline(t *testing.T) {
	resp := validHandshakeCapabilitiesResponse()
	httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if _, ok := req.Context().Deadline(); !ok {
			t.Fatal("request context has no deadline")
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(mustJSON(t, resp))),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})}
	client, err := NewCapabilitiesClient("https://conductor.example", httpClient, LocalFollowerCapabilities{})
	if err != nil {
		t.Fatalf("NewCapabilitiesClient() error = %v", err)
	}
	if _, err := client.Handshake(context.Background()); err != nil {
		t.Fatalf("Handshake() error = %v", err)
	}
}

func TestCapabilitiesClientHandshakeRejectsZeroValueClient(t *testing.T) {
	_, err := new(CapabilitiesClient).Handshake(context.Background())
	if !errors.Is(err, ErrCapabilityNegotiation) {
		t.Fatalf("Handshake() = %v, want ErrCapabilityNegotiation", err)
	}
}

func TestCapabilitiesClientRejectsUnsafeBaseURL(t *testing.T) {
	httpClient := &http.Client{Timeout: defaultCapabilitiesTimeout}
	for _, raw := range []string{
		"http://conductor.example",
		"https://user:pass@conductor.example",
		"https://conductor.example?token=x",
		"https://conductor.example#fragment",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := NewCapabilitiesClient(raw, httpClient, LocalFollowerCapabilities{})
			if !errors.Is(err, ErrCapabilityNegotiation) {
				t.Fatalf("NewCapabilitiesClient() = %v, want ErrCapabilityNegotiation", err)
			}
		})
	}
}

func TestCapabilitiesClientRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non_200", status: http.StatusForbidden, body: "nope"},
		{name: "unknown_field", status: http.StatusOK, body: `{"schema_version":1,"unexpected":true}`},
		{name: "trailing_document", status: http.StatusOK, body: mustJSON(t, validHandshakeCapabilitiesResponse()) + `{}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			client, err := NewCapabilitiesClient(srv.URL, srv.Client(), LocalFollowerCapabilities{})
			if err != nil {
				t.Fatalf("NewCapabilitiesClient() error = %v", err)
			}
			_, err = client.Handshake(context.Background())
			if !errors.Is(err, ErrCapabilityNegotiation) {
				t.Fatalf("Handshake() = %v, want ErrCapabilityNegotiation", err)
			}
		})
	}
}

func TestNegotiateCapabilitiesCapsAuditSchemaAtFollowerSupported(t *testing.T) {
	// Conductor advertises a forward-compat audit envelope range that exceeds
	// what the follower can produce. The negotiated AuditSchemaVersion must
	// equal the local SchemaVersion constant, not the server-advertised max,
	// otherwise the audit batcher (next PR) will emit envelopes claiming a
	// schema version it cannot actually produce.
	resp := validHandshakeCapabilitiesResponse()
	resp.AuditBatch = SchemaRange{Min: SchemaVersion, Max: SchemaVersion + 5}

	got, err := NegotiateCapabilities(resp, LocalFollowerCapabilities{})
	if err != nil {
		t.Fatalf("NegotiateCapabilities() error = %v", err)
	}
	if got.AuditSchemaVersion != SchemaVersion {
		t.Fatalf("AuditSchemaVersion = %d, want %d (capped at local supported)", got.AuditSchemaVersion, SchemaVersion)
	}
}

func TestCapabilitiesClientRejectsBaseURLWithPath(t *testing.T) {
	for _, raw := range []string{
		"https://conductor.example/admin",
		"https://conductor.example/api/v1/conductor/capabilities",
		"https://conductor.example/a/b/c",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := NewCapabilitiesClient(raw, &http.Client{Timeout: defaultCapabilitiesTimeout}, LocalFollowerCapabilities{})
			if !errors.Is(err, ErrCapabilityNegotiation) {
				t.Fatalf("NewCapabilitiesClient() = %v, want ErrCapabilityNegotiation", err)
			}
		})
	}
	// Bare path component "/" is still allowed (matches the no-path case).
	if _, err := NewCapabilitiesClient("https://conductor.example/", &http.Client{Timeout: defaultCapabilitiesTimeout}, LocalFollowerCapabilities{}); err != nil {
		t.Fatalf("NewCapabilitiesClient(trailing slash) = %v, want nil", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func validHandshakeCapabilitiesResponse() CapabilitiesResponse {
	r := SchemaRange{Min: SchemaVersion, Max: SchemaVersion}
	return CapabilitiesResponse{
		SchemaVersion:          SchemaVersion,
		ConductorID:            "conductor-us-1",
		RequiredMTLS:           true,
		ConductorBundle:        r,
		RemoteKill:             r,
		RollbackAuthorization:  r,
		AuditBatch:             r,
		ReceiptEntryVersions:   []int{recorder.EntryVersion},
		MaxCreatedSkewSeconds:  60,
		EmergencyStream:        true,
		RemoteKillThreshold:    2,
		RollbackThreshold:      2,
		TrustRotationThreshold: 2,
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(data)
}
