//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CapabilitiesPath           = "/api/v1/conductor/capabilities"
	AuditBatchesPath           = "/api/v1/conductor/audit/batches"
	MaxCapabilitiesBodyBytes   = 64 * 1024
	defaultCapabilitiesTimeout = 10 * time.Second
)

var ErrCapabilityNegotiation = errors.New("conductor capability negotiation failed")

type LocalFollowerCapabilities struct {
	MaxCreatedSkew       time.Duration
	MaxThreshold         int
	EmergencyStream      bool
	MaxResponseBodyBytes int64
}

type NegotiatedCapabilities struct {
	ConductorID            string
	SchemaVersion          int
	AuditSchemaVersion     int
	CreatedSkew            time.Duration
	EmergencyStream        bool
	RemoteKillThreshold    int
	RollbackThreshold      int
	TrustRotationThreshold int
}

type CapabilitiesClient struct {
	baseURL    *url.URL
	httpClient *http.Client
	local      LocalFollowerCapabilities
}

// NewCapabilitiesClient builds a Conductor capabilities client.
//
// SECURITY: callers must pass an httpClient whose Transport is configured for
// mTLS against the Conductor trust roster. The Conductor audit-sink design
// requires follower-to-Conductor transport to be mTLS; this constructor does
// not enforce that requirement because transport plumbing lives in the runtime
// wiring. Passing a default http.Client authenticates only the server
// certificate against the system trust store and sends no client certificate.
func NewCapabilitiesClient(rawBaseURL string, httpClient *http.Client, local LocalFollowerCapabilities) (*CapabilitiesClient, error) {
	baseURL, err := parseConductorBaseURL(rawBaseURL)
	if err != nil {
		return nil, err
	}
	if httpClient == nil {
		return nil, fmt.Errorf("%w: http client required", ErrCapabilityNegotiation)
	}
	return &CapabilitiesClient{
		baseURL:    baseURL,
		httpClient: httpClient,
		local:      local.withDefaults(),
	}, nil
}

func (c *CapabilitiesClient) Handshake(ctx context.Context) (NegotiatedCapabilities, error) {
	if c == nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: nil client", ErrCapabilityNegotiation)
	}
	if c.baseURL == nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: uninitialized base URL", ErrCapabilityNegotiation)
	}
	if c.httpClient == nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: uninitialized http client", ErrCapabilityNegotiation)
	}
	if ctx == nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: nil context", ErrCapabilityNegotiation)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCapabilitiesTimeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.capabilitiesURL(), nil)
	if err != nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: build request: %w", ErrCapabilityNegotiation, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: fetch capabilities: %w", ErrCapabilityNegotiation, err)
	}
	defer func() { _ = resp.Body.Close() }()

	limit := c.local.MaxResponseBodyBytes
	if limit <= 0 {
		limit = MaxCapabilitiesBodyBytes
	}
	body := http.MaxBytesReader(nil, resp.Body, limit)
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(body, 1024))
		return NegotiatedCapabilities{}, fmt.Errorf("%w: status=%d body=%q", ErrCapabilityNegotiation, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var capabilities CapabilitiesResponse
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&capabilities); err != nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: decode response: %w", ErrCapabilityNegotiation, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: trailing JSON document", ErrCapabilityNegotiation)
	}
	return NegotiateCapabilities(capabilities, c.local)
}

func (c *CapabilitiesClient) capabilitiesURL() string {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + CapabilitiesPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func NegotiateCapabilities(c CapabilitiesResponse, local LocalFollowerCapabilities) (NegotiatedCapabilities, error) {
	local = local.withDefaults()
	if err := c.ValidateWithLocalThresholdCap(local.MaxThreshold); err != nil {
		return NegotiatedCapabilities{}, fmt.Errorf("%w: %w", ErrCapabilityNegotiation, err)
	}
	serverSkew := time.Duration(c.MaxCreatedSkewSeconds) * time.Second
	createdSkew := serverSkew
	if local.MaxCreatedSkew < createdSkew {
		createdSkew = local.MaxCreatedSkew
	}
	// Audit envelope schema must be the highest version the FOLLOWER
	// supports, capped by the server's advertised range. Using c.AuditBatch.Max
	// directly would have the follower claim a version it cannot actually
	// emit when Conductor advertises a forward-compat upper bound. Validation
	// already ensures SchemaVersion ∈ [Min, Max], so the local constant is
	// always inside the server's range.
	auditSchemaVersion := SchemaVersion
	if c.AuditBatch.Max < auditSchemaVersion {
		auditSchemaVersion = c.AuditBatch.Max
	}
	return NegotiatedCapabilities{
		ConductorID:        c.ConductorID,
		SchemaVersion:      SchemaVersion,
		AuditSchemaVersion: auditSchemaVersion,
		CreatedSkew:        createdSkew,
		// EmergencyStream is enabled iff BOTH Conductor advertises support and
		// the follower has opted in locally. Either side disabled means polling
		// fallback only.
		EmergencyStream:        c.EmergencyStream && local.EmergencyStream,
		RemoteKillThreshold:    c.RemoteKillThreshold,
		RollbackThreshold:      c.RollbackThreshold,
		TrustRotationThreshold: c.TrustRotationThreshold,
	}, nil
}

func (l LocalFollowerCapabilities) withDefaults() LocalFollowerCapabilities {
	if l.MaxCreatedSkew <= 0 {
		l.MaxCreatedSkew = DefaultAuditMaxSkew
	}
	if l.MaxCreatedSkew > MaxAllowedAuditSkew {
		l.MaxCreatedSkew = MaxAllowedAuditSkew
	}
	if l.MaxThreshold <= 0 {
		l.MaxThreshold = MaxCapabilityThreshold
	}
	if l.MaxResponseBodyBytes <= 0 {
		l.MaxResponseBodyBytes = MaxCapabilitiesBodyBytes
	}
	return l
}

func parseConductorBaseURL(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%w: base URL required", ErrCapabilityNegotiation)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: parse base URL: %w", ErrCapabilityNegotiation, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("%w: base URL must be https with a host", ErrCapabilityNegotiation)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: base URL must not include userinfo, query, or fragment", ErrCapabilityNegotiation)
	}
	// Reject path components. The capabilities client appends CapabilitiesPath
	// to the base, so a base of "https://host/admin" silently produces
	// "https://host/admin/api/v1/conductor/capabilities" — almost always a
	// misconfiguration where the operator confused base URL with a deep link.
	// Same class of mistake as userinfo / query / fragment.
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("%w: base URL must not include a path component, got %q", ErrCapabilityNegotiation, u.Path)
	}
	return u, nil
}
