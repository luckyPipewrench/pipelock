//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package conductor

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/tlsfile"
)

const (
	clientHTTPTimeout   = 30 * time.Second
	clientMaxBodyBytes  = 8 << 20 // 8 MiB cap on operator read responses
	defaultClientServer = "https://127.0.0.1:8895"

	// ReadClientFollowerLimitMax is the bounded read limit for dashboard follower roster queries.
	ReadClientFollowerLimitMax = 501
)

// clientOptions are the connection flags shared by every Conductor operator
// read command (audit query, fleet status, followers). The operator
// authenticates to the Conductor with a client certificate (mTLS transport)
// AND a bearer token (role/audience authorization); both are required because
// the control plane verifies the client cert at the TLS layer and the bearer
// scope at the application layer.
type clientOptions struct {
	server         string
	caFile         string
	clientCertFile string
	clientKeyFile  string
	tokenFile      string
	serverName     string
	licenseCRLFile string
}

// ReadClientOptions configures a read-only Conductor client for dashboard and
// operator read surfaces. It mirrors clientOptions without exposing mutating CLI
// helpers to callers outside this package.
type ReadClientOptions struct {
	Server         string
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
	TokenFile      string
	ServerName     string
}

// ReadClient exposes only the Conductor read endpoints the dashboard can use.
// It deliberately has no publish, kill, resume, rollback, enroll, revoke, or
// delete methods.
type ReadClient struct {
	client *conductorClient
}

// NewReadClient builds an authenticated TLS 1.3 + bearer-token Conductor read
// client using the same validation and transport setup as the operator CLI.
func NewReadClient(opts ReadClientOptions) (*ReadClient, error) {
	client, err := newConductorClient(clientOptions{
		server:         opts.Server,
		caFile:         opts.CAFile,
		clientCertFile: opts.ClientCertFile,
		clientKeyFile:  opts.ClientKeyFile,
		tokenFile:      opts.TokenFile,
		serverName:     opts.ServerName,
	})
	if err != nil {
		return nil, err
	}
	return &ReadClient{client: client}, nil
}

// ListFollowers reads the enrolled-follower roster. It only issues GET against
// the allowlisted followers endpoint.
func (c *ReadClient) ListFollowers(ctx context.Context, orgID, fleetID string, limit int) ([]byte, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("conductor read client is nil")
	}
	if limit <= 0 {
		return nil, errors.New("follower limit must be positive")
	}
	if limit > ReadClientFollowerLimitMax {
		return nil, fmt.Errorf("follower limit exceeds maximum %d", ReadClientFollowerLimitMax)
	}
	orgID = strings.TrimSpace(orgID)
	fleetID = strings.TrimSpace(fleetID)
	if orgID == "" || fleetID == "" {
		return nil, errors.New("org_id and fleet_id are required")
	}
	if strings.IndexFunc(orgID, unicode.IsControl) >= 0 || strings.IndexFunc(fleetID, unicode.IsControl) >= 0 {
		return nil, errors.New("org_id and fleet_id must not contain control characters")
	}
	params := map[string]string{
		"org_id":   orgID,
		"fleet_id": fleetID,
		"limit":    fmt.Sprintf("%d", limit),
	}
	return c.client.getJSON(ctx, controlplane.FollowersPath+encodeQuery(params))
}

func (o *clientOptions) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.server, "server", defaultClientServer, "Conductor HTTPS base URL")
	cmd.Flags().StringVar(&o.caFile, "ca-file", "", "PEM CA bundle that signed the Conductor server certificate (required)")
	cmd.Flags().StringVar(&o.clientCertFile, "client-cert", "", "operator client certificate for mTLS (required)")
	cmd.Flags().StringVar(&o.clientKeyFile, "client-key", "", "operator client private key for mTLS (required)")
	cmd.Flags().StringVar(&o.tokenFile, "token-file", "", "file containing the operator bearer token (required)")
	cmd.Flags().StringVar(&o.serverName, "server-name", "", "TLS server name override (defaults to the --server host)")
	cmd.Flags().StringVar(&o.licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
}

// conductorClient is a thin authenticated GET-only client for the Conductor
// operator read endpoints.
type conductorClient struct {
	httpClient *http.Client
	baseURL    string
	token      string
}

func newConductorClient(opts clientOptions) (*conductorClient, error) {
	server := strings.TrimSpace(opts.server)
	if server == "" {
		return nil, errors.New("--server is required")
	}
	parsed, err := url.Parse(server)
	if err != nil {
		return nil, fmt.Errorf("invalid --server %q: %w", server, err)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid --server %q: scheme must be https", server)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid --server %q: missing host", server)
	}
	if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid --server %q: conductor server URL must not include userinfo, path, query, or fragment", server)
	}
	if strings.TrimSpace(opts.caFile) == "" {
		return nil, errors.New("--ca-file is required")
	}
	if strings.TrimSpace(opts.clientCertFile) == "" {
		return nil, errors.New("--client-cert is required")
	}
	if strings.TrimSpace(opts.clientKeyFile) == "" {
		return nil, errors.New("--client-key is required")
	}
	token, err := readClientTokenFile(opts.tokenFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Clean(opts.caFile))
	if err != nil {
		return nil, fmt.Errorf("read --ca-file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("--ca-file contains no PEM certificates")
	}
	cert, err := tlsfile.LoadX509KeyPair(opts.clientCertFile, opts.clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load operator client certificate: %w", err)
	}
	serverName := strings.TrimSpace(opts.serverName)
	if serverName == "" {
		serverName = parsed.Hostname()
	}
	client := &http.Client{
		Timeout: clientHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("conductor redirects are not allowed")
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{cert},
				RootCAs:      pool,
				ServerName:   serverName,
			},
		},
	}
	return &conductorClient{
		httpClient: client,
		baseURL:    strings.TrimRight(server, "/"),
		token:      token,
	}, nil
}

// getJSON performs an authenticated GET and returns the response body bytes for
// a 200 response, or a descriptive error otherwise. The body is read under a
// hard size cap so a hostile or buggy server cannot exhaust client memory.
func (c *conductorClient) getJSON(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request conductor: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, readErr := readClientBody(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("read conductor response: %w", readErr)
	}
	if err := checkClientStatus(resp, body, c.token); err != nil {
		return nil, err
	}
	return body, nil
}

// getStreamStatus performs the authenticated GET for the conductor stream
// overview, scoped by org (required) and optional fleet. It mirrors
// fetchFollowers: build the allowlisted query, then delegate to getJSON which
// enforces the response size cap and status handling.
func (c *conductorClient) getStreamStatus(ctx context.Context, orgID, fleetID string) ([]byte, error) {
	params := map[string]string{
		"org_id":   orgID,
		"fleet_id": fleetID,
	}
	return c.getJSON(ctx, controlplane.StreamStatusPath+encodeQuery(params))
}

// deleteJSON performs an authenticated DELETE with a JSON body and returns the
// response body bytes for a 200 response, or a descriptive error otherwise.
func (c *conductorClient) deleteJSON(ctx context.Context, path string, body any) ([]byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal delete request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build delete request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("delete request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, readErr := readClientBody(resp.Body)
	if readErr != nil {
		return nil, fmt.Errorf("read conductor response: %w", readErr)
	}
	if err := checkClientStatus(resp, respBody, c.token); err != nil {
		return nil, err
	}
	return respBody, nil
}

func checkClientStatus(resp *http.Response, body []byte, secrets ...string) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("conductor returned status %d: %s", resp.StatusCode, clientSnippet(body, secrets...))
	}
	return nil
}

func readClientBody(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, clientMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > clientMaxBodyBytes {
		return nil, fmt.Errorf("conductor response exceeds %d byte limit", clientMaxBodyBytes)
	}
	return body, nil
}

func readClientTokenFile(path string) (string, error) {
	return readSecureTokenFile("--token-file", path)
}

func clientSnippet(b []byte, secrets ...string) string {
	s := strings.TrimSpace(string(b))
	for _, cred := range secrets {
		cred = strings.TrimSpace(cred)
		if cred != "" {
			s = strings.ReplaceAll(s, cred, "[redacted]")
		}
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	const maxLen = 256
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

func encodeQuery(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		if strings.TrimSpace(v) == "" {
			continue
		}
		values.Set(k, v)
	}
	if len(values) == 0 {
		return ""
	}
	return "?" + values.Encode()
}
