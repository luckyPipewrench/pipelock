//go:build enterprise

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

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

const (
	clientHTTPTimeout   = 30 * time.Second
	clientMaxBodyBytes  = 8 << 20 // 8 MiB cap on operator read responses
	defaultClientServer = "https://127.0.0.1:8895"
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
	cert, err := tls.LoadX509KeyPair(filepath.Clean(opts.clientCertFile), filepath.Clean(opts.clientKeyFile))
	if err != nil {
		return nil, fmt.Errorf("load operator client certificate: %w", err)
	}
	serverName := strings.TrimSpace(opts.serverName)
	if serverName == "" {
		serverName = parsed.Hostname()
	}
	client := &http.Client{
		Timeout: clientHTTPTimeout,
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
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, clientMaxBodyBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("conductor returned status %d: %s", resp.StatusCode, clientSnippet(body, c.token))
	}
	if readErr != nil {
		return nil, fmt.Errorf("read conductor response: %w", readErr)
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
	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, clientMaxBodyBytes))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("conductor returned status %d: %s", resp.StatusCode, clientSnippet(respBody, c.token))
	}
	if readErr != nil {
		return nil, fmt.Errorf("read delete response: %w", readErr)
	}
	return respBody, nil
}

func readClientTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--token-file is required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read --token-file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("--token-file is empty")
	}
	return token, nil
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
