//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enrollmentclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/enterprise/conductor/controlplane"
)

const maxResponseBytes = 64 * 1024

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Config struct {
	BaseURL string
	Client  HTTPDoer
}

type Client struct {
	endpoint string
	client   HTTPDoer
}

type Request struct {
	Token          string `json:"token"`
	AuditKeyID     string `json:"audit_key_id"`
	AuditPublicKey string `json:"audit_public_key"`
}

type Response struct {
	OrgID       string    `json:"org_id"`
	FleetID     string    `json:"fleet_id"`
	InstanceID  string    `json:"instance_id"`
	Environment string    `json:"environment"`
	AuditKeyID  string    `json:"audit_key_id"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

func New(cfg Config) (*Client, error) {
	if cfg.Client == nil {
		return nil, errors.New("enrollmentclient: http client required")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if base == "" {
		return nil, errors.New("enrollmentclient: conductor base URL required")
	}
	return &Client{
		endpoint: base + controlplane.EnrollPath,
		client:   cfg.Client,
	}, nil
}

func (c *Client) Enroll(ctx context.Context, reqBody Request) (Response, error) {
	if c == nil {
		return Response{}, errors.New("enrollmentclient: nil client")
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: marshal enroll request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: build enroll request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: enroll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: read enroll response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Response{}, fmt.Errorf("enrollmentclient: enroll status=%d body=%s", resp.StatusCode, snippet(respBody, reqBody.Token))
	}
	var out Response
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: decode enroll response: %w", err)
	}
	return out, nil
}

func snippet(b []byte, secrets ...string) string {
	s := strings.TrimSpace(string(b))
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	const maxSnippetBytes = 512
	if len(s) > maxSnippetBytes {
		return s[:maxSnippetBytes] + "..."
	}
	return s
}
