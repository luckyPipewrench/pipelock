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
	"net/url"
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
	endpoint, err := enrollEndpoint(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		endpoint: endpoint,
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
		msg := fmt.Sprintf("enrollmentclient: enroll status=%d body=%s", resp.StatusCode, snippet(respBody, reqBody.Token))
		if resp.StatusCode == http.StatusConflict {
			msg += "; to re-enroll, first remove the existing enrollment: pipelock conductor follower remove --org-id <org> --fleet-id <fleet> --instance-id <instance> --environment <env>, then mint a new enrollment token and re-enroll"
		}
		return Response{}, errors.New(msg)
	}
	var out Response
	if err := json.Unmarshal(respBody, &out); err != nil {
		return Response{}, fmt.Errorf("enrollmentclient: decode enroll response: %w", err)
	}
	if err := validateResponse(out, reqBody); err != nil {
		return Response{}, err
	}
	return out, nil
}

func enrollEndpoint(rawBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawBaseURL))
	if err != nil {
		return "", fmt.Errorf("enrollmentclient: parse conductor base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return "", errors.New("enrollmentclient: conductor base URL must be https with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("enrollmentclient: conductor base URL must not include userinfo, query, or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return "", errors.New("enrollmentclient: conductor base URL must not include a path component")
	}
	u.Path = controlplane.EnrollPath
	u.RawPath = ""
	return u.String(), nil
}

func validateResponse(resp Response, req Request) error {
	switch {
	case strings.TrimSpace(resp.OrgID) == "":
		return errors.New("enrollmentclient: enroll response missing org_id")
	case strings.TrimSpace(resp.FleetID) == "":
		return errors.New("enrollmentclient: enroll response missing fleet_id")
	case strings.TrimSpace(resp.InstanceID) == "":
		return errors.New("enrollmentclient: enroll response missing instance_id")
	case strings.TrimSpace(resp.Environment) == "":
		return errors.New("enrollmentclient: enroll response missing environment")
	case strings.TrimSpace(resp.AuditKeyID) == "":
		return errors.New("enrollmentclient: enroll response missing audit_key_id")
	case resp.EnrolledAt.IsZero():
		return errors.New("enrollmentclient: enroll response missing enrolled_at")
	case resp.AuditKeyID != req.AuditKeyID:
		return errors.New("enrollmentclient: enroll response audit_key_id does not match request")
	default:
		return nil
	}
}

func snippet(b []byte, secrets ...string) string {
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
	const maxSnippetBytes = 512
	if len(s) > maxSnippetBytes {
		return s[:maxSnippetBytes] + "..."
	}
	return s
}
