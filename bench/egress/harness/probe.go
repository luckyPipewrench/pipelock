package harness

import (
	"context"
	"net"
	"net/http"
	"time"
)

// ProbeClient is a tiny HTTP client used to check pipelock's /health endpoint.
type ProbeClient struct {
	client *http.Client
}

// NewProbeClient returns a ProbeClient with a 250 ms per-request timeout.
func NewProbeClient() (*ProbeClient, error) {
	return &ProbeClient{
		client: &http.Client{Timeout: 250 * time.Millisecond},
	}, nil
}

// Healthy reports whether GET url returns HTTP 200.
func (p *ProbeClient) Healthy(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}

// PickFreePort returns a random free TCP port on 127.0.0.1. Exposed so the
// bench-egress entry binary can reuse the same allocator as the cold-start
// harness.
func PickFreePort() (int, error) {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port, nil
}
