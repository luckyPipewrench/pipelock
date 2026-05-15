package harness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"

	"github.com/luckyPipewrench/pipelock/bench/egress/mocks/httpecho"
	"github.com/luckyPipewrench/pipelock/bench/egress/mocks/sse"
	"github.com/luckyPipewrench/pipelock/bench/egress/mocks/toolchain"
	"github.com/luckyPipewrench/pipelock/bench/egress/mocks/wsfeed"
)

// LatencyConfig parameterizes the latency runs.
type LatencyConfig struct {
	Iterations  int           // measured iterations per workload
	Warmup      int           // unmeasured iterations before measurement starts
	PipelockURL string        // e.g., http://127.0.0.1:8888 (forward proxy + /ws + /fetch)
	HTTPTimeout time.Duration // per-request timeout
	// ToolchainSteps controls how many tool_use rounds per iteration.
	ToolchainSteps int
	// WSFrames controls how many text frames per WebSocket iteration.
	WSFrames int
}

// DefaultLatencyConfig returns sensible defaults for a quick run.
func DefaultLatencyConfig(pipelockURL string) LatencyConfig {
	return LatencyConfig{
		Iterations:     1000,
		Warmup:         100,
		PipelockURL:    pipelockURL,
		HTTPTimeout:    10 * time.Second,
		ToolchainSteps: 3,
		WSFrames:       100,
	}
}

// TransportResult holds direct vs through-pipelock measurements for one
// transport. Streaming transports (SSE, WebSocket) populate TTFB; the others
// leave it zero.
type TransportResult struct {
	Transport string        `json:"transport"`
	Direct    Stats         `json:"direct"`
	Proxied   Stats         `json:"proxied"`
	TTFB      *TTFBPair     `json:"ttfb,omitempty"`
	Notes     string        `json:"notes,omitempty"`
	Error     string        `json:"error,omitempty"`
	Elapsed   time.Duration `json:"elapsed_ns"`
}

// TTFBPair reports time-to-first-byte for streaming transports.
type TTFBPair struct {
	Direct  Stats `json:"direct"`
	Proxied Stats `json:"proxied"`
}

// RunHTTP exercises a plain HTTP GET against the httpecho mock, directly and
// through pipelock's HTTP forward proxy.
func RunHTTP(ctx context.Context, cfg LatencyConfig) TransportResult {
	start := time.Now()
	res := TransportResult{Transport: "http"}
	mock, addr, err := httpecho.Start(ctx)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = mock.Close() }()
	mockURL := "http://" + addr + "/"
	direct, err := newHTTPClient(cfg, "")
	if err != nil {
		res.Error = "direct client: " + err.Error()
		return res
	}
	proxied, err := newHTTPClient(cfg, cfg.PipelockURL)
	if err != nil {
		res.Error = "proxied client: " + err.Error()
		return res
	}
	directSamples, proxiedSamples, err := pairedLoop(ctx, cfg, func() (time.Duration, error) {
		return timeHTTPGet(ctx, direct, mockURL)
	}, func() (time.Duration, error) {
		return timeHTTPGet(ctx, proxied, mockURL)
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Direct = Summarize(directSamples)
	res.Proxied = Summarize(proxiedSamples)
	res.Elapsed = time.Since(start)
	return res
}

// RunSSE exercises a streaming Server-Sent Events response. Reports both
// time-to-first-byte and full-stream duration.
func RunSSE(ctx context.Context, cfg LatencyConfig) TransportResult {
	start := time.Now()
	res := TransportResult{Transport: "sse"}
	mock, addr, err := sse.Start(ctx)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = mock.Close() }()
	mockURL := "http://" + addr + "/"
	direct, err := newHTTPClient(cfg, "")
	if err != nil {
		res.Error = "direct client: " + err.Error()
		return res
	}
	proxied, err := newHTTPClient(cfg, cfg.PipelockURL)
	if err != nil {
		res.Error = "proxied client: " + err.Error()
		return res
	}
	var directTTFB, proxiedTTFB []time.Duration
	directTotal, proxiedTotal, err := pairedLoop(ctx, cfg, func() (time.Duration, error) {
		ttfb, total, err := timeSSE(ctx, direct, mockURL)
		if err == nil {
			directTTFB = append(directTTFB, ttfb)
		}
		return total, err
	}, func() (time.Duration, error) {
		ttfb, total, err := timeSSE(ctx, proxied, mockURL)
		if err == nil {
			proxiedTTFB = append(proxiedTTFB, ttfb)
		}
		return total, err
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Direct = Summarize(directTotal)
	res.Proxied = Summarize(proxiedTotal)
	res.TTFB = &TTFBPair{Direct: Summarize(directTTFB), Proxied: Summarize(proxiedTTFB)}
	res.Elapsed = time.Since(start)
	return res
}

// RunToolchain exercises a multi-step tool_use sequence against the toolchain
// mock. Each iteration walks ToolchainSteps round-trips before the mock
// returns end_turn.
func RunToolchain(ctx context.Context, cfg LatencyConfig) TransportResult {
	start := time.Now()
	res := TransportResult{Transport: "toolchain", Notes: fmt.Sprintf("%d tool_use rounds per iteration", cfg.ToolchainSteps)}
	mock, addr, err := toolchain.Start(ctx, cfg.ToolchainSteps)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = mock.Close() }()
	mockURL := "http://" + addr + "/v1/messages"
	body := []byte(`{"model":"mock","max_tokens":10,"messages":[{"role":"user","content":"bench"}]}`)
	direct, err := newHTTPClient(cfg, "")
	if err != nil {
		res.Error = "direct client: " + err.Error()
		return res
	}
	proxied, err := newHTTPClient(cfg, cfg.PipelockURL)
	if err != nil {
		res.Error = "proxied client: " + err.Error()
		return res
	}
	directSamples, proxiedSamples, err := pairedLoop(ctx, cfg, func() (time.Duration, error) {
		mock.Reset()
		return timeToolchain(ctx, direct, mockURL, body, cfg.ToolchainSteps)
	}, func() (time.Duration, error) {
		mock.Reset()
		return timeToolchain(ctx, proxied, mockURL, body, cfg.ToolchainSteps)
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Direct = Summarize(directSamples)
	res.Proxied = Summarize(proxiedSamples)
	res.Elapsed = time.Since(start)
	return res
}

// RunWebSocket exercises pipelock's /ws path. Direct baseline connects to the
// wsfeed mock without pipelock; proxied connects via /ws?url=ws://mock/.
//
// Each iteration: handshake, send WSFrames text frames, read back WSFrames
// echo frames, close. TTFB = time to first echo frame.
func RunWebSocket(ctx context.Context, cfg LatencyConfig) TransportResult {
	start := time.Now()
	res := TransportResult{Transport: "websocket", Notes: fmt.Sprintf("%d frames per iteration", cfg.WSFrames)}
	mock, addr, err := wsfeed.Start(ctx)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = mock.Close() }()
	directTarget := wsTargetDirect(addr)
	proxiedTarget, err := wsTargetProxied(cfg.PipelockURL, addr)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var directTTFB, proxiedTTFB []time.Duration
	directTotal, proxiedTotal, err := pairedLoop(ctx, cfg, func() (time.Duration, error) {
		ttfb, total, err := timeWebSocket(ctx, directTarget, cfg.WSFrames, false)
		if err == nil {
			directTTFB = append(directTTFB, ttfb)
		}
		return total, err
	}, func() (time.Duration, error) {
		ttfb, total, err := timeWebSocket(ctx, proxiedTarget, cfg.WSFrames, true)
		if err == nil {
			proxiedTTFB = append(proxiedTTFB, ttfb)
		}
		return total, err
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Direct = Summarize(directTotal)
	res.Proxied = Summarize(proxiedTotal)
	res.TTFB = &TTFBPair{Direct: Summarize(directTTFB), Proxied: Summarize(proxiedTTFB)}
	res.Elapsed = time.Since(start)
	return res
}

// RunMCPStdio exercises pipelock's stdio MCP proxy. Direct baseline spawns
// the mcpstdio mock binary by itself; proxied spawns it via
// `pipelock mcp proxy -- ./mcpstdio`.
//
// Each iteration sends one tools/call JSON-RPC request and reads the response.
// The subprocess is reused across iterations to avoid measuring fork/exec.
func RunMCPStdio(ctx context.Context, cfg LatencyConfig, mcpstdioPath, pipelockPath, pipelockConfig string) TransportResult {
	start := time.Now()
	res := TransportResult{Transport: "mcp_stdio"}

	directProc, err := startStdioProc(ctx, mcpstdioPath)
	if err != nil {
		res.Error = "spawn direct: " + err.Error()
		return res
	}
	defer directProc.close()

	proxiedProc, err := startStdioProc(ctx, pipelockPath,
		"mcp", "proxy", "--config", pipelockConfig, "--", mcpstdioPath)
	if err != nil {
		res.Error = "spawn proxied: " + err.Error()
		return res
	}
	defer proxiedProc.close()

	// Initialize both before measurement.
	if err := mcpInit(directProc, 0); err != nil {
		res.Error = "init direct: " + err.Error()
		return res
	}
	if err := mcpInit(proxiedProc, 0); err != nil {
		res.Error = "init proxied: " + err.Error()
		return res
	}

	id := 1
	directSamples, proxiedSamples, err := pairedLoop(ctx, cfg, func() (time.Duration, error) {
		t, err := timeMCPCall(directProc, id)
		id++
		return t, err
	}, func() (time.Duration, error) {
		t, err := timeMCPCall(proxiedProc, id)
		id++
		return t, err
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Direct = Summarize(directSamples)
	res.Proxied = Summarize(proxiedSamples)
	res.Elapsed = time.Since(start)
	return res
}

// pairedLoop runs warmup iterations of both fns, then runs Iterations measured
// pairs adjacent to each other. Pairing reduces thermal and scheduler drift
// between the two measurements being compared.
func pairedLoop(ctx context.Context, cfg LatencyConfig, direct, proxied func() (time.Duration, error)) ([]time.Duration, []time.Duration, error) {
	for i := 0; i < cfg.Warmup; i++ {
		if _, err := direct(); err != nil {
			return nil, nil, fmt.Errorf("warmup direct: %w", err)
		}
		if _, err := proxied(); err != nil {
			return nil, nil, fmt.Errorf("warmup proxied: %w", err)
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}
	directs := make([]time.Duration, 0, cfg.Iterations)
	proxies := make([]time.Duration, 0, cfg.Iterations)
	for i := 0; i < cfg.Iterations; i++ {
		d, err := direct()
		if err != nil {
			return nil, nil, fmt.Errorf("iteration %d direct: %w", i, err)
		}
		p, err := proxied()
		if err != nil {
			return nil, nil, fmt.Errorf("iteration %d proxied: %w", i, err)
		}
		directs = append(directs, d)
		proxies = append(proxies, p)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
	}
	return directs, proxies, nil
}

// newHTTPClient builds an http.Client that either connects directly or routes
// through the supplied HTTP proxy URL.
func newHTTPClient(cfg LatencyConfig, proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		DisableKeepAlives:     false,
		MaxIdleConnsPerHost:   16,
		ResponseHeaderTimeout: cfg.HTTPTimeout,
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{
		Transport: transport,
		Timeout:   cfg.HTTPTimeout,
	}, nil
}

func timeHTTPGet(ctx context.Context, c *http.Client, target string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, fmt.Errorf("GET status %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return time.Since(start), nil
}

func timeSSE(ctx context.Context, c *http.Client, target string) (ttfb, total time.Duration, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Accept", "text/event-stream")
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return 0, 0, fmt.Errorf("SSE status %d", resp.StatusCode)
	}
	r := bufio.NewReader(resp.Body)
	firstByte, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	ttfb = time.Since(start)
	_ = firstByte
	_, _ = io.Copy(io.Discard, r)
	total = time.Since(start)
	return ttfb, total, nil
}

func timeToolchain(ctx context.Context, c *http.Client, target string, body []byte, steps int) (time.Duration, error) {
	start := time.Now()
	for i := 0; i <= steps; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, err
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			return 0, fmt.Errorf("toolchain status %d", resp.StatusCode)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return time.Since(start), nil
}

// wsTargetDirect builds a direct WebSocket target ws://addr/.
func wsTargetDirect(addr string) string {
	return "ws://" + addr + "/"
}

// wsTargetProxied builds the pipelock /ws?url=... form. pipelockURL is the
// scheme+authority of the pipelock listener; mockAddr is the upstream mock.
func wsTargetProxied(pipelockURL, mockAddr string) (string, error) {
	pu, err := url.Parse(pipelockURL)
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("url", "ws://"+mockAddr+"/")
	return "ws://" + pu.Host + "/ws?" + q.Encode(), nil
}

// timeWebSocket connects via raw TCP, performs the RFC 6455 handshake, sends
// WSFrames text frames, reads WSFrames echo frames, and closes.
func timeWebSocket(ctx context.Context, target string, frames int, proxied bool) (ttfb, total time.Duration, err error) {
	_ = proxied // currently both paths use the same client transport
	u, err := url.Parse(target)
	if err != nil {
		return 0, 0, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = conn.Close() }()
	start := time.Now()
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return 0, 0, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	hs := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if _, err := conn.Write([]byte(hs)); err != nil {
		return 0, 0, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return 0, 0, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return 0, 0, fmt.Errorf("ws handshake status %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	payload := []byte("bench")
	for i := 0; i < frames; i++ {
		if err := writeMaskedTextFrame(conn, payload); err != nil {
			return 0, 0, err
		}
		echo, err := readUnmaskedFrame(br)
		if err != nil {
			return 0, 0, err
		}
		if ttfb == 0 {
			ttfb = time.Since(start)
		}
		_ = echo
	}
	// Send close frame.
	_, _ = conn.Write([]byte{0x88, 0x80, 0, 0, 0, 0})
	total = time.Since(start)
	return ttfb, total, nil
}

// writeMaskedTextFrame writes a client-to-server text frame with a random mask.
func writeMaskedTextFrame(w io.Writer, payload []byte) error {
	header := []byte{0x81} // FIN=1, opcode=text
	switch n := len(payload); {
	case n <= 125:
		header = append(header, byte(n)|0x80) //nolint:gosec // n <= 125
	case n < 65536:
		header = append(header, 126|0x80, byte(n>>8&0xFF), byte(n&0xFF))
	default:
		return fmt.Errorf("payload too large for bench")
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	header = append(header, mask[:]...)
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func readUnmaskedFrame(br *bufio.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(br, header); err != nil {
		return nil, err
	}
	length := int(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(br, ext); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(ext))
	case 127:
		return nil, fmt.Errorf("frames >64 KiB not supported")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// stdioProc represents a running subprocess speaking line-delimited JSON-RPC.
type stdioProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
}

func startStdioProc(ctx context.Context, name string, args ...string) (*stdioProc, error) {
	// G204: the binary path is supplied by the bench operator at startup
	// (pipelock + mcpstdio mock paths), not from untrusted input.
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &stdioProc{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReaderSize(stdout, 1<<20),
	}, nil
}

func (p *stdioProc) close() {
	_ = p.stdin.Close()
	_ = p.cmd.Process.Kill()
	_, _ = p.cmd.Process.Wait()
}

func (p *stdioProc) writeRequest(method string, id int, params map[string]any) error {
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := p.stdin.Write(append(b, '\n')); err != nil {
		return err
	}
	return nil
}

func (p *stdioProc) readResponse() error {
	if _, err := p.stdout.ReadBytes('\n'); err != nil {
		return err
	}
	return nil
}

func mcpInit(p *stdioProc, id int) error {
	if err := p.writeRequest("initialize", id, map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "bench-egress", "version": "0.1.0"},
	}); err != nil {
		return err
	}
	return p.readResponse()
}

func timeMCPCall(p *stdioProc, id int) (time.Duration, error) {
	start := time.Now()
	if err := p.writeRequest("tools/call", id, map[string]any{
		"name":      "echo",
		"arguments": map[string]any{"value": "bench"},
	}); err != nil {
		return 0, err
	}
	if err := p.readResponse(); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}
