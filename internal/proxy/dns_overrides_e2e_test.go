package proxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// generateWSKey returns a base64-encoded random 16-byte value suitable for
// the Sec-WebSocket-Key header. Built at runtime rather than hardcoded so
// the value does not trip secret scanners on the repo (gosec G101) and to
// match the same pattern the agent-egress-bench runner adapter uses for
// its manual upgrade requests.
func generateWSKey(t *testing.T) string {
	t.Helper()
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generate websocket key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(keyBytes)
}

// TestProxy_DNSHostOverrides_WSFixtureRoutesViaTrustedHostname mirrors the
// agent-egress-bench scenario where a local WebSocket fixture lives on
// loopback but must be reachable via a stable hostname so SSRF attacks
// targeting raw loopback IPs still get rejected.
//
// Setup:
//   - WS echo backend on a random 127.0.0.1 port (acts like the bench fixture).
//   - pipelock proxy with cfg.DNS.HostOverrides mapping the test hostname to
//     the backend IP, and cfg.TrustedDomains adding the hostname to the
//     SSRF-exempt list. ssrf.ip_allowlist is empty.
//   - Client dials proxy's /ws endpoint with url=ws://aeb-fixture.test:<port>/echo.
//
// Expectations:
//   - Connection succeeds (override + trusted_domains let pipelock dial the
//     fixture's loopback IP without tripping SSRF).
//   - A benign text frame round-trips through pipelock and the fixture.
//   - A raw http://127.0.0.1/admin request through ssrfSafeDialContext still
//     fails — trusted_domains explicitly rejects IP literals, and the
//     override map never gets consulted for IP-literal targets.
func TestProxy_DNSHostOverrides_WSFixtureRoutesViaTrustedHostname(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()

	backendHost, backendPort, splitErr := net.SplitHostPort(backendAddr)
	if splitErr != nil {
		t.Fatalf("split backend addr: %v", splitErr)
	}

	const fixtureHostname = "aeb-fixture.test"
	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.SSRF.IPAllowlist = nil
		cfg.TrustedDomains = []string{fixtureHostname}
		cfg.DNS.HostOverrides = map[string][]string{
			fixtureHostname: {backendHost},
		}
	})
	defer proxyCleanup()

	// Dial pipelock's /ws endpoint with a target URL that uses the trusted
	// hostname. pipelock should resolve via the override, see the hostname
	// is trusted, skip the loopback SSRF block, and tunnel to the backend.
	hostPort := net.JoinHostPort(fixtureHostname, backendPort)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	tcpConn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", proxyAddr)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	defer func() { _ = tcpConn.Close() }()
	if deadlineErr := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatalf("set deadline: %v", deadlineErr)
	}

	// Manual WS upgrade. Gobwas's dialer would re-resolve the hostname on
	// the client side, which we cannot intercept; we need pipelock to see
	// and honor the override, so the runner-side path through the proxy
	// is what counts. Use http.ReadResponse via bufio so a partial TCP
	// read cannot fragment the status line or headers, and so any bytes
	// pipelock buffers ahead of the WS frames stay accessible.
	upgrade := fmt.Sprintf(
		"%s /ws?url=%s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		http.MethodGet, "ws://"+hostPort+"/echo", proxyAddr, generateWSKey(t),
	)
	if _, writeErr := tcpConn.Write([]byte(upgrade)); writeErr != nil {
		t.Fatalf("write upgrade: %v", writeErr)
	}

	br := bufio.NewReader(tcpConn)
	resp, respErr := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if respErr != nil {
		t.Fatalf("read upgrade response: %v", respErr)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		_ = resp.Body.Close()
		t.Fatalf("expected 101 Switching Protocols upgrade; got: %d %s", resp.StatusCode, resp.Status)
	}
	_ = resp.Body.Close()

	// Write a single benign text frame and expect an echo. Wrap the conn
	// in the package-local bufferedConn so wsutil.ReadServerData consumes
	// any frame bytes already buffered by http.ReadResponse rather than
	// losing them past the bufio boundary.
	rw := &bufferedConn{Conn: tcpConn, r: br}
	if err := wsutil.WriteClientMessage(rw, ws.OpText, []byte("hello via trusted host")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo, _, err := wsutil.ReadServerData(rw)
	if err != nil {
		t.Fatalf("read echo: %v - override + trusted_domains should let the connection round-trip", err)
	}
	if string(echo) != "hello via trusted host" {
		t.Fatalf("echo = %q, want round-trip via fixture", echo)
	}
}

// TestProxy_DNSHostOverrides_RawIPLiteralStillBlocked confirms the
// security invariant: an SSRF attack that targets a raw loopback IP must
// be blocked even when dns.host_overrides happens to map some hostname to
// that same IP. Trusted_domains rejects IP literals at the matcher, and
// the override map is hostname-only.
func TestProxy_DNSHostOverrides_RawIPLiteralStillBlocked(t *testing.T) {
	// We don't even need a backend — pipelock should reject before any
	// connection attempt. But we'll bring one up to ensure failure is
	// caused by SSRF policy, not by "nothing listening".
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()
	backendHost, backendPort, splitErr := net.SplitHostPort(backendAddr)
	if splitErr != nil {
		t.Fatalf("split backend addr: %v", splitErr)
	}

	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		// Same operator setup as the trusted-hostname test: override +
		// trusted_domains for a hostname. The attacker hits the IP
		// directly, not the hostname.
		cfg.SSRF.IPAllowlist = nil
		cfg.TrustedDomains = []string{"aeb-fixture.test"}
		cfg.DNS.HostOverrides = map[string][]string{
			"aeb-fixture.test": {backendHost},
		}
	})
	defer proxyCleanup()

	// Sanity: the override port must be a number we can reuse.
	if _, err := strconv.Atoi(backendPort); err != nil {
		t.Fatalf("backend port %q is not an integer", backendPort)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	tcpConn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", proxyAddr)
	if dialErr != nil {
		t.Fatalf("dial proxy: %v", dialErr)
	}
	defer func() { _ = tcpConn.Close() }()
	if deadlineErr := tcpConn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
		t.Fatalf("set deadline: %v", deadlineErr)
	}

	// Direct attack: agent sends a /ws upgrade for raw 127.0.0.1:<port>.
	// trusted_domains rejects IP literals, override map is hostname-only,
	// RFC1918/loopback check still fires so the upgrade is denied.
	upgrade := fmt.Sprintf(
		"%s /ws?url=ws://%s/admin HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		http.MethodGet, net.JoinHostPort(backendHost, backendPort), proxyAddr, generateWSKey(t),
	)
	if _, writeErr := tcpConn.Write([]byte(upgrade)); writeErr != nil {
		t.Fatalf("write upgrade: %v", writeErr)
	}

	br := bufio.NewReader(tcpConn)
	resp, respErr := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if respErr != nil {
		t.Fatalf("read response: %v", respErr)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatalf("raw 127.0.0.1 WS upgrade was accepted; SSRF check did NOT reject - override map must not exempt IP literals")
	}
	// Pipelock should signal refusal with a 4xx/5xx status.
	if resp.StatusCode < 400 {
		t.Fatalf("expected 4xx/5xx refusal, got: %d %s", resp.StatusCode, resp.Status)
	}
}
