package proxy

import (
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// TestWSProxy_BenchCrossMessage_GitHubToken reproduces the exact gauntlet
// payload for ws-dlp-cross-message-005: two text frames whose label-stripped
// suffixes concatenate to a GitHub PAT matching the bench Benchmark GitHub
// Token pattern (ghp_[A-Za-z0-9_]{30,}).
func TestWSProxy_BenchCrossMessage_GitHubToken(t *testing.T) {
	backendAddr, backendCleanup := wsEchoServer(t)
	defer backendCleanup()

	proxyAddr, proxyCleanup := setupWSProxy(t, func(cfg *config.Config) {
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
			Name:     "Benchmark GitHub Token",
			Regex:    `ghp_[A-Za-z0-9_]{30,}`,
			Severity: "critical",
		})
	})
	defer proxyCleanup()

	conn := dialWS(t, proxyAddr, backendAddr)
	defer func() { _ = conn.Close() }()

	// First frame: prefix, no pattern hit alone.
	msg1 := []byte("part1: ghp_ABCDEFGHIJKLMN")
	if err := wsutil.WriteClientMessage(conn, ws.OpText, msg1); err != nil {
		t.Fatalf("write msg1: %v", err)
	}
	if _, _, err := wsutil.ReadServerData(conn); err != nil {
		t.Fatalf("read msg1 echo: %v (first half should pass)", err)
	}

	// Second frame: completes the secret when label-stripped suffixes are joined.
	msg2 := []byte("part2: OPQRSTUVWXYZabcdef12")
	if err := wsutil.WriteClientMessage(conn, ws.OpText, msg2); err != nil {
		t.Fatalf("write msg2: %v", err)
	}

	// Expectation: pipelock should close the connection because
	// joinLabeledWSCrossMessageSuffixes("part1: ghp_ABCDEFGHIJKLMN",
	// "part2: OPQRSTUVWXYZabcdef12") yields "ghp_" + 34 alphanumeric chars,
	// which matches the Benchmark GitHub Token pattern's {30,} length.
	if _, _, err := wsutil.ReadServerData(conn); err == nil {
		t.Fatal("expected connection closed on cross-message labeled GitHub PAT, got nil — pipelock allowed the split-key exfiltration")
	}
}
