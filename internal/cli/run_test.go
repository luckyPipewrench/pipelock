package cli

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func listenUDP(t *testing.T) net.PacketConn {
	t.Helper()
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestRedactEndpoint(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "webhook with query param",
			raw:  "https://hooks.example.com:8088/services/collector?session=abc123",
			want: "https://hooks.example.com:8088/services/collector",
		},
		{
			name: "webhook with userinfo",
			raw:  "https://" + "user:pass" + "@hooks.example.com/webhook", //nolint:goconst // test value
			want: "https://hooks.example.com/webhook",
		},
		{
			name: "webhook with fragment",
			raw:  "https://hooks.example.com/webhook#section",
			want: "https://hooks.example.com/webhook",
		},
		{
			name: "webhook with all sensitive parts",
			raw:  "https://" + "admin:secret" + "@example.com:8080/path?token=xyz&key=abc#frag",
			want: "https://example.com:8080/path",
		},
		{
			name: "syslog udp address",
			raw:  "udp://syslog.example.com:514",
			want: "udp://syslog.example.com:514",
		},
		{
			name: "syslog tcp address",
			raw:  "tcp://syslog.example.com:514",
			want: "tcp://syslog.example.com:514",
		},
		{
			name: "plain https URL",
			raw:  "https://example.com/webhook",
			want: "https://example.com/webhook",
		},
		{
			name: "empty string",
			raw:  "",
			want: "",
		},
		{
			name: "invalid URL returns sentinel",
			raw:  "%invalid",
			want: "<invalid>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactEndpoint(tt.raw)
			if got != tt.want {
				t.Errorf("redactEndpoint(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil
	return cfg
}

func TestBuildEmitSinks_NoConfig(t *testing.T) {
	cfg := testConfig()
	sinks, err := buildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 0 {
		t.Errorf("expected 0 sinks, got %d", len(sinks))
	}
}

func TestBuildEmitSinks_WebhookOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = "warn" //nolint:goconst // test value

	sinks, err := buildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_WebhookWithAllOptions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = "info"          //nolint:goconst // test value
	cfg.Emit.Webhook.AuthToken = "test-" + "token" //nolint:goconst // test value
	cfg.Emit.Webhook.QueueSize = 32
	cfg.Emit.Webhook.TimeoutSecs = 10

	sinks, err := buildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_SyslogOnly(t *testing.T) {
	conn := listenUDP(t)

	cfg := testConfig()
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.Syslog.MinSeverity = "warn" //nolint:goconst // test value
	cfg.Emit.Syslog.Facility = "local3"
	cfg.Emit.Syslog.Tag = "test"

	sinks, err := buildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 1 {
		t.Errorf("expected 1 sink, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_BothSinks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	conn := listenUDP(t)

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = "info" //nolint:goconst // test value
	cfg.Emit.Syslog.Address = "udp://" + conn.LocalAddr().String()
	cfg.Emit.Syslog.MinSeverity = "warn" //nolint:goconst // test value

	sinks, err := buildEmitSinks(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sinks) != 2 {
		t.Errorf("expected 2 sinks, got %d", len(sinks))
	}
	for _, s := range sinks {
		_ = s.Close()
	}
}

func TestBuildEmitSinks_SyslogError_CleansUpWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig()
	cfg.Emit.Webhook.URL = srv.URL
	cfg.Emit.Webhook.MinSeverity = "info"
	// Invalid syslog address triggers error after webhook is created
	cfg.Emit.Syslog.Address = "tcp://127.0.0.1:notaport" // deterministic parse failure

	sinks, err := buildEmitSinks(cfg)
	if err == nil {
		for _, s := range sinks {
			_ = s.Close()
		}
		t.Fatal("expected error for unreachable syslog")
	}
	// Webhook sink should have been cleaned up (no goroutine leak)
	if sinks != nil {
		t.Errorf("expected nil sinks on error, got %d", len(sinks))
	}
}
