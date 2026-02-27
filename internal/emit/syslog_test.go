//go:build !windows

package emit

import (
	"context"
	"log/syslog"
	"net"
	"testing"
	"time"
)

func TestParseSyslogAddress(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantNet  string
		wantAddr string
		wantErr  bool
	}{
		{name: "udp valid", addr: "udp://syslog.example.com:514", wantNet: "udp", wantAddr: "syslog.example.com:514"},
		{name: "tcp valid", addr: "tcp://syslog.example.com:514", wantNet: "tcp", wantAddr: "syslog.example.com:514"},
		{name: "UDP uppercase", addr: "UDP://syslog.example.com:514", wantNet: "udp", wantAddr: "syslog.example.com:514"},
		{name: "localhost with port", addr: "udp://127.0.0.1:1514", wantNet: "udp", wantAddr: "127.0.0.1:1514"},
		{name: "unsupported scheme", addr: "http://syslog.example.com:514", wantErr: true},
		{name: "empty scheme", addr: "://syslog.example.com:514", wantErr: true},
		{name: "missing host", addr: "udp://", wantErr: true},
		{name: "missing port", addr: "udp://syslog.example.com", wantErr: true},
		{name: "empty string", addr: "", wantErr: true},
		{name: "garbage", addr: "not-a-url", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNet, gotAddr, err := parseSyslogAddress(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSyslogAddress(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if gotNet != tt.wantNet {
				t.Errorf("network = %q, want %q", gotNet, tt.wantNet)
			}
			if gotAddr != tt.wantAddr {
				t.Errorf("address = %q, want %q", gotAddr, tt.wantAddr)
			}
		})
	}
}

func TestParseFacility(t *testing.T) {
	tests := []struct {
		name string
		want syslog.Priority
	}{
		{"kern", syslog.LOG_KERN},
		{"user", syslog.LOG_USER},
		{"mail", syslog.LOG_MAIL},
		{"daemon", syslog.LOG_DAEMON},
		{"auth", syslog.LOG_AUTH},
		{"syslog", syslog.LOG_SYSLOG},
		{"lpr", syslog.LOG_LPR},
		{"news", syslog.LOG_NEWS},
		{"uucp", syslog.LOG_UUCP},
		{"local0", syslog.LOG_LOCAL0},
		{"local1", syslog.LOG_LOCAL1},
		{"local2", syslog.LOG_LOCAL2},
		{"local3", syslog.LOG_LOCAL3},
		{"local4", syslog.LOG_LOCAL4},
		{"local5", syslog.LOG_LOCAL5},
		{"local6", syslog.LOG_LOCAL6},
		{"local7", syslog.LOG_LOCAL7},
		{"LOCAL0", syslog.LOG_LOCAL0}, // case insensitive
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseFacility(tt.name); got != tt.want {
				t.Errorf("parseFacility(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}

	// Unrecognized value defaults to LOG_LOCAL0
	t.Run("unrecognized", func(t *testing.T) {
		if got := parseFacility("bogus"); got != syslog.LOG_LOCAL0 {
			t.Errorf("parseFacility(\"bogus\") = %d, want LOG_LOCAL0 (%d)", got, syslog.LOG_LOCAL0)
		}
	})
}

func TestSyslogSink_Close_NilReceiver(t *testing.T) {
	var s *SyslogSink
	if err := s.Close(); err != nil {
		t.Errorf("Close() on nil receiver: %v", err)
	}
}

func TestSyslogSink_Close_NilWriter(t *testing.T) {
	s := &SyslogSink{}
	if err := s.Close(); err != nil {
		t.Errorf("Close() on nil writer: %v", err)
	}
}

// startUDPSyslog starts a minimal UDP listener that acts as a syslog endpoint.
// Returns the listener address and a channel that receives each message.
func startUDPSyslog(t *testing.T) (string, <-chan string) {
	t.Helper()
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	msgs := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			msgs <- string(buf[:n])
		}
	}()

	return conn.LocalAddr().String(), msgs
}

func TestNewSyslogSink_And_Emit(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://"+addr, WithSyslogTag("test"))
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:   SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		InstanceID: "test-1",
		Fields:     map[string]any{"reason": "dlp_secret"},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		// Syslog prepends a header; the JSON payload should be in there
		if len(msg) == 0 {
			t.Fatal("received empty message")
		}
		// Verify it contains our payload fields
		for _, want := range []string{`"severity":"warn"`, `"type":"blocked"`, `"pipelock_instance":"test-1"`, `"reason":"dlp_secret"`} {
			if !contains(msg, want) {
				t.Errorf("message missing %q:\n%s", want, msg)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_CriticalSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://" + addr)
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityCritical,
		Type:      "kill_switch_deny",
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		if !contains(msg, `"severity":"critical"`) {
			t.Errorf("expected critical severity in message:\n%s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_InfoSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://" + addr)
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityInfo,
		Type:      "allowed",
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		if !contains(msg, `"severity":"info"`) {
			t.Errorf("expected info severity in message:\n%s", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for syslog message")
	}
}

func TestSyslogSink_Emit_BelowMinSeverity(t *testing.T) {
	addr, msgs := startUDPSyslog(t)
	sink, err := NewSyslogSink("udp://"+addr, WithSyslogMinSeverity(SeverityWarn))
	if err != nil {
		t.Fatalf("NewSyslogSink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	event := Event{
		Severity:  SeverityInfo,
		Type:      "allowed",
		Timestamp: time.Now(),
		Fields:    map[string]any{},
	}

	// Should be silently dropped
	if err := sink.Emit(context.Background(), event); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	select {
	case msg := <-msgs:
		t.Fatalf("expected no message, got: %s", msg)
	case <-time.After(200 * time.Millisecond):
		// Good — nothing received
	}
}

func TestNewSyslogSink_InvalidAddress(t *testing.T) {
	_, err := NewSyslogSink("http://example.com:514")
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestNewSyslogSink_DialFailure(t *testing.T) {
	// TCP to a port nothing is listening on should fail to connect
	// (or at least error on write; UDP is connectionless so use TCP)
	_, err := NewSyslogSink("tcp://127.0.0.1:1")
	if err == nil {
		t.Error("expected error for unreachable address")
	}
}

func TestNewSyslogSinkFromConfig(t *testing.T) {
	addr, _ := startUDPSyslog(t)

	sink, err := NewSyslogSinkFromConfig("udp://"+addr, "local3", "myapp", "warn")
	if err != nil {
		t.Fatalf("NewSyslogSinkFromConfig: %v", err)
	}
	defer func() { _ = sink.Close() }()

	if sink.minSev != SeverityWarn {
		t.Errorf("minSev = %v, want SeverityWarn", sink.minSev)
	}
}

func TestNewSyslogSinkFromConfig_Defaults(t *testing.T) {
	addr, _ := startUDPSyslog(t)

	sink, err := NewSyslogSinkFromConfig("udp://"+addr, "", "", "")
	if err != nil {
		t.Fatalf("NewSyslogSinkFromConfig: %v", err)
	}
	defer func() { _ = sink.Close() }()
}

func TestNewSyslogSinkFromConfig_InvalidAddress(t *testing.T) {
	_, err := NewSyslogSinkFromConfig("not-valid", "", "", "")
	if err == nil {
		t.Error("expected error for invalid address")
	}
}

func TestSyslogOptions(t *testing.T) {
	cfg := &syslogConfig{}

	WithSyslogFacility(syslog.LOG_AUTH)(cfg)
	if cfg.facility != syslog.LOG_AUTH {
		t.Errorf("facility = %v, want LOG_AUTH", cfg.facility)
	}

	WithSyslogTag("custom")(cfg)
	if cfg.tag != "custom" {
		t.Errorf("tag = %q, want %q", cfg.tag, "custom")
	}

	WithSyslogMinSeverity(SeverityCritical)(cfg)
	if cfg.minSev != SeverityCritical {
		t.Errorf("minSev = %v, want SeverityCritical", cfg.minSev)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
