package killswitch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF for tests
	return cfg
}

func TestController_ConfigEnabled(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "test deny-all" //nolint:goconst // test value

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch?url=http://example.com", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch to be active when config enabled")
	}
	if d.Source != "config" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "config", d.Source)
	}
	if d.Message != "test deny-all" { //nolint:goconst // test value
		t.Errorf("expected message %q, got %q", "test deny-all", d.Message)
	}
}

func TestController_ConfigDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = false

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch?url=http://example.com", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch to be inactive when config disabled")
	}
}

func TestController_SentinelFile(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)

	// No sentinel file — inactive.
	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch inactive when sentinel file absent")
	}

	// Create sentinel file — active.
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch active when sentinel file present")
	}
	if d.Source != "sentinel" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "sentinel", d.Source)
	}

	// Remove sentinel file — inactive again.
	if err := os.Remove(sentinelPath); err != nil {
		t.Fatal(err)
	}

	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch inactive after sentinel file removed")
	}
}

func TestController_SignalToggle(t *testing.T) {
	cfg := testConfig()
	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)

	// Initially inactive.
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch inactive initially")
	}

	// Toggle on.
	active := c.ToggleSignal()
	if !active {
		t.Fatal("expected ToggleSignal to return true (now active)")
	}

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch active after signal toggle on")
	}
	if d.Source != "signal" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "signal", d.Source)
	}

	// Toggle off.
	active = c.ToggleSignal()
	if active {
		t.Fatal("expected ToggleSignal to return false (now inactive)")
	}

	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch inactive after signal toggle off")
	}
}

func TestController_ORComposition(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)

	// Config enabled → active (source=config takes priority in reporting).
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active from config")
	}

	// Add signal — still active.
	c.ToggleSignal()
	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active from config+signal")
	}

	// Disable config via reload, signal still on.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = false
	cfg2.KillSwitch.SentinelFile = sentinelPath
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active from signal alone")
	}
	if d.Source != "signal" {
		t.Errorf("expected source %q, got %q", "signal", d.Source)
	}

	// Toggle signal off, create sentinel.
	c.ToggleSignal()
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active from sentinel alone")
	}
	if d.Source != "sentinel" {
		t.Errorf("expected source %q, got %q", "sentinel", d.Source)
	}

	// Remove sentinel — all sources off.
	if err := os.Remove(sentinelPath); err != nil {
		t.Fatal(err)
	}

	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected inactive when all sources off")
	}
}

func TestController_HealthExempt(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)

	// /health is exempt by default.
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected /health to be exempt from kill switch")
	}

	// Disable health exemption.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = true
	cfg2.KillSwitch.HealthExempt = ptrBool(false)
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected /health to be blocked when exemption disabled")
	}
}

func TestController_MetricsExempt(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)

	// /metrics is exempt by default.
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected /metrics to be exempt from kill switch")
	}

	// Disable metrics exemption.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = true
	cfg2.KillSwitch.MetricsExempt = ptrBool(false)
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected /metrics to be blocked when exemption disabled")
	}
}

func TestController_AllowlistIP(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.AllowlistIPs = []string{"192.168.1.0/24", "10.0.0.5/32"}

	c := New(cfg)

	// Allowed IP passes.
	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r.RemoteAddr = "192.168.1.42:12345"
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected allowlisted IP to pass through kill switch")
	}

	// Non-allowed IP blocked.
	r2 := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r2.RemoteAddr = "172.16.0.1:12345"
	d = c.IsActiveHTTP(r2)
	if !d.Active {
		t.Fatal("expected non-allowlisted IP to be blocked")
	}

	// Exact match on /32.
	r3 := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r3.RemoteAddr = "10.0.0.5:54321"
	d = c.IsActiveHTTP(r3)
	if d.Active {
		t.Fatal("expected /32 allowlisted IP to pass")
	}
}

func TestController_Reload(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "initial message" //nolint:goconst // test value

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if d.Message != "initial message" {
		t.Errorf("expected message %q, got %q", "initial message", d.Message)
	}

	// Reload with different config.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = false
	cfg2.KillSwitch.Message = "updated message" //nolint:goconst // test value
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected kill switch inactive after reload disabling it")
	}

	// Re-enable with updated message.
	cfg3 := testConfig()
	cfg3.KillSwitch.Enabled = true
	cfg3.KillSwitch.Message = "updated message"
	c.Reload(cfg3)

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch active after reload re-enabling")
	}
	if d.Message != "updated message" {
		t.Errorf("expected message %q, got %q", "updated message", d.Message)
	}
}

func TestController_HTTPResponse(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "test deny-all" //nolint:goconst // test value

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch?url=http://example.com", nil)
	d := c.IsActiveHTTP(r)

	if !d.Active {
		t.Fatal("expected active decision")
	}
	if d.Message != "test deny-all" {
		t.Errorf("expected message %q, got %q", "test deny-all", d.Message)
	}
	if d.Source != "config" {
		t.Errorf("expected source %q, got %q", "config", d.Source)
	}
}

func TestController_MCPNotification(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "deny all" //nolint:goconst // test value

	c := New(cfg)

	// Notification (no "id" field).
	notification := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	d := c.IsActiveMCP(notification)
	if !d.Active {
		t.Fatal("expected active for MCP notification")
	}
	if !d.IsNotification {
		t.Fatal("expected notification to be flagged as IsNotification")
	}

	// Request (has "id" field).
	request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	d = c.IsActiveMCP(request)
	if !d.Active {
		t.Fatal("expected active for MCP request")
	}
	if d.IsNotification {
		t.Fatal("expected request to not be a notification")
	}

	// Notification with no id — check IsNotification.
	d = c.IsActiveMCP(notification)
	if !d.IsNotification {
		t.Fatal("expected notification (no id) to have IsNotification=true")
	}
}

func TestController_MCPInactive(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = false

	c := New(cfg)

	msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`)
	d := c.IsActiveMCP(msg)
	if d.Active {
		t.Fatal("expected kill switch inactive for MCP when not enabled")
	}
}

func TestController_Concurrent(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "concurrent test"

	c := New(cfg)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
			_ = c.IsActiveHTTP(r)
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.ToggleSignal()
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newCfg := testConfig()
			newCfg.KillSwitch.Enabled = true
			c.Reload(newCfg)
		}()
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			msg := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
			_ = c.IsActiveMCP(msg)
		}()
	}
	wg.Wait()
}

func TestController_NilController(t *testing.T) {
	// Ensure nil check safety when no controller is configured.
	var c *Controller
	if c != nil {
		t.Fatal("nil controller should be nil")
	}
	// Callers should nil-check before calling methods.
	// This test documents the expected nil guard pattern.
}

func TestController_MCPResponseFormat(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.Message = "deny all"

	c := New(cfg)

	// Verify the kill switch error response format.
	request := []byte(`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{}}`)
	d := c.IsActiveMCP(request)
	if !d.Active {
		t.Fatal("expected active")
	}

	// Build the error response as the caller would.
	var reqID json.RawMessage
	var req struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(request, &req) == nil {
		reqID = req.ID
	}
	errResp := KillSwitchErrorResponse(reqID, d.Message)

	// Parse and verify format.
	var parsed struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(errResp, &parsed); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if parsed.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc %q, got %q", "2.0", parsed.JSONRPC)
	}
	if parsed.ID != 42 {
		t.Errorf("expected id 42, got %d", parsed.ID)
	}
	if parsed.Error.Code != -32004 {
		t.Errorf("expected error code -32004, got %d", parsed.Error.Code)
	}
	if parsed.Error.Message != "deny all" {
		t.Errorf("expected error message %q, got %q", "deny all", parsed.Error.Message)
	}
}

func TestController_SourcePriority(t *testing.T) {
	// When multiple sources are active, verify priority order: config > signal > sentinel.
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)
	c.ToggleSignal()
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if d.Source != "config" {
		t.Errorf("expected source %q when all sources active, got %q", "config", d.Source)
	}

	// Disable config — signal should be next.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = false
	cfg2.KillSwitch.SentinelFile = sentinelPath
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if d.Source != "signal" {
		t.Errorf("expected source %q when config disabled, got %q", "signal", d.Source)
	}

	// Disable signal — sentinel should be next.
	c.ToggleSignal()
	d = c.IsActiveHTTP(r)
	if d.Source != "sentinel" {
		t.Errorf("expected source %q when config+signal disabled, got %q", "sentinel", d.Source)
	}
}

func ptrBool(v bool) *bool { return &v }
