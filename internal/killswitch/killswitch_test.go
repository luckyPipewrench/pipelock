package killswitch

import (
	"bytes"
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
	errResp := ErrorResponse(reqID, d.Message)

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

func TestController_SentinelStatError(t *testing.T) {
	// Verify fail-closed: if os.Stat returns an error other than ErrNotExist
	// (e.g. permission denied), the kill switch should be ACTIVE.
	if os.Getuid() == 0 {
		t.Skip("permission-based test cannot run as root")
	}

	dir := t.TempDir()
	restrictedDir := filepath.Join(dir, "noaccess")
	if err := os.Mkdir(restrictedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	sentinelPath := filepath.Join(restrictedDir, "killswitch")
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Remove all permissions on the directory so os.Stat on the file inside
	// returns EACCES (permission denied), not ErrNotExist.
	if err := os.Chmod(restrictedDir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer func() {
		// Restore permissions so t.TempDir() cleanup can remove the directory.
		_ = os.Chmod(restrictedDir, 0o700) //nolint:errcheck,gosec // best-effort cleanup, directory needs execute
	}()

	cfg := testConfig()
	cfg.KillSwitch.SentinelFile = sentinelPath
	cfg.KillSwitch.Message = "fail closed" //nolint:goconst // test value

	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch ACTIVE on sentinel stat permission error (fail closed)")
	}
	if d.Source != "sentinel" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "sentinel", d.Source)
	}
	if d.Message != "fail closed" { //nolint:goconst // test value
		t.Errorf("expected message %q, got %q", "fail closed", d.Message)
	}
}

func TestController_ErrorResponse(t *testing.T) {
	tests := []struct {
		name    string
		id      json.RawMessage
		message string
		wantID  string
		wantMsg string
	}{
		{
			name:    "numeric id",
			id:      json.RawMessage(`1`),
			message: "deny all", //nolint:goconst // test value
			wantID:  "1",
			wantMsg: "deny all", //nolint:goconst // test value
		},
		{
			name:    "string id",
			id:      json.RawMessage(`"abc-123"`),
			message: "kill switch active", //nolint:goconst // test value
			wantID:  `"abc-123"`,
			wantMsg: "kill switch active", //nolint:goconst // test value
		},
		{
			name:    "null id",
			id:      json.RawMessage(`null`),
			message: "emergency shutdown", //nolint:goconst // test value
			wantID:  "null",
			wantMsg: "emergency shutdown", //nolint:goconst // test value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := ErrorResponse(tt.id, tt.message)

			var parsed struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Error   struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp, &parsed); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}
			if parsed.JSONRPC != "2.0" {
				t.Errorf("expected jsonrpc %q, got %q", "2.0", parsed.JSONRPC)
			}
			if string(parsed.ID) != tt.wantID {
				t.Errorf("expected id %s, got %s", tt.wantID, string(parsed.ID))
			}
			if parsed.Error.Code != -32004 {
				t.Errorf("expected error code -32004, got %d", parsed.Error.Code)
			}
			if parsed.Error.Message != tt.wantMsg {
				t.Errorf("expected error message %q, got %q", tt.wantMsg, parsed.Error.Message)
			}
		})
	}
}

func TestController_BareIPAddress(t *testing.T) {
	// extractIP must handle bare IPs (no port) as well as host:port.
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.AllowlistIPs = []string{"10.0.0.0/24"}
	cfg.KillSwitch.Message = "bare IP test" //nolint:goconst // test value

	c := New(cfg)

	// Request with bare IP (no port) — should be allowlisted.
	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r.RemoteAddr = "10.0.0.1" // bare IP, no :port
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Error("bare IP 10.0.0.1 should be allowlisted")
	}

	// Verify non-allowlisted bare IP is still blocked.
	r2 := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r2.RemoteAddr = "192.168.1.1" // bare IP, not in allowlist
	d2 := c.IsActiveHTTP(r2)
	if !d2.Active {
		t.Error("non-allowlisted bare IP should be denied")
	}
}

func TestController_HasIDEdgeCases(t *testing.T) {
	// hasID is used in IsActiveMCP to distinguish requests from notifications.
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"invalid json", "not json at all", false},
		{"null id", `{"jsonrpc":"2.0","method":"test","id":null}`, false},
		{"no id field", `{"jsonrpc":"2.0","method":"test"}`, false},
		{"numeric id", `{"jsonrpc":"2.0","method":"test","id":1}`, true},
		{"string id", `{"jsonrpc":"2.0","method":"test","id":"abc"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasID([]byte(tt.msg))
			if got != tt.want {
				t.Errorf("hasID(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}

func TestController_APISource(t *testing.T) {
	cfg := testConfig()
	c := New(cfg)

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected inactive initially")
	}

	c.SetAPI(true)
	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active after SetAPI(true)")
	}
	if d.Source != "api" { //nolint:goconst // test value
		t.Errorf("expected source %q, got %q", "api", d.Source)
	}

	c.SetAPI(false)
	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected inactive after SetAPI(false)")
	}
}

func TestController_APIExempt(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)

	// /api/v1/killswitch is exempt by default
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected /api/v1/killswitch to be exempt from kill switch")
	}

	// /api/v1/killswitch/status is also exempt
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch/status", nil)
	d2 := c.IsActiveHTTP(r2)
	if d2.Active {
		t.Fatal("expected /api/v1/killswitch/status to be exempt")
	}

	// Non-API path is still blocked
	r3 := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d3 := c.IsActiveHTTP(r3)
	if !d3.Active {
		t.Fatal("expected /fetch to be blocked")
	}
}

func TestController_APIExemptDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.APIExempt = ptrBool(false)

	c := New(cfg)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected /api/v1/killswitch to be blocked when api_exempt disabled")
	}
}

func TestController_SourcePriority_WithAPI(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)
	c.SetAPI(true)
	c.ToggleSignal()
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)

	// All sources active — config wins
	d := c.IsActiveHTTP(r)
	if d.Source != "config" {
		t.Errorf("expected source %q, got %q", "config", d.Source)
	}

	// Disable config — api wins
	cfg2 := testConfig()
	cfg2.KillSwitch.SentinelFile = sentinelPath
	c.Reload(cfg2)
	d = c.IsActiveHTTP(r)
	if d.Source != "api" {
		t.Errorf("expected source %q, got %q", "api", d.Source)
	}

	// Disable api — signal wins
	c.SetAPI(false)
	d = c.IsActiveHTTP(r)
	if d.Source != "signal" {
		t.Errorf("expected source %q, got %q", "signal", d.Source)
	}

	// Disable signal — sentinel wins
	c.ToggleSignal()
	d = c.IsActiveHTTP(r)
	if d.Source != "sentinel" {
		t.Errorf("expected source %q, got %q", "sentinel", d.Source)
	}
}

func TestController_Sources(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.Enabled = true
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)
	c.SetAPI(true)

	sources := c.Sources()
	if !sources["config"] {
		t.Error("expected config source active")
	}
	if !sources["api"] {
		t.Error("expected api source active")
	}
	if sources["signal"] {
		t.Error("expected signal source inactive")
	}
	if sources["sentinel"] {
		t.Error("expected sentinel source inactive (file doesn't exist)")
	}
}

func TestController_SeparatePort_SkipsAPIExemption(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)
	c.SetSeparateAPIPort(true)

	// With separatePort=true, /api/v1/killswitch should NOT be exempt.
	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected /api/v1/killswitch to be BLOCKED when separatePort=true")
	}

	// /api/v1/killswitch/status should also be blocked.
	r2 := httptest.NewRequest(http.MethodGet, "/api/v1/killswitch/status", nil)
	d2 := c.IsActiveHTTP(r2)
	if !d2.Active {
		t.Fatal("expected /api/v1/killswitch/status to be BLOCKED when separatePort=true")
	}

	// /health and /metrics should still be exempt (separate from API exemption).
	rHealth := httptest.NewRequest(http.MethodGet, "/health", nil)
	if c.IsActiveHTTP(rHealth).Active {
		t.Fatal("expected /health to remain exempt when separatePort=true")
	}
	rMetrics := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if c.IsActiveHTTP(rMetrics).Active {
		t.Fatal("expected /metrics to remain exempt when separatePort=true")
	}
}

func TestController_SeparatePort_Default(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)
	// separatePort defaults to false — API should be exempt as before.

	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", nil)
	d := c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected /api/v1/killswitch to be exempt by default (separatePort=false)")
	}
}

func TestController_SeparatePort_Toggle(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Enabled = true

	c := New(cfg)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", nil)

	// Default: exempt.
	if c.IsActiveHTTP(r).Active {
		t.Fatal("expected exempt initially")
	}

	// Enable separate port: blocked.
	c.SetSeparateAPIPort(true)
	if !c.IsActiveHTTP(r).Active {
		t.Fatal("expected blocked after SetSeparateAPIPort(true)")
	}

	// Disable separate port: exempt again.
	c.SetSeparateAPIPort(false)
	if c.IsActiveHTTP(r).Active {
		t.Fatal("expected exempt after SetSeparateAPIPort(false)")
	}
}

func TestController_MultiSource_DeactivateAPI_OthersRemain(t *testing.T) {
	dir := t.TempDir()
	sentinelPath := filepath.Join(dir, "killswitch")

	cfg := testConfig()
	cfg.KillSwitch.SentinelFile = sentinelPath

	c := New(cfg)
	c.SetAPI(true)
	c.ToggleSignal()
	if err := os.WriteFile(sentinelPath, []byte("kill"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)

	// All three runtime sources active.
	d := c.IsActiveHTTP(r)
	if !d.Active || d.Source != "api" {
		t.Fatalf("expected active from api, got active=%v source=%q", d.Active, d.Source)
	}

	// Deactivate API — signal and sentinel remain.
	c.SetAPI(false)
	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected still active after deactivating API (signal+sentinel remain)")
	}
	if d.Source != "signal" {
		t.Errorf("expected source %q after API off, got %q", "signal", d.Source)
	}

	// Deactivate signal — sentinel remains.
	c.ToggleSignal()
	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected still active after deactivating signal (sentinel remains)")
	}
	if d.Source != "sentinel" {
		t.Errorf("expected source %q after signal off, got %q", "sentinel", d.Source)
	}

	// Remove sentinel — all off.
	if err := os.Remove(sentinelPath); err != nil {
		t.Fatal(err)
	}
	d = c.IsActiveHTTP(r)
	if d.Active {
		t.Fatal("expected inactive after all sources deactivated")
	}
}

func TestController_Reload_PreservesRuntimeState(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.Message = "before reload" //nolint:goconst // test value

	c := New(cfg)
	c.SetAPI(true)
	c.ToggleSignal()

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active || d.Source != "api" {
		t.Fatalf("pre-reload: expected active from api, got active=%v source=%q", d.Active, d.Source)
	}

	// Reload with different message — API and signal must survive.
	cfg2 := testConfig()
	cfg2.KillSwitch.Message = "after reload" //nolint:goconst // test value
	c.Reload(cfg2)

	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected active after reload (API and signal should be preserved)")
	}
	if d.Source != "api" {
		t.Errorf("expected source %q after reload, got %q", "api", d.Source)
	}
	if d.Message != "after reload" {
		t.Errorf("expected message %q after reload, got %q", "after reload", d.Message)
	}

	// Verify signal also survived reload.
	c.SetAPI(false)
	d = c.IsActiveHTTP(r)
	if !d.Active || d.Source != "signal" {
		t.Fatalf("expected signal survived reload, got active=%v source=%q", d.Active, d.Source)
	}
}

func TestController_APIHandler_Deactivate_PreservesOtherSources(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.APIToken = "test-token" //nolint:goconst,gosec // test value
	c := New(cfg)
	h := NewAPIHandler(c)

	// Activate both API and signal.
	c.SetAPI(true)
	c.ToggleSignal()

	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	d := c.IsActiveHTTP(r)
	if !d.Active || d.Source != "api" {
		t.Fatalf("expected active from api, got active=%v source=%q", d.Active, d.Source)
	}

	// Deactivate via the API handler (same as a real HTTP call).
	body := bytes.NewBufferString(`{"active": false}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/killswitch", body)
	req.Header.Set("Authorization", "Bearer test-token") //nolint:goconst // test value
	w := httptest.NewRecorder()
	h.HandleToggle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// API source off, but kill switch still active from signal.
	d = c.IsActiveHTTP(r)
	if !d.Active {
		t.Fatal("expected kill switch still active (signal source remains)")
	}
	if d.Source != "signal" {
		t.Errorf("expected source %q after API deactivation, got %q", "signal", d.Source)
	}

	// Verify the status endpoint reflects both sources correctly.
	sources := c.Sources()
	if sources["api"] {
		t.Error("expected api source to be false after deactivation")
	}
	if !sources["signal"] {
		t.Error("expected signal source to still be true")
	}
}

func TestController_Reload_InvalidCIDR(t *testing.T) {
	cfg := testConfig()
	c := New(cfg)

	// Reload with an invalid CIDR — should log to stderr and continue,
	// not panic.
	cfg2 := testConfig()
	cfg2.KillSwitch.Enabled = true
	cfg2.KillSwitch.Message = "test deny"
	cfg2.KillSwitch.AllowlistIPs = []string{"not-a-cidr", "10.0.0.0/8"}
	c.Reload(cfg2)

	// Non-allowlisted IP should be blocked (kill switch is enabled).
	r := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r.RemoteAddr = "192.168.1.1:12345"
	d := c.IsActiveHTTP(r)
	if !d.Active {
		t.Error("expected active — IP is not in allowlist and kill switch is enabled")
	}

	// Allowlisted IP should pass despite the kill switch (valid CIDR was processed).
	r2 := httptest.NewRequest(http.MethodGet, "/fetch", nil)
	r2.RemoteAddr = "10.0.0.1:12345"
	d2 := c.IsActiveHTTP(r2)
	if d2.Active {
		t.Error("expected inactive — IP should be in allowlist from the valid CIDR")
	}
}

func ptrBool(v bool) *bool { return &v }
