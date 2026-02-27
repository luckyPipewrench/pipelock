// Package killswitch implements an emergency deny-all controller for Pipelock.
// Three activation sources (config, SIGUSR1, sentinel file) are OR-composed:
// any one being active engages the kill switch and denies all requests.
package killswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Decision describes the outcome of a kill switch check.
type Decision struct {
	Active         bool
	Message        string
	Source         string // "config", "signal", "sentinel"
	IsNotification bool   // MCP only: true if the message has no "id" field
}

// Controller manages the kill switch state across three activation sources.
type Controller struct {
	cfg     atomic.Pointer[runtime]
	sigusr1 atomic.Bool
}

// runtime holds the parsed config state for atomic swap on reload.
type runtime struct {
	cfgEnabled    bool
	sentinelFile  string
	message       string
	healthExempt  bool
	metricsExempt bool
	allowlistNets []*net.IPNet
}

// New creates a Controller from the current config.
func New(cfg *config.Config) *Controller {
	c := &Controller{}
	c.cfg.Store(buildRuntime(cfg))
	return c
}

// buildRuntime parses config into the runtime struct.
func buildRuntime(cfg *config.Config) *runtime {
	rt := &runtime{
		cfgEnabled:   cfg.KillSwitch.Enabled,
		sentinelFile: cfg.KillSwitch.SentinelFile,
		message:      cfg.KillSwitch.Message,
	}

	if cfg.KillSwitch.HealthExempt != nil {
		rt.healthExempt = *cfg.KillSwitch.HealthExempt
	} else {
		rt.healthExempt = true
	}
	if cfg.KillSwitch.MetricsExempt != nil {
		rt.metricsExempt = *cfg.KillSwitch.MetricsExempt
	} else {
		rt.metricsExempt = true
	}

	for _, cidr := range cfg.KillSwitch.AllowlistIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			// config.Validate guarantees all CIDRs are valid. If we reach
			// here, it is a programming error in the reload path.
			panic(fmt.Sprintf("BUG: kill switch CIDR %q failed after validation: %v", cidr, err))
		}
		rt.allowlistNets = append(rt.allowlistNets, ipNet)
	}

	return rt
}

// IsActiveHTTP checks whether the kill switch should deny an HTTP request.
// Checks exemptions (health/metrics endpoints, allowlisted IPs) before
// computing the active state from the three sources.
func (c *Controller) IsActiveHTTP(r *http.Request) Decision {
	rt := c.cfg.Load()

	// Check endpoint exemptions first.
	path := r.URL.Path
	if rt.healthExempt && path == "/health" {
		return Decision{}
	}
	if rt.metricsExempt && path == "/metrics" {
		return Decision{}
	}

	// Check IP allowlist.
	if len(rt.allowlistNets) > 0 {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if clientIP := net.ParseIP(host); clientIP != nil {
			for _, ipNet := range rt.allowlistNets {
				if ipNet.Contains(clientIP) {
					return Decision{}
				}
			}
		}
	}

	return c.computeDecision(rt)
}

// IsActiveMCP checks whether the kill switch should deny an MCP message.
// MCP has no health/metrics endpoints and no IP-based allowlisting, so this
// only checks the three activation sources. It also detects whether the
// message is a notification (no "id" field) for the caller to decide
// whether to drop silently or send a JSON-RPC error.
func (c *Controller) IsActiveMCP(msg []byte) Decision {
	rt := c.cfg.Load()
	d := c.computeDecision(rt)
	if d.Active {
		d.IsNotification = !hasID(msg)
	}
	return d
}

// ToggleSignal flips the SIGUSR1 activation source and returns the new state.
func (c *Controller) ToggleSignal() bool {
	// atomic.Bool doesn't have a toggle method, so use CompareAndSwap in a loop.
	for {
		current := c.sigusr1.Load()
		if c.sigusr1.CompareAndSwap(current, !current) {
			return !current
		}
	}
}

// Reload updates the config-derived state atomically.
// The SIGUSR1 toggle state is preserved across reloads.
func (c *Controller) Reload(cfg *config.Config) {
	c.cfg.Store(buildRuntime(cfg))
}

// computeDecision evaluates the three activation sources in priority order.
func (c *Controller) computeDecision(rt *runtime) Decision {
	// Priority: config > signal > sentinel.
	if rt.cfgEnabled {
		return Decision{Active: true, Message: rt.message, Source: "config"}
	}
	if c.sigusr1.Load() {
		return Decision{Active: true, Message: rt.message, Source: "signal"}
	}
	if rt.sentinelFile != "" {
		_, err := os.Stat(rt.sentinelFile)
		if err == nil {
			return Decision{Active: true, Message: rt.message, Source: "sentinel"}
		}
		// Fail closed: if stat fails for any reason other than file-not-found
		// (e.g. permission denied, broken symlink), treat as active. An
		// attacker should not be able to bypass the kill switch by making the
		// sentinel file unreadable.
		if !errors.Is(err, os.ErrNotExist) {
			return Decision{Active: true, Message: rt.message, Source: "sentinel"}
		}
	}
	return Decision{}
}

// hasID checks if a JSON message contains an "id" field (i.e., is a request,
// not a notification). A notification has no "id" or "id": null.
func hasID(msg []byte) bool {
	var env struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(msg, &env) != nil {
		return false
	}
	return len(env.ID) > 0 && string(env.ID) != "null"
}

// ErrorResponse builds a JSON-RPC 2.0 error response for a kill switch
// denial. Uses error code -32004 (implementation-defined range).
func ErrorResponse(id json.RawMessage, message string) []byte {
	resp := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{
		JSONRPC: "2.0",
		ID:      id,
	}
	resp.Error.Code = -32004
	resp.Error.Message = message
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}
