// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package killswitch implements an emergency deny-all controller for Pipelock.
// Six activation sources (config, API, Conductor remote kill, Conductor stale
// bundle, SIGUSR1, sentinel file) are OR-composed: any one being active engages
// the kill switch and denies all requests.
package killswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// EnvAPIToken is the environment variable that overrides kill_switch.api_token
// from the config file. When set to a non-empty value, it takes priority over
// the config file value. This allows Kubernetes deployments to source the token
// from a Secret (via env[].valueFrom.secretKeyRef) instead of a ConfigMap.
const EnvAPIToken = config.EnvKillSwitchAPIToken

// Decision describes the outcome of a kill switch check.
type Decision struct {
	Active         bool
	Message        string
	Source         string // "config", "api", "conductor_remote", "conductor_stale", "signal", "sentinel"
	IsNotification bool   // MCP only: true if the message has no "id" field
}

// Controller manages the kill switch state across six activation sources.
type Controller struct {
	cfg          atomic.Pointer[runtime]
	api          atomic.Bool
	sigusr1      atomic.Bool
	conductor    atomic.Bool
	conductorMsg atomic.Value
	// conductorStale is the autonomous fail-closed source: the follower's active
	// policy bundle aged past its grace window with no fresh bundle from the
	// leader. It is independent of conductorRemote (operator-driven remote kill)
	// so clearing one never clears the other - a follower can be both stale AND
	// remote-killed, and recovering from staleness must not lift an operator kill.
	conductorStale    atomic.Bool
	conductorStaleMsg atomic.Value
	separatePort      atomic.Bool // true when API runs on a dedicated port (no main-port exemption)
}

// runtime holds the parsed config state for atomic swap on reload.
type runtime struct {
	cfgEnabled    bool
	sentinelFile  string
	message       string
	healthExempt  bool
	metricsExempt bool
	apiExempt     bool
	apiToken      string
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
	if cfg.KillSwitch.APIExempt != nil {
		rt.apiExempt = *cfg.KillSwitch.APIExempt
	} else {
		rt.apiExempt = true
	}
	rt.apiToken = cfg.EffectiveKillSwitchAPIToken()

	for _, cidr := range cfg.KillSwitch.AllowlistIPs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pipelock: ignoring invalid CIDR in kill switch allowlist: %q: %v\n", cidr, err)
			continue
		}
		rt.allowlistNets = append(rt.allowlistNets, ipNet)
	}

	return rt
}

// IsActive returns true if the kill switch is currently active from any source.
// It checks all activation sources without applying any endpoint or IP
// exemptions. Use this for non-HTTP callers (e.g. the Scan API handler) that
// perform their own exemption logic.
func (c *Controller) IsActive() bool {
	return c.computeDecision(c.cfg.Load()).Active
}

// IsActiveForIP checks whether the kill switch should deny a request from
// the given client IP. Only checks IP allowlist exemptions - no path/endpoint
// exemptions. Use this inside intercepted CONNECT tunnels where request paths
// belong to the upstream origin, not to pipelock's own endpoints.
func (c *Controller) IsActiveForIP(clientIP string) Decision {
	rt := c.cfg.Load()
	if len(rt.allowlistNets) > 0 {
		if ip := net.ParseIP(clientIP); ip != nil {
			for _, ipNet := range rt.allowlistNets {
				if ipNet.Contains(ip) {
					return Decision{}
				}
			}
		}
	}
	return c.computeDecision(rt)
}

// IsActiveHTTP checks whether the kill switch should deny an HTTP request.
// Checks exemptions (health/metrics/API endpoints, allowlisted IPs) before
// computing the active state from all sources.
// isProxiedRequest reports whether r is a request to be PROXIED somewhere else
// rather than a request against pipelock's own endpoints. A forward-proxy
// request carries an absolute-URI request-target and CONNECT carries an
// authority-form one, so in neither case does the request path name a pipelock
// endpoint - it names a path on the DESTINATION host.
//
// Every endpoint exemption below must be gated on this, because those
// exemptions compare the request path against pipelock's own endpoint paths.
// Without the gate, a request for http://any-host/health takes the health
// exemption and is forwarded while the kill switch is active, which defeats the
// emergency control entirely. The gate lives in one helper consulted ahead of
// all exemptions so that any exemption added later inherits it by construction
// rather than by the next author remembering this.
func isProxiedRequest(r *http.Request) bool {
	if r.Method == http.MethodConnect {
		return true
	}
	return r.URL != nil && r.URL.IsAbs() && r.URL.Host != ""
}

func (c *Controller) IsActiveHTTP(r *http.Request) Decision {
	rt := c.cfg.Load()

	// Proxied traffic gets no endpoint exemption: the request path belongs to
	// the destination, not to pipelock. The IP allowlist is deliberately still
	// honoured here, because it keys on the CLIENT address rather than on a
	// path the client chooses.
	if isProxiedRequest(r) {
		if d := c.allowlistExempt(rt, r); d != nil {
			return *d
		}
		return c.computeDecision(rt)
	}

	// Check endpoint exemptions first. Compare on EscapedPath so an exemption
	// cannot be broader than the routes it is meant to cover: sessionAPIRouter
	// routes on EscapedPath, so matching the decoded path here would exempt
	// e.g. /api/v1/sessions/x/%74erminate, which the router then 404s.
	path := r.URL.EscapedPath()
	if rt.healthExempt && path == "/health" {
		return Decision{}
	}
	if rt.metricsExempt && path == "/metrics" {
		return Decision{}
	}

	// Check IP allowlist.
	if d := c.allowlistExempt(rt, r); d != nil {
		return *d
	}

	// Check API exemption. When the API runs on a separate port
	// (separatePort=true), the main port gets no exemption - the agent
	// cannot reach the API to self-deactivate the kill switch.
	if rt.apiExempt && !c.separatePort.Load() &&
		(path == "/api/v1/killswitch" || path == "/api/v1/killswitch/status" ||
			path == "/api/v1/sessions" ||
			IsSessionKeyPath(path) ||
			IsSessionActionPath(path, "reset") ||
			IsSessionActionPath(path, "airlock") ||
			IsSessionActionPath(path, "task") ||
			IsSessionActionPath(path, "trust") ||
			IsSessionActionPath(path, "explain") ||
			IsSessionActionPath(path, "terminate")) {
		return Decision{}
	}

	return c.computeDecision(rt)
}

// allowlistExempt returns a non-nil zero Decision when the request's client IP
// is allowlisted, and nil when it is not. Keyed on the client address, so it is
// safe to honour for proxied traffic: a client cannot choose its own source IP
// the way it chooses a request path.
func (c *Controller) allowlistExempt(rt *runtime, r *http.Request) *Decision {
	if len(rt.allowlistNets) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	clientIP := net.ParseIP(host)
	if clientIP == nil {
		return nil
	}
	for _, ipNet := range rt.allowlistNets {
		if ipNet.Contains(clientIP) {
			return &Decision{}
		}
	}
	return nil
}

// IsActiveMCP checks whether the kill switch should deny an MCP message.
// MCP has no health/metrics endpoints and no IP-based allowlisting, so this
// only checks the activation sources. It also detects whether the
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

// IsSessionActionPath validates that path matches the exact route structure
// /api/v1/sessions/{key}/{action} with exactly five segments and a non-empty
// key that contains no path separators or null bytes. This prevents traversal
// attacks like /api/v1/sessions/../../etc/passwd/airlock from matching.
func IsSessionActionPath(path, action string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) != 5 {
		return false
	}
	return segs[0] == "api" && segs[1] == "v1" && segs[2] == "sessions" &&
		segs[3] != "" && !strings.Contains(segs[3], "\x00") &&
		segs[4] == action
}

// IsSessionKeyPath validates that path matches /api/v1/sessions/{key} with
// exactly four segments and a non-empty key. Used by the admin API router
// to detect inspect lookups on the base session path. Applies the same
// traversal-prevention rules as IsSessionActionPath.
func IsSessionKeyPath(path string) bool {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) != 4 {
		return false
	}
	return segs[0] == "api" && segs[1] == "v1" && segs[2] == "sessions" &&
		segs[3] != "" && !strings.Contains(segs[3], "\x00")
}

// Reload updates the config-derived state atomically.
// The SIGUSR1 and API toggle states are preserved across reloads.
func (c *Controller) Reload(cfg *config.Config) {
	c.cfg.Store(buildRuntime(cfg))
}

// SetAPI sets the API activation source.
func (c *Controller) SetAPI(active bool) {
	c.api.Store(active)
}

// SetConductorRemote sets the Conductor remote-kill activation source.
func (c *Controller) SetConductorRemote(active bool, message string) {
	c.conductorMsg.Store(message)
	c.conductor.Store(active)
}

// SetConductorStale sets the Conductor stale-bundle activation source. The
// follower's stale enforcer engages this when the active policy bundle ages
// past its grace window under a strict_deny_all policy, and clears it once a
// fresh bundle restores a within-grace state. It is independent of the
// remote-kill source: clearing stale never lifts an operator remote kill, and
// vice versa.
func (c *Controller) SetConductorStale(active bool, message string) {
	c.conductorStaleMsg.Store(message)
	c.conductorStale.Store(active)
}

// SetSeparateAPIPort marks whether the kill switch API runs on a separate
// listener. When true, IsActiveHTTP skips the /api/v1/* exemption on the
// main port - the agent cannot reach the API to deactivate its own kill switch.
func (c *Controller) SetSeparateAPIPort(sep bool) {
	c.separatePort.Store(sep)
}

// Sources returns the current state of each activation source.
func (c *Controller) Sources() map[string]bool {
	rt := c.cfg.Load()
	sources := map[string]bool{
		"config":           rt.cfgEnabled,
		"api":              c.api.Load(),
		"signal":           c.sigusr1.Load(),
		"conductor_remote": c.conductor.Load(),
		"conductor_stale":  c.conductorStale.Load(),
	}
	if rt.sentinelFile != "" {
		_, err := os.Stat(rt.sentinelFile)
		sources["sentinel"] = err == nil || !errors.Is(err, os.ErrNotExist)
	} else {
		sources["sentinel"] = false
	}
	return sources
}

// computeDecision evaluates activation sources in priority order.
func (c *Controller) computeDecision(rt *runtime) Decision {
	// Priority: config > api > conductor_remote > conductor_stale > signal > sentinel.
	if rt.cfgEnabled {
		return Decision{Active: true, Message: rt.message, Source: "config"}
	}
	if c.api.Load() {
		return Decision{Active: true, Message: rt.message, Source: "api"}
	}
	if c.conductor.Load() {
		msg, _ := c.conductorMsg.Load().(string)
		if msg == "" {
			msg = rt.message
		}
		return Decision{Active: true, Message: msg, Source: "conductor_remote"}
	}
	if c.conductorStale.Load() {
		msg, _ := c.conductorStaleMsg.Load().(string)
		if msg == "" {
			msg = rt.message
		}
		return Decision{Active: true, Message: msg, Source: "conductor_stale"}
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
