// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// configuredListener describes a single listen address the operator configured
// in pipelock.yaml. The label is used in doctor output so an operator can
// tell which config field a collision came from. Address is preserved
// verbatim from the config (e.g. ":8888", "127.0.0.1:9090", "[::1]:8080")
// so the collision-detection logic can distinguish wildcard vs explicit
// bind addresses without re-parsing.
type configuredListener struct {
	Label   string // e.g. "fetch_proxy.listen"
	Address string // e.g. ":8888" or "127.0.0.1:9090"
}

// collectConfiguredListeners walks the pipelock config and returns every
// configured listen address with a stable label. Empty addresses are skipped
// (an unset listen field is not a collision risk).
func collectConfiguredListeners(cfg *config.Config) []configuredListener {
	out := make([]configuredListener, 0, 8)
	add := func(label, addr string) {
		if strings.TrimSpace(addr) != "" {
			out = append(out, configuredListener{Label: label, Address: addr})
		}
	}
	if cfg == nil {
		return out
	}
	add("fetch_proxy.listen", cfg.FetchProxy.Listen)
	add("kill_switch.api_listen", cfg.KillSwitch.APIListen)
	add("metrics_listen", cfg.MetricsListen)
	add("scan_api.listen", cfg.ScanAPI.Listen)
	add("reverse_proxy.listen", cfg.ReverseProxy.Listen)
	return out
}

// portFromListenAddr extracts the TCP port from a listen-address string
// (":8888", "127.0.0.1:9090", "[::1]:8080"). Returns 0 when the address has
// no explicit port (e.g. a plain hostname). The port-collision check skips
// zero ports because /proc only enumerates bound listeners.
func portFromListenAddr(addr string) (uint16, error) {
	if addr == "" {
		return 0, fmt.Errorf("empty listen address")
	}
	// Bare ":NNNN" is valid for net.SplitHostPort.
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("split host/port %q: %w", addr, err)
	}
	if portStr == "" {
		return 0, nil
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}
	return uint16(n), nil
}

// procListener identifies the process holding a TCP listen on a given port.
type procListener struct {
	Port    uint16
	IP      net.IP
	PID     int
	Cmdline string
}

// checkPortsReportLinesFromCfg builds the doctor checks for port collisions
// against every configured listener in cfg. The platform implementation
// lives in portcheck_{linux,other}.go.
func checkPortsReport(cfg *config.Config) []doctorReportCheck {
	listeners := collectConfiguredListeners(cfg)
	if len(listeners) == 0 {
		return []doctorReportCheck{{
			Name:    "port_collisions",
			Surface: doctorSurfaceHost,
			Status:  doctorStatusInfo,
			Detail:  "no listener addresses configured; nothing to check",
		}}
	}

	holders, err := enumerateListenerHolders()
	if err != nil {
		// Non-Linux or /proc unreadable: emit info, not failure. Operators
		// running on macOS/Windows still get a clear "we didn't check" line
		// rather than a spurious pass.
		return []doctorReportCheck{{
			Name:    "port_collisions",
			Surface: doctorSurfaceHost,
			Status:  doctorStatusInfo,
			Detail:  "port-collision check unavailable: " + err.Error(),
			Next:    "run pipelock doctor --check-ports on a Linux host with /proc to identify processes holding configured listener ports",
		}}
	}

	checks := make([]doctorReportCheck, 0, len(listeners))
	for _, l := range listeners {
		port, perr := portFromListenAddr(l.Address)
		switch {
		case perr != nil:
			checks = append(checks, doctorReportCheck{
				Name:       "port_collisions:" + l.Label,
				Surface:    doctorSurfaceHost,
				Status:     doctorStatusWarn,
				Configured: true,
				Detail:     fmt.Sprintf("could not parse listen address %q: %v", l.Address, perr),
			})
		case port == 0:
			checks = append(checks, doctorReportCheck{
				Name:       "port_collisions:" + l.Label,
				Surface:    doctorSurfaceHost,
				Status:     doctorStatusInfo,
				Configured: true,
				Detail:     fmt.Sprintf("listen address %q has no explicit port; skipped", l.Address),
			})
		default:
			checks = append(checks, evaluateListenerCollision(l, port, holders))
		}
	}
	return checks
}

// evaluateListenerCollision compares one configured listener against the
// per-port holder map. Returns an OK check when no other process holds the
// port, or a warn check naming the conflicting PID + cmdline.
func evaluateListenerCollision(l configuredListener, port uint16, holders map[uint16][]procListener) doctorReportCheck {
	check := doctorReportCheck{
		Name:       "port_collisions:" + l.Label,
		Surface:    doctorSurfaceHost,
		Configured: true,
	}
	holder, ok := firstCollidingHolder(l.Address, holders[port])
	if !ok {
		check.Status = doctorStatusOK
		check.Detail = fmt.Sprintf("port %d (%s) is free", port, l.Address)
		return check
	}
	check.Status = doctorStatusWarn
	if holder.PID == os.Getpid() {
		// pipelock itself is holding the port — this is the doctor running
		// against a live process. Surface as OK, not a collision.
		check.Status = doctorStatusOK
		check.Detail = fmt.Sprintf("port %d (%s) held by this pipelock process (pid %d)", port, l.Address, holder.PID)
		return check
	}
	if holder.PID == 0 {
		// Holder identified by inode in /proc/net/tcp but no /proc/<pid>/fd
		// entry pointed to that inode — typical when the holder runs as a
		// different user and the doctor wasn't run as root.
		check.Detail = fmt.Sprintf("port %d (%s) is held by another process; run as root to identify it", port, l.Address)
		check.Next = "rerun `pipelock doctor --check-ports` as root, OR use `ss -tlnp | grep :" + strconv.Itoa(int(port)) + "` to identify the holder"
		return check
	}
	check.Detail = fmt.Sprintf("port %d (%s) already in use by pid %d (%s)", port, l.Address, holder.PID, truncateCmdline(holder.Cmdline))
	check.Next = "stop the conflicting process or move pipelock's " + l.Label + " to a free port"
	return check
}

func firstCollidingHolder(configuredAddr string, holders []procListener) (procListener, bool) {
	for _, holder := range holders {
		if listenerAddressesMayCollide(configuredAddr, holder.IP) {
			return holder, true
		}
	}
	return procListener{}, false
}

func listenerAddressesMayCollide(configuredAddr string, holderIP net.IP) bool {
	host, _, err := net.SplitHostPort(configuredAddr)
	if err != nil {
		// portFromListenAddr already parsed this address. If that changes,
		// be conservative and surface the possible collision.
		return true
	}
	if host == "" {
		return true
	}
	configuredIP := net.ParseIP(host)
	if configuredIP == nil {
		// Hostnames can resolve to the holder address. Avoid a false "free".
		return true
	}
	if holderIP == nil {
		return true
	}
	configuredIs4 := configuredIP.To4() != nil
	holderIs4 := holderIP.To4() != nil
	if configuredIP.IsUnspecified() {
		// 0.0.0.0 only overlaps IPv4 holders. :: may overlap IPv4 holders
		// on dual-stack sockets, so keep that side conservative.
		return !configuredIs4 || holderIs4
	}
	if holderIP.IsUnspecified() {
		// An existing 0.0.0.0 listener does not block a later explicit IPv6
		// loopback bind; an existing :: listener might be dual-stack.
		return !holderIs4 || configuredIs4
	}
	if configuredIs4 != holderIs4 {
		return false
	}
	return configuredIP.Equal(holderIP)
}

// truncateCmdline keeps doctor output readable when the conflicting process
// has a long argv.
func truncateCmdline(s string) string {
	const maxLen = 120
	s = strings.TrimSpace(s)
	if s == "" {
		return "(empty)"
	}
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

// readProcCmdline reads /proc/<pid>/cmdline and converts NUL separators back
// to spaces. Returns "" on error.
func readProcCmdline(pid int) string {
	path := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	data, err := os.ReadFile(path) // #nosec G304 -- /proc path constructed from numeric PID
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
}
