// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestPortFromListenAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		want    uint16
		wantErr bool
	}{
		{"bare-port", ":8888", 8888, false},
		{"loopback-port", "127.0.0.1:9090", 9090, false},
		{"ipv6-loopback", "[::1]:8080", 8080, false},
		{"empty", "", 0, true},
		{"bad-format", "not-a-host-port", 0, true},
		{"non-numeric-port", "127.0.0.1:abc", 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := portFromListenAddr(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("port = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCollectConfiguredListeners(t *testing.T) {
	cfg := &config.Config{}
	cfg.FetchProxy.Listen = ":8888"
	cfg.KillSwitch.APIListen = "127.0.0.1:9090"
	cfg.MetricsListen = "" // skipped because empty
	cfg.ReverseProxy.Listen = "127.0.0.1:8892"

	got := collectConfiguredListeners(cfg)
	labels := make([]string, len(got))
	for i, l := range got {
		labels[i] = l.Label
	}
	wantLabels := []string{"fetch_proxy.listen", "kill_switch.api_listen", "reverse_proxy.listen"}
	if len(labels) != len(wantLabels) {
		t.Fatalf("labels = %v, want %v", labels, wantLabels)
	}
	for i, l := range labels {
		if l != wantLabels[i] {
			t.Errorf("labels[%d] = %q, want %q", i, l, wantLabels[i])
		}
	}
}

func TestCheckPortsReport_NoListeners(t *testing.T) {
	report := checkPortsReport(&config.Config{})
	if len(report) != 1 {
		t.Fatalf("len(report) = %d, want 1", len(report))
	}
	if report[0].Status != doctorStatusInfo {
		t.Errorf("status = %q, want %q", report[0].Status, doctorStatusInfo)
	}
}

// TestCheckPortsReport_DetectsOwnListener verifies that when this test process
// holds a TCP listener on a port that the cfg references, the port check
// surfaces an OK status (because the holding PID matches os.Getpid()) rather
// than a collision warning. Linux-only because /proc is the data source.
func TestCheckPortsReport_DetectsOwnListener(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("requires Linux /proc; current GOOS=%s", runtime.GOOS)
	}
	// Bind a real listener so /proc/net/tcp will show us in LISTEN state.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	host, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		t.Fatalf("port not numeric: %v", err)
	}

	cfg := &config.Config{}
	cfg.FetchProxy.Listen = net.JoinHostPort(host, portStr)
	checks := checkPortsReport(cfg)

	var found bool
	for _, c := range checks {
		if !strings.HasPrefix(c.Name, "port_collisions:fetch_proxy.listen") {
			continue
		}
		found = true
		// Either OK (own process) or warn (when /proc enumerates a different
		// PID first, e.g. when running as a different uid). Both are valid
		// signals that the check is functioning. A "free" report would mean
		// the kernel didn't see our listener, which is the test failure mode.
		if c.Status == doctorStatusOK && strings.Contains(c.Detail, "held by this pipelock process") {
			return
		}
		if c.Status == doctorStatusWarn && strings.Contains(c.Detail, "is held by another process") {
			// Acceptable: /proc-restricted execution can't tie the inode to
			// our own PID. The check still surfaces the collision.
			return
		}
		t.Errorf("unexpected check for fetch_proxy.listen: status=%q detail=%q", c.Status, c.Detail)
	}
	if !found {
		t.Errorf("no port_collisions check for fetch_proxy.listen; got %d checks", len(checks))
	}
}

func TestEvaluateListenerCollision_RespectsListenAddress(t *testing.T) {
	tests := []struct {
		name           string
		configuredAddr string
		holderIP       net.IP
		wantStatus     string
	}{
		{
			name:           "different loopback address is free",
			configuredAddr: "127.0.0.1:8888",
			holderIP:       net.ParseIP("127.0.0.2"),
			wantStatus:     doctorStatusOK,
		},
		{
			name:           "holder wildcard collides with specific address",
			configuredAddr: "127.0.0.1:8888",
			holderIP:       net.ParseIP("0.0.0.0"),
			wantStatus:     doctorStatusWarn,
		},
		{
			name:           "configured wildcard collides with specific holder",
			configuredAddr: ":8888",
			holderIP:       net.ParseIP("127.0.0.2"),
			wantStatus:     doctorStatusWarn,
		},
		{
			name:           "same specific address collides",
			configuredAddr: "127.0.0.1:8888",
			holderIP:       net.ParseIP("127.0.0.1"),
			wantStatus:     doctorStatusWarn,
		},
		{
			name:           "different IP families are free",
			configuredAddr: "[::1]:8888",
			holderIP:       net.ParseIP("127.0.0.1"),
			wantStatus:     doctorStatusOK,
		},
		{
			name:           "ipv4 wildcard does not collide with explicit ipv6",
			configuredAddr: "[::1]:8888",
			holderIP:       net.ParseIP("0.0.0.0"),
			wantStatus:     doctorStatusOK,
		},
		{
			name:           "ipv6 wildcard may collide with explicit ipv4",
			configuredAddr: "127.0.0.1:8888",
			holderIP:       net.ParseIP("::"),
			wantStatus:     doctorStatusWarn,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			check := evaluateListenerCollision(
				configuredListener{Label: "fetch_proxy.listen", Address: tc.configuredAddr},
				8888,
				map[uint16][]procListener{
					8888: {{Port: 8888, IP: tc.holderIP, PID: os.Getpid() + 1000000, Cmdline: "holder"}},
				},
			)
			if check.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q; detail=%q", check.Status, tc.wantStatus, check.Detail)
			}
		})
	}
}

func TestTruncateCmdline(t *testing.T) {
	short := "/usr/bin/short-cmd --flag"
	if got := truncateCmdline(short); got != short {
		t.Errorf("short cmd was truncated: %q", got)
	}
	long := strings.Repeat("argument ", 30)
	got := truncateCmdline(long)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("long cmd was not truncated with ellipsis: %q", got)
	}
	if got := truncateCmdline("   "); got != "(empty)" {
		t.Errorf("whitespace cmd = %q, want (empty)", got)
	}
}

func TestReadProcCmdline_NonexistentPID(t *testing.T) {
	// PID 0 is the swapper/idle thread and its cmdline is unreadable.
	// readProcCmdline returns "" on any read error.
	got := readProcCmdline(0)
	if got != "" {
		t.Errorf("readProcCmdline(0) = %q, want empty", got)
	}
	// Also check a clearly-bogus PID.
	got = readProcCmdline(os.Getpid() + 999999)
	if got != "" {
		t.Errorf("readProcCmdline(huge) = %q, want empty", got)
	}
}
