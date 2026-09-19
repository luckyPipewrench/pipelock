// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	loopbackNamespaceHelperEnv     = "PIPELOCK_TEST_LOOPBACK_NAMESPACE_HELPER"
	loopbackNamespaceUnavailable   = "loopback namespace capability unavailable"
	loopbackNamespaceTimeout       = 5 * time.Second
	loopbackNamespaceHelperTimeout = 4 * loopbackNamespaceTimeout
	loopbackNamespaceTable         = "pipelock_loopback_test"
)

func TestLoopbackServiceSameUIDCompletionInNamespace(t *testing.T) {
	if os.Getenv(loopbackNamespaceHelperEnv) != "" {
		testLoopbackServiceSameUIDCompletionInNamespaceHelper(t)
		return
	}
	for _, binary := range []string{"ip", "nft"} {
		if _, err := exec.LookPath(binary); err != nil {
			t.Skipf("namespace test prerequisite %s unavailable: %v", binary, err)
		}
	}

	for _, tc := range []struct {
		name   string
		family string
	}{
		{name: "IPv4", family: "ipv4"},
		{name: "IPv6", family: "ipv6"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output, err := runLoopbackNamespaceHelper(tc.family)
			if strings.Contains(output, loopbackNamespaceUnavailable) {
				t.Skipf("%s", oneLine(output))
			}
			if err != nil && strings.TrimSpace(output) == "" &&
				(errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)) {
				t.Skipf("%s: create user/network namespace: %v", loopbackNamespaceUnavailable, err)
			}
			if err == nil {
				return
			}
			t.Fatalf("namespace helper for %s failed: %v\n%s", tc.family, err, output)
		})
	}
}

func runLoopbackNamespaceHelper(family string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceHelperTimeout)
	defer cancel()
	// #nosec G204,G702 -- os.Args[0] is the current Go test binary, re-executed with fixed test flags.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoopbackServiceSameUIDCompletionInNamespace$", "-test.v")
	cmd.Env = append(os.Environ(), loopbackNamespaceHelperEnv+"="+family)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:                 syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
	}
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func testLoopbackServiceSameUIDCompletionInNamespaceHelper(t *testing.T) {
	t.Helper()
	namespaceRequireCapability(t)
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
		defer cleanupCancel()
		_ = exec.CommandContext(cleanupCtx, "nft", "delete", "table", "inet", loopbackNamespaceTable).Run()
	})

	host, network := namespaceLoopbackFamily(t)
	listener := namespaceListener(t, network, host)
	servicePort := listener.Addr().(*net.TCPAddr).Port

	paired := namespaceLoopbackRules(host, servicePort, true, true)
	forwardOnly := namespaceLoopbackRules(host, servicePort, true, false)
	replyOnly := namespaceLoopbackRules(host, servicePort, false, true)
	if paired == forwardOnly || paired == replyOnly || forwardOnly == replyOnly {
		t.Fatal("rule mutations must produce three distinct nft fixtures")
	}

	loadNamespaceRules(t, paired)
	namespaceAssertCompletion(t, network, listener.Addr().String())

	loadNamespaceRules(t, forwardOnly)
	namespaceAssertRejected(t, network, listener.Addr().String(), "missing established reply rule")

	loadNamespaceRules(t, replyOnly)
	namespaceAssertRejected(t, network, listener.Addr().String(), "missing forward rule")

	loadNamespaceRules(t, paired)
	namespaceAssertCompletion(t, network, listener.Addr().String())
	if network == "tcp4" {
		namespaceAssertCompletionFromAlternateLoopbackAddress(t, network, listener.Addr().String())
		namespaceAssertNewSourcePortRejected(t, host, servicePort, listener)
	}
}

func namespaceRequireCapability(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ip", "link", "set", "lo", "up").CombinedOutput()
	if err != nil {
		namespaceCapabilityFailure(t, "bring loopback up", err, output)
	}
	output, err = exec.CommandContext(ctx, "nft", "add", "table", "inet", loopbackNamespaceTable).CombinedOutput()
	if err != nil {
		namespaceCapabilityFailure(t, "create nft table", err, output)
	}
}

func namespaceCapabilityFailure(t *testing.T, operation string, err error, output []byte) {
	t.Helper()
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("namespace capability check %s timed out: %v\n%s", operation, err, output)
	}
	if strings.Contains(strings.ToLower(string(output)), "operation not permitted") ||
		strings.Contains(strings.ToLower(string(output)), "permission denied") {
		t.Skipf("%s: %s: %v\n%s", loopbackNamespaceUnavailable, operation, err, output)
	}
	t.Fatalf("namespace capability check %s: %v\n%s", operation, err, output)
}

func namespaceLoopbackFamily(t *testing.T) (string, string) {
	t.Helper()
	switch os.Getenv(loopbackNamespaceHelperEnv) {
	case "ipv4":
		return "127.0.0.1", "tcp4"
	case "ipv6":
		return "::1", "tcp6"
	default:
		t.Fatalf("unknown namespace loopback family %q", os.Getenv(loopbackNamespaceHelperEnv))
		return "", ""
	}
}

func namespaceListener(t *testing.T, network, host string) net.Listener {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen %s: %v", network, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func namespaceLoopbackRules(host string, servicePort int, forward, reply bool) string {
	rules := renderNFTRulesWithServices(nftRuleOptions{
		OperatorUID: 1,
		ProxyUID:    2,
		AgentUID:    0,
		ProxyPort:   1,
		Table:       loopbackNamespaceTable,
		Chain:       "output_filter",
		LoopbackServices: []config.ContainmentLoopbackService{{
			Host: host,
			Port: servicePort,
		}},
	})
	serviceRules := nftLoopbackAcceptLines(0, host, servicePort)
	forwardRule, replyRule, ok := strings.Cut(serviceRules, "\n")
	if !ok {
		panic("declared loopback renderer omitted reply rule")
	}
	if !forward {
		rules = namespaceWithoutRenderedRule(rules, forwardRule)
	}
	if !reply {
		rules = namespaceWithoutRenderedRule(rules, replyRule)
	}
	return rules
}

func namespaceWithoutRenderedRule(rules, renderedRule string) string {
	lines := strings.Split(rules, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) == strings.TrimSpace(renderedRule) {
			return strings.Join(append(lines[:i], lines[i+1:]...), "\n")
		}
	}
	panic("declared loopback renderer rule missing from managed ruleset")
}

func loadNamespaceRules(t *testing.T, rules string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", loopbackNamespaceTable).Run()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("load namespace nft rules: %v\n%s", err, output)
	}
	listed, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", loopbackNamespaceTable).CombinedOutput()
	if err != nil {
		t.Fatalf("list namespace nft rules: %v\n%s", err, listed)
	}
	if !strings.Contains(string(listed), "meta skuid 0 counter") || !strings.Contains(string(listed), " drop") {
		t.Fatalf("loaded namespace fixture is missing its catch-all drop:\n%s", listed)
	}
	for _, predicate := range []string{"tcp dport", "ct state established ct direction reply"} {
		want := strings.Contains(rules, predicate)
		got := strings.Contains(string(listed), predicate)
		if got != want {
			t.Fatalf("namespace fixture mutation for %q did not take effect: want present=%t, got present=%t\n%s", predicate, want, got, listed)
		}
	}
}

func namespaceAssertCompletion(t *testing.T, network, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	// A successful TCP dial completes the three-way handshake. The listener and
	// client share the namespace UID, so the server's SYN-ACK must pass the
	// paired reply rule in this OUTPUT chain.
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		t.Fatalf("same-UID loopback dial did not complete: %v", err)
	}
	defer func() { _ = conn.Close() }()
}

// namespaceAssertCompletionFromAlternateLoopbackAddress proves the reply rule
// matches the declared service's source address. A connection from 127.0.0.2
// to a service declared at 127.0.0.1 has a SYN-ACK source of 127.0.0.1 and a
// destination of 127.0.0.2, so a reply daddr match would time out here.
func namespaceAssertCompletionFromAlternateLoopbackAddress(t *testing.T, network, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		t.Fatalf("alternate-loopback source dial did not complete: %v", err)
	}
	defer func() { _ = conn.Close() }()
}

func namespaceAssertRejected(t *testing.T, network, address, rejected string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s unexpectedly allowed a same-UID loopback connection", rejected)
	}
	if !namespaceDialTimedOut(ctx, err) {
		t.Fatalf("%s rejected with %v, want a timeout from the nft drop", rejected, err)
	}
}

func namespaceDialTimedOut(ctx context.Context, err error) bool {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return true
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && networkErr.Timeout()
}

// namespaceAssertNewSourcePortRejected proves the reply rule's conntrack
// predicates are what refuse a NEW flow, rather than an address or port
// predicate refusing it first. The packet is built to satisfy every other
// predicate the reply rule carries: it leaves over the loopback interface,
// from the declared service address, from the declared service source port.
// Only `ct state established ct direction reply` can reject it. It is aimed at
// a DIFFERENT listener so the forward rule, which matches the declared
// destination port, cannot admit it either.
//
// Freeing the declared port first is what makes that possible: while the
// service still holds it, the dialer cannot bind it as a source, and an
// earlier version of this test dialed from another loopback address instead.
// That version passed with the conntrack predicates removed entirely, so it
// proved nothing.
func namespaceAssertNewSourcePortRejected(t *testing.T, host string, servicePort int, service net.Listener) {
	t.Helper()
	if err := service.Close(); err != nil {
		t.Fatalf("close declared service listener to free port %d: %v", servicePort, err)
	}
	target := namespaceListener(t, "tcp4", host)
	newCtx, cancel := context.WithTimeout(context.Background(), loopbackNamespaceTimeout)
	defer cancel()
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(host), Port: servicePort}}
	conn, err := dialer.DialContext(newCtx, "tcp4", target.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("a NEW flow matching the reply rule's address and source port passed: the conntrack state and direction predicates are not enforcing")
	}
	if !namespaceDialTimedOut(newCtx, err) {
		t.Fatalf("NEW flow from %s:%d rejected with %v, want a timeout from the nft drop", host, servicePort, err)
	}
}
