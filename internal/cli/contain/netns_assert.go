// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

type netnsAssertEnv struct {
	agentUser   string
	proxyPort   int
	euid        func() int
	lookup      lookupUserFunc
	runCmd      runCommand
	readFile    func(string) ([]byte, error)
	readLink    func(string) (string, error)
	interfaces  func() ([]net.Interface, error)
	proxyHealth func(context.Context, int) error
}

func defaultNetnsAssertEnv() netnsAssertEnv {
	return netnsAssertEnv{
		agentUser:   defaultAgentUser,
		proxyPort:   defaultProxyPort,
		euid:        os.Geteuid,
		lookup:      user.Lookup,
		runCmd:      realRunCommand,
		readFile:    os.ReadFile,
		readLink:    os.Readlink,
		interfaces:  net.Interfaces,
		proxyHealth: directContainedProxyHealth,
	}
}

func netnsAssertCmd() *cobra.Command {
	env := defaultNetnsAssertEnv()
	cmd := &cobra.Command{
		Use:           "assert-agent-netns",
		Short:         "Refuse a tool launch outside the managed agent namespace",
		Hidden:        true,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := assertAgentNetworkNamespace(cmd.Context(), env); err != nil {
				return cliutil.ExitCodeError(cliutil.ExitConfig, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&env.agentUser, "agent-user", defaultAgentUser, "managed agent user whose namespace is required")
	cmd.Flags().IntVar(&env.proxyPort, "proxy-port", defaultProxyPort, "contained proxy doorway port that must be reachable")
	return cmd
}

// assertAgentNetworkNamespace runs immediately before plk-launch execs an
// allow-listed tool. systemd unit properties describe intent; these identity
// comparisons prove the process actually occupies the managed namespace.
func assertAgentNetworkNamespace(ctx context.Context, env netnsAssertEnv) error {
	agent, err := env.lookup(env.agentUser)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", env.agentUser, err)
	}
	wantUID, err := strconv.Atoi(agent.Uid)
	if err != nil || wantUID <= 0 {
		return fmt.Errorf("%s has invalid uid %q", env.agentUser, agent.Uid)
	}
	if got := env.euid(); got != wantUID {
		return fmt.Errorf("launcher has effective uid %d, want %s uid %d", got, env.agentUser, wantUID)
	}
	return assertManagedNetworkNamespace(ctx, env)
}

// assertManagedNetworkNamespace proves that the calling process is inside the
// exact managed namespace and can use only its loopback proxy doorway. It does
// not constrain the caller's uid, so a short root pre-start signer can attest
// what it directly observed before the unprivileged service body starts.
func assertManagedNetworkNamespace(ctx context.Context, env netnsAssertEnv) error {
	out, code, err := env.runCmd(ctx, containSystemctlPath, "is-active", "--quiet", containedNetworkNamespaceUnit)
	if err != nil {
		return fmt.Errorf("check managed network namespace: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("managed network namespace is not active (systemctl exit %d: %s); run `pipelock contain install`", code, oneLine(out))
	}
	identity, err := env.readFile(containedNamespaceIdentityPath)
	if err != nil {
		return fmt.Errorf("read managed network namespace identity: %w", err)
	}
	wantNamespace := strings.TrimSpace(string(identity))
	if !strings.HasPrefix(wantNamespace, "net:[") || !strings.HasSuffix(wantNamespace, "]") {
		return fmt.Errorf("managed network namespace identity %q is malformed; rerun `pipelock contain install`", oneLine(string(identity)))
	}
	inode := strings.TrimSuffix(strings.TrimPrefix(wantNamespace, "net:["), "]")
	if _, err := strconv.ParseUint(inode, 10, 64); err != nil {
		return fmt.Errorf("managed network namespace identity %q is malformed; rerun `pipelock contain install`", oneLine(string(identity)))
	}
	selfNamespace, err := env.readLink("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("read launcher network namespace identity: %w", err)
	}
	if selfNamespace != wantNamespace {
		return fmt.Errorf("launcher network namespace %s does not match managed namespace %s; refusing tool launch", selfNamespace, wantNamespace)
	}

	interfaces, err := env.interfaces()
	if err != nil {
		return fmt.Errorf("list launcher network interfaces: %w", err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagLoopback == 0 {
		names := make([]string, 0, len(interfaces))
		for _, iface := range interfaces {
			names = append(names, iface.Name)
		}
		return fmt.Errorf("launcher network namespace exposes interfaces %v, want only loopback; refusing tool launch", names)
	}
	if err := env.proxyHealth(ctx, env.proxyPort); err != nil {
		return fmt.Errorf("contained proxy doorway is not healthy on 127.0.0.1:%d: %w", env.proxyPort, err)
	}
	return nil
}

func directContainedProxyHealth(ctx context.Context, port int) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/health", port), nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", resp.StatusCode)
	}
	return nil
}

const (
	selfNetworkNamespacePath = "/proc/self/ns/net"
	hostNetworkNamespacePath = "/proc/1/ns/net"
	// nsenterPath joins the initial namespace for the host-side half of
	// service-posture.
	nsenterPath = "/usr/bin/nsenter"
)

// requireHostNetworkNamespace fails closed unless the calling process is in the
// initial network namespace (the one PID 1 holds). Unreadable identity is a
// refusal, never a pass.
func requireHostNetworkNamespace(readLink func(string) (string, error)) error {
	if readLink == nil {
		return errors.New("network namespace identity reader is unavailable")
	}
	self, err := readLink(selfNetworkNamespacePath)
	if err != nil {
		return fmt.Errorf("read own network namespace identity: %w", err)
	}
	host, err := readLink(hostNetworkNamespacePath)
	if err != nil {
		return fmt.Errorf("read host network namespace identity: %w", err)
	}
	if self == "" || self != host {
		return fmt.Errorf("process network namespace %q is not the host network namespace %q; refusing to evaluate host containment state from another namespace", self, host)
	}
	return nil
}

// hostNamespaceCommandArgs builds the nsenter argv that re-runs this binary in
// the initial network namespace.
func hostNamespaceCommandArgs(self string, args []string) []string {
	out := []string{"--net=" + hostNetworkNamespacePath, "--", self}
	return append(out, args...)
}

// runInHostNetworkNamespace re-executes this binary with args in the initial
// network namespace, streaming its output. The caller is root; joining a
// namespace needs CAP_SYS_ADMIN, which systemd's credential prefix keeps.
func runInHostNetworkNamespace(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate pipelock binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, nsenterPath, hostNamespaceCommandArgs(self, args)...) //nolint:gosec // G204: fixed nsenter path; argv is this binary plus validated flags and the registered tool name.
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run host-namespace preflight: %w", err)
	}
	return nil
}
