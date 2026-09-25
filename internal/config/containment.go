// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ContainmentManagedEnvKey and ContainmentManagedEnvValue identify a Pipelock
// process started by the managed containment service. They are deliberately
// separate from generic configuration validation: standalone Pipelock may
// expose metrics on a LAN address, while containment must not.
const (
	ContainmentManagedEnvKey   = "PIPELOCK_CONTAINMENT_MANAGED"
	ContainmentManagedEnvValue = "1"
)

// ValidateContainmentMetricsListen enforces the metrics listener invariant
// used only by the containment lifecycle: a numeric loopback address on a
// non-proxy TCP port. It does not participate in Config.Validate, because
// ordinary Pipelock deployments may intentionally expose metrics on a LAN.
func ValidateContainmentMetricsListen(listen string, proxyPort int) error {
	return ValidateContainmentMetricsExposure(listen, proxyPort, nil, time.Now())
}

// ContainmentConfig holds settings that are enforced only by the containment
// lifecycle. It is kept separate from ordinary proxy configuration because
// the containment runtime owns the kernel boundary around the agent.
type ContainmentConfig struct {
	MetricsExposure   *ContainmentMetricsExposure   `yaml:"metrics_exposure"`
	LoopbackServices  []ContainmentLoopbackService  `yaml:"loopback_services"`
	PublishedServices []ContainmentPublishedService `yaml:"published_services"`
	Display           ContainmentDisplay            `yaml:"display"`
	// AgentListener names the per-agent listener the containment doorway
	// delivers the contained agent's traffic to, e.g. "127.0.0.1:8889". It
	// must be one of the listeners declared under agents.<name>.listeners, so
	// the proxy attributes that traffic to the profile bound to the listener.
	// Only processes inside the agent's network namespace can reach the
	// doorway. The managed host nftables rule restricts the listener to the
	// relay account and root. Empty keeps the shared proxy listener.
	AgentListener string `yaml:"agent_listener,omitempty"`
}

// ValidateContainmentAgentListener checks containment.agent_listener: a
// numeric loopback host:port that is not the shared proxy listener and that
// exactly matches a declared agents.<name>.listeners entry. An address no
// profile binds would attribute the agent to nothing.
func ValidateContainmentAgentListener(listener string, agents map[string]AgentProfile, proxyPort int) error {
	if listener == "" {
		return nil
	}
	host, portText, err := net.SplitHostPort(listener)
	if err != nil {
		return fmt.Errorf("containment.agent_listener %q: %w", listener, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("containment.agent_listener %q must use a numeric loopback address (127.0.0.1 or ::1)", listener)
	}
	// An IPv4 address in IPv6 form (::ffff:127.0.0.1) selects the IPv4 rule
	// family but cannot be written in an IPv4 address expression.
	if ip.To4() != nil && strings.Contains(host, ":") {
		return fmt.Errorf("containment.agent_listener %q uses an IPv4-mapped IPv6 address; write it as 127.0.0.1", listener)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("containment.agent_listener %q has an invalid port", listener)
	}
	if port == proxyPort {
		return fmt.Errorf("containment.agent_listener %q is the shared proxy port; omit agent_listener to keep the shared listener", listener)
	}
	want := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	for _, profile := range agents {
		for _, declared := range profile.Listeners {
			dHost, dPort, splitErr := net.SplitHostPort(declared)
			if splitErr != nil {
				continue
			}
			if dIP := net.ParseIP(dHost); dIP != nil && net.JoinHostPort(dIP.String(), dPort) == want {
				return nil
			}
		}
	}
	return fmt.Errorf("containment.agent_listener %q is not declared under any agents.<name>.listeners; declare it on the contained agent's profile", listener)
}

// ContainmentDisplay configures the private Xvfb display installed for the
// contained agent.
//
// Enabled is a POINTER so an omitted value is distinguishable from an
// explicit false. Omitted means "provision where it is possible": a
// contained agent cannot run a browser without a display, the browser tools
// agents actually use have no headless mode, and requiring an operator to
// discover this knob means the capability silently does not work out of the
// box. An explicit false still turns it off, and a host without Xvfb
// installed is left alone rather than failing its install.
type ContainmentDisplay struct {
	Enabled *bool `yaml:"enabled"`
	Number  *int  `yaml:"number"`
}

// IsEnabled resolves the three states: explicitly on, explicitly off, and
// omitted. Only the omitted case consults the host, and it provisions
// exactly where a display can actually be created.
func (d ContainmentDisplay) IsEnabled(xvfbPresent bool) bool {
	if d.Enabled != nil {
		return *d.Enabled
	}
	return xvfbPresent
}

// EffectiveNumber returns the configured display number, or the conventional
// fallback used when display provisioning is enabled.
func (d ContainmentDisplay) EffectiveNumber() int {
	if d.Number == nil {
		return 99
	}
	return *d.Number
}

// ContainmentLoopbackService declares a second loopback destination the
// contained agent may reach beyond the mediated proxy port. This is the
// outbound sibling of ContainmentMetricsExposure: it is the sole declared
// exception format for an extra agent-reachable loopback service, carrying
// the same owner/reason/expiry lifecycle so an operator carve-out is visible
// to config validation, contain install, and contain verify instead of being
// a hand-edited nft rule that reload tolerates and verify condemns.
type ContainmentLoopbackService struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	Owner     string `yaml:"owner"`
	Reason    string `yaml:"reason"`
	ExpiresAt string `yaml:"expires_at"`
}

// ContainmentMetricsExposure records the deliberate exception required to
// serve full Prometheus metrics beyond loopback from a contained runtime.
// Every field is required so an operator can identify who accepted the
// exposure, why, when it ends, and which scrapers may use it.
type ContainmentMetricsExposure struct {
	AllowFullMetrics   bool     `yaml:"allow_full_metrics"`
	AllowedSourceCIDRs []string `yaml:"allowed_source_cidrs"`
	Owner              string   `yaml:"owner"`
	Reason             string   `yaml:"reason"`
	ExpiresAt          string   `yaml:"expires_at"`
}

// ValidateContainmentMetricsExposure enforces the containment metrics
// listener invariant. Loopback needs no exception. Any other numeric address
// requires a complete, current metrics exposure policy.
func ValidateContainmentMetricsExposure(listen string, proxyPort int, policy *ContainmentMetricsExposure, now time.Time) error {
	if strings.TrimSpace(listen) == "" {
		return fmt.Errorf("metrics_listen is unsafe for containment: set a numeric loopback address on a dedicated port and do not delete the key")
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: %w", listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a numeric address, not a hostname", listen)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: wildcard binds are not allowed", listen)
	}
	parsedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil || parsedPort == 0 || int(parsedPort) == proxyPort {
		return fmt.Errorf("metrics_listen %q is unsafe for containment: use a port other than the agent-accessible proxy port %d", listen, proxyPort)
	}
	if ip.IsLoopback() {
		if policy != nil {
			return fmt.Errorf("containment.metrics_exposure requires a non-loopback metrics_listen address")
		}
		return nil
	}
	if err := validateContainmentMetricsExposurePolicy(policy, now); err != nil {
		return err
	}
	return nil
}

// validateContainmentExceptionLifecycle enforces the shared owner/reason/expiry
// contract every declared containment exception carries: ContainmentMetricsExposure
// and ContainmentLoopbackService both call this instead of duplicating the
// RFC3339 parse and expiry comparison.
func validateContainmentExceptionLifecycle(field, owner, reason, expiresAt string, now time.Time) error {
	if strings.TrimSpace(owner) == "" {
		return fmt.Errorf("%s.owner is required", field)
	}
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%s.reason is required", field)
	}
	expiresAtParsed, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAt))
	if err != nil {
		return fmt.Errorf("%s.expires_at must use RFC3339: %w", field, err)
	}
	if !expiresAtParsed.After(now) {
		return fmt.Errorf("%s expired at %s", field, expiresAtParsed.UTC().Format(time.RFC3339))
	}
	return nil
}

func validateContainmentMetricsExposurePolicy(policy *ContainmentMetricsExposure, now time.Time) error {
	if policy == nil {
		return fmt.Errorf("non-loopback metrics_listen requires containment.metrics_exposure")
	}
	if !policy.AllowFullMetrics {
		return fmt.Errorf("containment.metrics_exposure.allow_full_metrics must be true")
	}
	if err := validateContainmentExceptionLifecycle("containment.metrics_exposure", policy.Owner, policy.Reason, policy.ExpiresAt, now); err != nil {
		return err
	}
	if len(policy.AllowedSourceCIDRs) == 0 {
		return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs must name at least one source")
	}
	for i, source := range policy.AllowedSourceCIDRs {
		ip, cidr, err := net.ParseCIDR(strings.TrimSpace(source))
		if err != nil {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q is invalid: %w", i, source, err)
		}
		if !ip.Equal(cidr.IP) {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q must use a network address", i, source)
		}
		ones, bits := cidr.Mask.Size()
		if ones == 0 && (bits == 32 || bits == 128) {
			return fmt.Errorf("containment.metrics_exposure.allowed_source_cidrs[%d] %q must not allow every source", i, source)
		}
	}
	return nil
}

// ContainmentMetricsExposureAllowsSource reports whether an already-validated
// policy permits the connecting address. Invalid policies deny by returning
// false so callers never turn a parse failure into an open metrics endpoint.
func ContainmentMetricsExposureAllowsSource(policy *ContainmentMetricsExposure, source net.IP) bool {
	if policy == nil || source == nil {
		return false
	}
	for _, rawCIDR := range policy.AllowedSourceCIDRs {
		_, cidr, err := net.ParseCIDR(strings.TrimSpace(rawCIDR))
		if err == nil && cidr.Contains(source) {
			return true
		}
	}
	return false
}

// ValidateContainmentLoopbackServices enforces the declared-exception
// lifecycle for every containment.loopback_services entry: a loopback-literal
// host, a TCP port distinct from the proxy port and from every other
// declared entry, and the same required owner/reason/expires_at contract as
// containment.metrics_exposure. An empty or nil list is valid: the contained
// agent's only implicit loopback destination remains the proxy port.
func ValidateContainmentLoopbackServices(services []ContainmentLoopbackService, proxyPort int, now time.Time) error {
	seen := make(map[string]struct{}, len(services))
	for i, svc := range services {
		field := fmt.Sprintf("containment.loopback_services[%d]", i)
		// Compare the host EXACTLY as declared, without trimming. The
		// validated value is the value nftLoopbackAcceptLine renders
		// verbatim into the nft rule, so accepting a padded " ::1 " here
		// would validate one string and render a different one: the render
		// selects its address family by exact literal match, so a padded
		// "::1" takes the IPv4 branch and emits a rule that either fails
		// the nft parse or cannot be matched by the verify probes. Refusing
		// non-canonical spacing keeps declaration and rendered rule
		// identical by construction rather than by two agreeing trims.
		host := svc.Host
		if host != "127.0.0.1" && host != "::1" {
			return fmt.Errorf("%s.host %q must be a loopback literal (127.0.0.1 or ::1) with no surrounding whitespace, not a hostname, wildcard, or CIDR", field, svc.Host)
		}
		if svc.Port < 1 || svc.Port > 65535 {
			return fmt.Errorf("%s.port %d must be between 1 and 65535", field, svc.Port)
		}
		if svc.Port == proxyPort {
			return fmt.Errorf("%s.port %d collides with the agent-accessible proxy port; the proxy allow is implicit and does not need a declared exception", field, svc.Port)
		}
		key := host + ":" + strconv.Itoa(svc.Port)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("%s duplicates an already-declared loopback service at %s", field, key)
		}
		seen[key] = struct{}{}
		if err := validateContainmentExceptionLifecycle(field, svc.Owner, svc.Reason, svc.ExpiresAt, now); err != nil {
			// Repeat the host:port and owner in the wrapped error so a caller
			// that only sees the flattened message (contain verify's FAIL
			// detail, an operator's terminal) can still tell WHICH declared
			// service is unusable without cross-referencing the index.
			return fmt.Errorf("%s:%d (owner=%s): %w", host, svc.Port, svc.Owner, err)
		}
	}
	return nil
}

// ContainmentPublishedService declares INBOUND publication of one listener the
// contained agent runs on its own namespace loopback to a host endpoint the
// operator can connect to. It is the inbound sibling of
// ContainmentLoopbackService and carries the same owner/reason/expiry
// lifecycle, so the doorway closes on expiry or removal without another
// install.
//
// Everything that crosses this doorway is agent-controlled in both
// directions: the agent chooses what the operator sees, and it sees whatever
// the operator sends. Pipelock provides the doorway only, never a viewer or
// remote access.
type ContainmentPublishedService struct {
	Name         string `yaml:"name"`
	AgentHost    string `yaml:"agent_host"`
	AgentPort    int    `yaml:"agent_port"`
	HostSocket   string `yaml:"host_socket"`
	OperatorUser string `yaml:"operator_user"`
	HostListen   string `yaml:"host_listen"`
	Owner        string `yaml:"owner"`
	Reason       string `yaml:"reason"`
	ExpiresAt    string `yaml:"expires_at"`
}

// ContainmentPublishedSocketDir holds the default published-service sockets.
// It is deliberately NOT under /run/pipelock-contain: that directory is the
// namespace holder's RuntimeDirectory, which systemd deletes whenever the
// holder stops, and a socket unlinked out from under its listener can never
// be reached again.
const ContainmentPublishedSocketDir = "/run/pipelock-contain-published"

// ValidPublishedServiceName reports whether name is usable as a published
// service name, and so inside a systemd unit name and a socket path. Callers
// that read back state Pipelock wrote use it so a tampered inventory cannot
// name a unit outside the managed set.
func ValidPublishedServiceName(name string) bool {
	return publishedServiceNamePattern.MatchString(name)
}

// EffectiveAgentHost returns the in-namespace address being published.
func (s ContainmentPublishedService) EffectiveAgentHost() string {
	if s.AgentHost == "" {
		return "127.0.0.1"
	}
	return s.AgentHost
}

// EffectiveHostSocket returns the host unix socket path for the publication.
func (s ContainmentPublishedService) EffectiveHostSocket() string {
	if s.HostSocket == "" {
		return ContainmentPublishedSocketDir + "/" + s.Name + ".sock"
	}
	return s.HostSocket
}

var (
	publishedServiceNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	// A POSIX portable user name as useradd(8) accepts it by default.
	publishedOperatorUserPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	// systemd.socket(5) ListenStream= takes the path verbatim; restricting the
	// character set keeps the rendered unit and the validated value identical.
	publishedSocketPathPattern = regexp.MustCompile(`^/run/[A-Za-z0-9._/-]+\.sock$`)
)

// ValidateContainmentPublishedServices enforces the declared-exception
// lifecycle for every containment.published_services entry. loopback is the
// declared outbound list, used only to refuse port collisions: a published
// agent_port would collide with the in-namespace listener a declared loopback
// service reserves, and a host_listen port with the host service that
// declaration forwards to.
func ValidateContainmentPublishedServices(services []ContainmentPublishedService, loopback []ContainmentLoopbackService, proxyPort int, now time.Time) error {
	reserved := make(map[int]string)
	reserved[proxyPort] = "the agent-accessible proxy port"
	for _, svc := range loopback {
		reserved[svc.Port] = "a declared containment.loopback_services port"
	}
	names := map[string]struct{}{}
	agentPorts := map[int]struct{}{}
	sockets := map[string]struct{}{}
	hostPorts := map[int]struct{}{}
	for i, svc := range services {
		field := fmt.Sprintf("containment.published_services[%d]", i)
		if !publishedServiceNamePattern.MatchString(svc.Name) {
			return fmt.Errorf("%s.name %q must be 1-32 lowercase letters, digits, or hyphens starting with a letter or digit", field, svc.Name)
		}
		if _, dup := names[svc.Name]; dup {
			return fmt.Errorf("%s.name %q is declared more than once", field, svc.Name)
		}
		names[svc.Name] = struct{}{}
		if svc.AgentHost != "" && svc.AgentHost != "127.0.0.1" && svc.AgentHost != "::1" {
			return fmt.Errorf("%s.agent_host %q must be a loopback literal (127.0.0.1 or ::1) with no surrounding whitespace", field, svc.AgentHost)
		}
		if svc.AgentPort < 1 || svc.AgentPort > 65535 {
			return fmt.Errorf("%s.agent_port %d must be between 1 and 65535", field, svc.AgentPort)
		}
		if what, taken := reserved[svc.AgentPort]; taken {
			return fmt.Errorf("%s.agent_port %d collides with %s", field, svc.AgentPort, what)
		}
		if _, dup := agentPorts[svc.AgentPort]; dup {
			return fmt.Errorf("%s.agent_port %d is already published by another entry", field, svc.AgentPort)
		}
		agentPorts[svc.AgentPort] = struct{}{}
		if svc.HostSocket != "" {
			if !publishedSocketPathPattern.MatchString(svc.HostSocket) || filepath.Clean(svc.HostSocket) != svc.HostSocket {
				return fmt.Errorf("%s.host_socket %q must be a clean absolute path under /run/ ending in .sock", field, svc.HostSocket)
			}
			if strings.HasPrefix(filepath.Base(svc.HostSocket), "pipelock-agent-") || strings.HasPrefix(svc.HostSocket, "/run/pipelock-contain/") {
				return fmt.Errorf("%s.host_socket %q is reserved for Pipelock's own containment doorways", field, svc.HostSocket)
			}
		}
		socket := svc.EffectiveHostSocket()
		if _, dup := sockets[socket]; dup {
			return fmt.Errorf("%s.host_socket %q is already used by another entry", field, socket)
		}
		sockets[socket] = struct{}{}
		if !publishedOperatorUserPattern.MatchString(svc.OperatorUser) {
			return fmt.Errorf("%s.operator_user %q must name the one local user allowed to connect", field, svc.OperatorUser)
		}
		if svc.HostListen != "" {
			host, portText, err := net.SplitHostPort(svc.HostListen)
			if err != nil || (host != "127.0.0.1" && host != "::1") {
				return fmt.Errorf("%s.host_listen %q must be 127.0.0.1:<port> or [::1]:<port>", field, svc.HostListen)
			}
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
				return fmt.Errorf("%s.host_listen %q has an invalid port", field, svc.HostListen)
			}
			if what, taken := reserved[port]; taken {
				return fmt.Errorf("%s.host_listen port %d collides with %s", field, port, what)
			}
			if _, dup := hostPorts[port]; dup {
				return fmt.Errorf("%s.host_listen port %d is already used by another entry", field, port)
			}
			hostPorts[port] = struct{}{}
		}
		if err := validateContainmentExceptionLifecycle(field, svc.Owner, svc.Reason, svc.ExpiresAt, now); err != nil {
			return fmt.Errorf("published service %s (owner=%s): %w", svc.Name, svc.Owner, err)
		}
	}
	return nil
}
