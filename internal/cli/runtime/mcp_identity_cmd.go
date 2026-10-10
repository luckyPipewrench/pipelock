// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	identityProbeDialTimeout = 5 * time.Second
	identityControlEnvHint   = "REVIEW: replace with the exact reviewed value"
	identityYAMLIndent       = "      "
	identityScopeSession     = "an acknowledgment bound to this identity covers every session of this verified local service, whatever credential or port the session uses; it is invalidated by a change to the registration or to the verified process"
	identityScopeTransport   = "an acknowledgment is bound to this launch's exact upstream and credentials; a changed credential or upstream invalidates it"
	identitySchemeHTTPLabel  = "http, https, ws or wss"
)

// systemLibraryPrefixes mark held files that belong to the operating system
// rather than to the service, so register lists them after the service's own.
var systemLibraryPrefixes = []string{"/usr/", "/lib/", "/lib64/", "/etc/"}

// identityProbe holds the dial and the owner checks the identity commands use,
// so tests can substitute them on any platform.
type identityProbe struct {
	dial    localservice.DialContextFunc
	observe func(context.Context, net.Conn) (localservice.Observation, error)
	verify  func(context.Context, net.Conn, localservice.Pin) (localservice.Evidence, error)
}

func defaultIdentityProbe() identityProbe {
	dialer := &net.Dialer{Timeout: identityProbeDialTimeout}
	return identityProbe{
		dial: dialer.DialContext,
		observe: func(ctx context.Context, conn net.Conn) (localservice.Observation, error) {
			return localServiceVerifier().Observe(ctx, conn)
		},
		verify: func(ctx context.Context, conn net.Conn, pin localservice.Pin) (localservice.Evidence, error) {
			return localServiceVerifier().VerifyConnContext(ctx, conn, pin)
		},
	}
}

func mcpIdentityCmd() *cobra.Command {
	return newMCPIdentityCmd(defaultIdentityProbe())
}

func newMCPIdentityCmd(probe identityProbe) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Inspect and register verified local MCP services",
		Long: `Work with the mcp_identities registry of verified local MCP services.

  inspect   resolve an upstream exactly as "mcp proxy" would, show the identity
            and acknowledgment binding it gets, and verify the live owner of
            the upstream against the registration.
  register  observe the live owner of a local upstream and print a reviewable
            mcp_identities entry. Nothing is written to any config file.

Verification is Linux only.`,
	}
	cmd.AddCommand(newMCPIdentityInspectCmd(probe))
	cmd.AddCommand(newMCPIdentityRegisterCmd(probe))
	return cmd
}

// parseIdentityUpstream validates an upstream URL for the identity commands and
// reports whether it is a WebSocket upstream.
func parseIdentityUpstream(raw string) (*url.URL, bool, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, false, fmt.Errorf("invalid upstream URL %q: must include a scheme and host", RedactEndpoint(raw))
	}
	switch u.Scheme {
	case schemeHTTP, schemeHTTPS:
		return u, false, nil
	case "ws", "wss":
		return u, true, nil
	default:
		return nil, false, fmt.Errorf("invalid upstream URL %q: scheme must be %s", RedactEndpoint(raw), identitySchemeHTTPLabel)
	}
}

func mcpIdentityInspectFlags() (cmd *cobra.Command, flags *identityInspectFlags) {
	flags = &identityInspectFlags{}
	cmd = &cobra.Command{
		Use:   "inspect",
		Args:  cobra.NoArgs,
		Short: "Show the identity and binding an upstream resolves to, and verify its live owner",
		Long: `Resolve an upstream against the mcp_identities registry exactly as "pipelock mcp proxy"
does for the same flags, and print the identity, matched registration, acknowledgment
binding mode and what an acknowledgment covers.

When the upstream is registered, inspect dials it and verifies the owning process
against the registration, and prints the evidence. Exit status is zero for a verified,
legacy or unnamed server and non-zero for a refusal.

Examples:
  pipelock mcp identity inspect --config pipelock.yaml --upstream http://127.0.0.1:43111/mcp
  pipelock mcp identity inspect --config pipelock.yaml --upstream http://127.0.0.1:43111/mcp \
    --header-carrier Authorization=PIPELOCK_VSCODE_MCP_AUTH`,
	}
	cmd.Flags().StringVar(&flags.configFile, "config", "", "config file with the mcp_identities registry")
	cmd.Flags().StringVar(&flags.upstream, "upstream", "", "upstream MCP server URL to resolve")
	cmd.Flags().StringVar(&flags.serverName, "server-name", "", "operator label, as for mcp proxy")
	cmd.Flags().StringArrayVar(&flags.headers, "header", nil, "upstream header as for mcp proxy (repeatable, 'Key: Value')")
	cmd.Flags().StringArrayVar(&flags.carriers, "header-carrier", nil, "map a host-resolved carrier into an upstream header (HEADER=CARRIER, repeatable)")
	cmd.Flags().StringVar(&flags.headerFile, "header-file", "", "headers file as for mcp proxy")
	_ = cmd.MarkFlagRequired("upstream")
	return cmd, flags
}

type identityInspectFlags struct {
	configFile string
	upstream   string
	serverName string
	headers    []string
	carriers   []string
	headerFile string
}

func newMCPIdentityInspectCmd(probe identityProbe) *cobra.Command {
	cmd, f := mcpIdentityInspectFlags()
	cmd.SilenceUsage = true
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		out := cmd.OutOrStdout()
		u, isWS, err := parseIdentityUpstream(f.upstream)
		if err != nil {
			return err
		}
		if f.serverName != "" {
			if err := config.ValidateMCPServerName(f.serverName, "--server-name"); err != nil {
				return err
			}
		}
		cfg, err := cliutil.LoadConfigOrDefault(f.configFile)
		if err != nil {
			return err
		}
		var fileLines []string
		if f.headerFile != "" {
			if fileLines, err = readHeaderFile(f.headerFile); err != nil {
				return err
			}
		}
		carrierEntries, err := resolveHeaderCarrierEntries(f.carriers)
		if err != nil {
			return err
		}
		headers, err := identityHeaders(fileLines, f.headers, carrierEntries)
		if err != nil {
			return err
		}
		res, err := identity.Resolve(cfg, f.serverName, identity.Transport{
			Kind:        upstreamTransportKind(isWS),
			UpstreamURL: f.upstream,
			Headers:     headers,
		})
		if err != nil {
			_, _ = fmt.Fprintf(out, "refused: %v\n", err)
			return fmt.Errorf("identity refused: %w", err)
		}
		writeInspectResolution(out, res)
		if res.Pin == nil {
			return nil
		}
		ev, err := verifyUpstream(cmd.Context(), probe, u, *res.Pin)
		if err != nil {
			_, _ = fmt.Fprintf(out, "verification: refused: %v\n", err)
			return fmt.Errorf("verified local service %s: %w", res.Name, err)
		}
		_, _ = fmt.Fprintf(out, "verification: verified pid=%d uid=%d executable_sha256=%s mapped_files=%d\n",
			ev.PID, ev.UID, ev.ExecutableSHA256, len(ev.MappedFiles))
		return nil
	}
	return cmd
}

func writeInspectResolution(out io.Writer, res identity.Resolution) {
	_, _ = fmt.Fprintln(out, identity.StartupLine(res))
	if res.Entry != nil {
		_, _ = fmt.Fprintf(out, "registration: %s revision=%s\n", res.Entry.Name, res.Revision)
	} else {
		_, _ = fmt.Fprintln(out, "registration: none (not a registered verified local service)")
	}
	_, _ = fmt.Fprintf(out, "binding mode: %s\n", res.BindingMode)
	scope := identityScopeTransport
	if res.BindingMode == config.MCPAckBindingModeVerifiedLocalSession {
		scope = identityScopeSession
	}
	_, _ = fmt.Fprintf(out, "scope: %s\n", scope)
}

// dialUpstream opens a TCP connection to the upstream's host and port.
func dialUpstream(ctx context.Context, probe identityProbe, u *url.URL) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if u.Port() == "" {
		return nil, fmt.Errorf("upstream %q has no explicit port to dial", RedactEndpoint(u.String()))
	}
	conn, err := probe.dial(ctx, "tcp", net.JoinHostPort(u.Hostname(), u.Port()))
	if err != nil {
		return nil, fmt.Errorf("dial upstream: %w", err)
	}
	return conn, nil
}

func verifyUpstream(ctx context.Context, probe identityProbe, u *url.URL, pin localservice.Pin) (localservice.Evidence, error) {
	conn, err := dialUpstream(ctx, probe, u)
	if err != nil {
		return localservice.Evidence{}, err
	}
	defer func() { _ = conn.Close() }()
	if ctx == nil {
		ctx = context.Background()
	}
	return probe.verify(ctx, conn, pin)
}

type identityRegisterFlags struct {
	upstream      string
	name          string
	sessionHeader string
	carrier       string
	mappedFiles   []string
}

func newMCPIdentityRegisterCmd(probe identityProbe) *cobra.Command {
	f := &identityRegisterFlags{}
	cmd := &cobra.Command{
		Use:   "register",
		Args:  cobra.NoArgs,
		Short: "Observe a local MCP service and print a reviewable mcp_identities entry",
		Long: `Dial a local MCP upstream, observe the process that owns it, and print an
mcp_identities entry for you to review and add to your config. The command never
writes a config file.

The entry carries the upstream scheme, host and path, the owning process's
effective uid and executable digest, and the digest of each file you choose with
--mapped-file. The other files the process holds are listed as comments, with
operating-system libraries last. Deny-listed control variables present in the
process appear as control_environment keys whose value you must fill in with the
reviewed exact value.

Run it against a service you trust at this moment: what is observed becomes what
is pinned.

Example:
  pipelock mcp identity register --upstream http://127.0.0.1:43111/mcp --name local-tools \
    --mapped-file /opt/vendor/lib/native.so \
    --session-header Authorization --carrier PIPELOCK_VSCODE_MCP_AUTH`,
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&f.upstream, "upstream", "", "upstream MCP server URL of the running local service (loopback literal host, explicit port, path)")
	cmd.Flags().StringVar(&f.name, "name", "", "registered name for the service")
	cmd.Flags().StringVar(&f.sessionHeader, "session-header", "", "HTTP header that carries each session's bearer credential (HTTP and HTTPS upstreams only)")
	cmd.Flags().StringVar(&f.carrier, "carrier", "", "carrier environment variable that holds the session credential (with --session-header)")
	cmd.Flags().StringArrayVar(&f.mappedFiles, "mapped-file", nil, "file the service must hold open or mapped, pinned by digest (repeatable)")
	_ = cmd.MarkFlagRequired("upstream")
	_ = cmd.MarkFlagRequired("name")
	cmd.RunE = func(cmd *cobra.Command, _ []string) error {
		return runIdentityRegister(cmd, probe, f)
	}
	return cmd
}

func runIdentityRegister(cmd *cobra.Command, probe identityProbe, f *identityRegisterFlags) error {
	u, isWS, err := parseIdentityUpstream(f.upstream)
	if err != nil {
		return err
	}
	if err := config.ValidateMCPServerName(f.name, "--name"); err != nil {
		return err
	}
	session, err := registerSessionHeader(f, isWS)
	if err != nil {
		return err
	}
	entry, err := registerEntryShape(f.name, u)
	if err != nil {
		return err
	}
	entry.VerifiedLocalService.SessionHeader = session

	conn, err := dialUpstream(cmd.Context(), probe, u)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	obs, err := probe.observe(ctx, conn)
	if err != nil {
		return fmt.Errorf("observe the owner of %s: %w", RedactEndpoint(f.upstream), err)
	}
	return writeRegistration(cmd.OutOrStdout(), entry, obs, f.mappedFiles)
}

// registerSessionHeader validates --session-header and --carrier together.
func registerSessionHeader(f *identityRegisterFlags, isWS bool) (*config.MCPIdentitySessionHeader, error) {
	if f.sessionHeader == "" && f.carrier == "" {
		return nil, nil
	}
	if f.sessionHeader == "" || f.carrier == "" {
		return nil, errors.New("--session-header and --carrier must be given together")
	}
	if isWS {
		return nil, errors.New("--session-header is not supported for a WebSocket upstream: a handshake header cannot be separated from the bound session")
	}
	if canon := http.CanonicalHeaderKey(f.sessionHeader); canon != f.sessionHeader {
		return nil, fmt.Errorf("--session-header %q must be written in canonical form %q", f.sessionHeader, canon)
	}
	if problem := config.MCPCarrierNameProblem(f.carrier); problem != "" {
		return nil, fmt.Errorf("--carrier %q: %s", f.carrier, problem)
	}
	sh := &config.MCPIdentitySessionHeader{Name: f.sessionHeader, Scheme: config.MCPIdentitySessionScheme, Carrier: f.carrier}
	// The loader's own rules, so a printed entry is never one it would refuse
	// (for example a name that is not an HTTP header token).
	if err := config.ValidateMCPIdentitySessionHeader(config.MCPIdentitySchemeHTTP, sh, "--session-header"); err != nil {
		return nil, err
	}
	return sh, nil
}

// registerEntryShape builds the matcher half of the entry from the upstream URL.
func registerEntryShape(name string, u *url.URL) (config.MCPIdentity, error) {
	host := u.Hostname()
	if host != config.MCPIdentityHostIPv4Loopback && host != config.MCPIdentityHostIPv6Loopback {
		return config.MCPIdentity{}, fmt.Errorf("upstream host %q must be the literal %s or %s: only a loopback service can be verified", host, config.MCPIdentityHostIPv4Loopback, config.MCPIdentityHostIPv6Loopback)
	}
	if port, err := strconv.Atoi(u.Port()); err != nil || port < 1 || port > 65535 {
		return config.MCPIdentity{}, errors.New("upstream needs an explicit port to dial")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return config.MCPIdentity{}, errors.New("upstream must not carry credentials, a query or a fragment: only scheme, host, port and path are registered")
	}
	path := u.EscapedPath()
	if path == "" || path[0] != '/' {
		return config.MCPIdentity{}, errors.New("upstream needs a path starting with \"/\" (for example http://127.0.0.1:PORT/mcp): the path is part of what is registered")
	}
	return config.MCPIdentity{
		Name: name,
		VerifiedLocalService: &config.MCPVerifiedLocalService{
			Scheme: u.Scheme,
			Host:   host,
			Path:   path,
		},
	}, nil
}

// writeRegistration prints the reviewable entry. The registration's matcher and
// session header come from entry; the observation supplies the process facts.
func writeRegistration(out io.Writer, entry config.MCPIdentity, obs localservice.Observation, chosen []string) error {
	pinned, held, err := splitObservedFiles(obs, chosen)
	if err != nil {
		return err
	}
	v := entry.VerifiedLocalService
	// The first write error is kept and returned, so a broken pipe or a full
	// destination fails the command instead of leaving a truncated entry that
	// looks complete.
	var writeErr error
	w := func(format string, args ...any) {
		if writeErr != nil {
			return
		}
		if _, err := fmt.Fprintf(out, format, args...); err != nil {
			writeErr = fmt.Errorf("write registration: %w", err)
		}
	}

	w("# Review before use. Observed process: pid=%d effective uid=%d.\n", obs.PID, obs.UID)
	w("# Add this entry to mcp_identities in a config loaded only by a binary that supports it.\n")
	w("mcp_identities:\n")
	w("  - name: %s\n", yamlScalar(entry.Name))
	w("    verified_local_service:\n")
	w("      scheme: %s\n", yamlScalar(v.Scheme))
	w("      host: %s\n", yamlScalar(v.Host))
	w("      path: %s\n", yamlScalar(v.Path))
	w("      principal_uid: %d\n", obs.UID)
	w("      executable_sha256: %s\n", yamlScalar(obs.ExecutableSHA256))
	if len(pinned) > 0 {
		w("      mapped_files:\n")
		for _, f := range pinned {
			w("        - path: %s\n", yamlScalar(f.Path))
			w("          sha256: %s\n", yamlScalar(f.SHA256))
		}
	}
	if len(held) > 0 {
		w("%s# Held but not pinned. Pin a file with --mapped-file when it carries code or\n", identityYAMLIndent)
		w("%s# configuration the service loads; operating-system libraries are listed last.\n", identityYAMLIndent)
		for _, f := range held {
			if f.SHA256 == "" {
				w("%s#   %s (digest unavailable: the path is not tied to the held file)\n", identityYAMLIndent, commentPath(f.Path))
				continue
			}
			w("%s#   %s sha256=%s\n", identityYAMLIndent, commentPath(f.Path), f.SHA256)
		}
	}
	if len(obs.ControlEnvironment) > 0 {
		w("%s# The process carries these loader or interpreter control variables. Their values\n", identityYAMLIndent)
		w("%s# are not read. Fill in the exact reviewed value for each, or remove the key if the\n", identityYAMLIndent)
		w("%s# service must not carry it.\n", identityYAMLIndent)
		w("      control_environment:\n")
		for _, name := range obs.ControlEnvironment {
			w("        %s: %s\n", name, yamlScalar(identityControlEnvHint))
		}
	}
	if sh := v.SessionHeader; sh != nil {
		w("      session_header:\n")
		w("        name: %s\n", yamlScalar(sh.Name))
		w("        scheme: %s\n", yamlScalar(sh.Scheme))
		w("        carrier: %s\n", yamlScalar(sh.Carrier))
	}
	return writeErr
}

// splitObservedFiles separates the files the operator chose to pin from the
// rest. Every chosen path must be a file the process holds with a digest tied to
// the held file.
func splitObservedFiles(obs localservice.Observation, chosen []string) (pinned []config.MCPIdentityFilePin, held []localservice.ObservedFile, err error) {
	byPath := make(map[string]localservice.ObservedFile, len(obs.Files))
	for _, f := range obs.Files {
		byPath[f.Path] = f
	}
	taken := make(map[string]bool, len(chosen))
	for _, raw := range chosen {
		path := cleanObservedPath(raw)
		f, ok := byPath[path]
		switch {
		case !ok:
			return nil, nil, fmt.Errorf("--mapped-file %q is not held open or mapped by the service; held files are: %s", raw, heldPaths(obs.Files))
		case f.SHA256 == "":
			return nil, nil, fmt.Errorf("--mapped-file %q is held but its digest could not be tied to the held file, so it cannot be pinned", raw)
		case taken[path]:
			return nil, nil, fmt.Errorf("--mapped-file %q is given more than once", raw)
		}
		taken[path] = true
		pinned = append(pinned, config.MCPIdentityFilePin{Path: f.Path, SHA256: f.SHA256})
	}
	for _, f := range obs.Files {
		if taken[f.Path] || f.SHA256 == obs.ExecutableSHA256 {
			continue
		}
		held = append(held, f)
	}
	sort.SliceStable(held, func(i, j int) bool {
		si, sj := isSystemLibrary(held[i].Path), isSystemLibrary(held[j].Path)
		if si != sj {
			return !si
		}
		return held[i].Path < held[j].Path
	})
	return pinned, held, nil
}

func cleanObservedPath(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

func heldPaths(files []localservice.ObservedFile) string {
	if len(files) == 0 {
		return "(none)"
	}
	paths := make([]string, len(files))
	for i, f := range files {
		// The service names its own files; quote any path with a control or
		// non-printable character so it cannot write terminal escapes or
		// forge lines in this error.
		paths[i] = commentPath(f.Path)
	}
	return strings.Join(paths, ", ")
}

func isSystemLibrary(path string) bool {
	for _, prefix := range systemLibraryPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// hasControl reports whether s holds anything but printable characters and
// the ASCII space, or invalid UTF-8. The observed service chooses its file
// names, and a control character or a Unicode line or paragraph separator
// (U+2028, U+2029, which YAML parsers treat as line breaks although they are
// not control characters) could end a YAML comment or an indented scalar and add
// live YAML to an entry the operator copies into a config.
func hasControl(s string) bool {
	return !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool { return r != ' ' && !unicode.IsPrint(r) }) >= 0
}

// commentPath renders an observed path for a YAML comment line, quoting it
// with escapes when it holds a control character.
func commentPath(p string) string {
	if hasControl(p) {
		return strconv.Quote(p)
	}
	return p
}

// yamlScalar renders s as a YAML scalar, quoting it when needed. A value with
// a control character becomes one double-quoted line with escapes, never a
// block scalar whose continuation lines would ignore this entry's indentation.
func yamlScalar(s string) string {
	if hasControl(s) {
		return strconv.Quote(s)
	}
	b, err := yaml.Marshal(s)
	if err != nil {
		return strconv.Quote(s)
	}
	return strings.TrimSuffix(string(b), "\n")
}
