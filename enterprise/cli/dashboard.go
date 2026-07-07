//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	// dashboardDefaultListen is loopback-only by design: the dashboard is an
	// authenticated admin surface on its own dedicated listener, never the
	// agent-reachable proxy port (same port-isolation principle as
	// kill_switch.api_listen).
	dashboardDefaultListen  = "127.0.0.1:8896"
	dashboardShutdownPeriod = 5 * time.Second
	// trustedSignerDefaultSource labels a trusted key whose --trusted-signer
	// value did not carry an explicit source= reason.
	trustedSignerDefaultSource = "--trusted-signer flag"
)

// DashboardCmd returns the `pipelock dashboard` command tree (Pro/Enterprise).
func DashboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Web dashboard over Pipelock evidence (Pro/Enterprise)",
	}
	cmd.AddCommand(dashboardServeCmd())
	return cmd
}

type dashboardServeOptions struct {
	listen         string
	receiptDir     string
	configFile     string
	authTokenFile  string
	rawTokenFile   string
	trustedSigners []string
	licenseCRLFile string
	tlsCert        string
	tlsKey         string
}

func dashboardServeCmd() *cobra.Command {
	opts := dashboardServeOptions{listen: dashboardDefaultListen}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the read-only Evidence dashboard on a dedicated listener",
		Long: `Serve the read-only Evidence dashboard over a flight-recorder evidence
directory. Every request must authenticate with the operator token from
--auth-token-file, sent either as "Authorization: Bearer <token>" or as the
password of an HTTP Basic prompt (any username). The license feature check is
entitlement, not identity; the token is the authentication boundary.

By default the view is redacted: receipt destinations and signed payloads are
hidden, because a destination URL can carry a capability token and the payload
is the largest exfil surface. Supply --raw-token-file to issue a second,
higher-privilege token whose holders see the full raw detail. Every
authenticated request is written to the access log on stderr.

Without --tls-cert/--tls-key the listener refuses non-loopback addresses,
because the operator token would transit in cleartext.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: the dashboard is a paid surface. Fail closed before
			// any listener bind or file IO so an unlicensed invocation produces
			// a clear entitlement error instead of a half-started server.
			lic, err := license.VerifyAgentsWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile})
			if err != nil {
				return err
			}
			return runDashboardServe(cmd, opts, lic)
		},
	}
	cmd.Flags().StringVar(&opts.listen, "listen", opts.listen,
		"address for the dashboard listener; non-loopback addresses require --tls-cert/--tls-key")
	cmd.Flags().StringVar(&opts.receiptDir, "receipt-dir", "",
		"flight-recorder evidence directory holding action receipts (flight_recorder.dir)")
	cmd.Flags().StringVar(&opts.configFile, "config", "",
		"optional Pipelock config file for the read-only exemptions inventory")
	cmd.Flags().StringVar(&opts.authTokenFile, "auth-token-file", "",
		"file containing the operator token required on every dashboard request (redacted metadata view)")
	cmd.Flags().StringVar(&opts.rawTokenFile, "raw-token-file", "",
		"optional file containing a higher-privilege token that unlocks raw destinations and signed payloads; must differ from --auth-token-file")
	cmd.Flags().StringArrayVar(&opts.trustedSigners, "trusted-signer", nil,
		"trusted receipt signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "",
		"signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "TLS server certificate file")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "TLS server private key file")
	_ = cmd.MarkFlagRequired("receipt-dir")
	_ = cmd.MarkFlagRequired("auth-token-file")
	return cmd
}

func runDashboardServe(cmd *cobra.Command, opts dashboardServeOptions, lic license.License) error {
	token, err := loadDashboardTokenFile("--auth-token-file", opts.authTokenFile)
	if err != nil {
		return err
	}
	// Optional raw-access token: elevates a request from the redacted metadata
	// view to full destinations + signed payloads. Must differ from the
	// metadata token so the two roles are actually distinguishable.
	var rawToken string
	if strings.TrimSpace(opts.rawTokenFile) != "" {
		rawToken, err = loadDashboardTokenFile("--raw-token-file", opts.rawTokenFile)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(rawToken), []byte(token)) == 1 {
			return errors.New("--raw-token-file must differ from --auth-token-file")
		}
	}
	trusted, err := parseTrustedSigners(opts.trustedSigners)
	if err != nil {
		return err
	}
	if err := validateDashboardListen(opts); err != nil {
		return err
	}
	tlsConfig, err := dashboardTLSConfig(opts)
	if err != nil {
		return err
	}
	info, err := os.Stat(filepath.Clean(opts.receiptDir))
	if err != nil {
		return fmt.Errorf("--receipt-dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--receipt-dir %q is not a directory", opts.receiptDir)
	}
	if len(trusted) == 0 {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
			"pipelock: warning: no --trusted-signer configured; the Authentic line will render every signer as Unverified")
	}
	var loadedConfig *config.Config
	if strings.TrimSpace(opts.configFile) != "" {
		loadedConfig, err = config.LoadForInspection(opts.configFile)
		if err != nil {
			return fmt.Errorf("--config: %w", err)
		}
	}

	// metaAuthorized gates all access: the metadata token OR the raw token (a
	// raw holder is also a valid operator). rawAuthorized gates only the
	// sensitive raw view and matches the raw token alone.
	metaAuthorized := func(r *http.Request) bool {
		if dashboardTokenMatches(r, token) {
			return true
		}
		return rawToken != "" && dashboardTokenMatches(r, rawToken)
	}
	rawAuthorized := func(r *http.Request) bool {
		return rawToken != "" && dashboardTokenMatches(r, rawToken)
	}

	inner := dashboard.New(dashboard.Options{
		ReceiptDir:   opts.receiptDir,
		TrustedKeys:  trusted,
		Config:       loadedConfig,
		HasFeature:   dashboardRuntimeHasFeature(lic),
		Authorize:    dashboardAuthorizeFunc(metaAuthorized),
		AuthorizeRaw: dashboardAuthorizeFunc(rawAuthorized),
		// Viewing evidence is itself audited; the access log goes to stderr.
		AuditWriter: cmd.ErrOrStderr(),
	})
	handler := dashboardAuthHandler(metaAuthorized, inner)

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	baseCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runCtx, stop := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:              opts.listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		TLSConfig:         tlsConfig,
	}
	ln, err := (&net.ListenConfig{}).Listen(runCtx, "tcp", opts.listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()

	go func() {
		<-runCtx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), dashboardShutdownPeriod)
		defer cancelShutdown()
		_ = server.Shutdown(shutdownCtx)
	}()

	useTLS := opts.tlsCert != ""
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: dashboard listening on %s://%s\n", scheme, ln.Addr())

	if useTLS {
		err = server.ServeTLS(ln, "", "")
	} else {
		err = server.Serve(ln)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func dashboardTLSConfig(opts dashboardServeOptions) (*tls.Config, error) {
	if opts.tlsCert == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(filepath.Clean(opts.tlsCert), filepath.Clean(opts.tlsKey))
	if err != nil {
		return nil, fmt.Errorf("load dashboard TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// validateDashboardListen refuses configurations that would put the operator
// token on the wire in cleartext: without TLS, only loopback addresses are
// allowed. TLS flags must come as a pair.
func validateDashboardListen(opts dashboardServeOptions) error {
	if (opts.tlsCert == "") != (opts.tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be set together")
	}
	if opts.tlsCert != "" {
		return nil
	}
	host, _, err := net.SplitHostPort(opts.listen)
	if err != nil {
		return fmt.Errorf("--listen %q: %w", opts.listen, err)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to serve the dashboard over cleartext HTTP on non-loopback address %q; "+
		"every request carries the operator token, so add --tls-cert/--tls-key or keep --listen on 127.0.0.1", opts.listen)
}

// dashboardAuthorizeFunc adapts a boolean request predicate to the
// Options.Authorize / Options.AuthorizeRaw seam: defense in depth behind the
// outer dashboardAuthHandler boundary, so the dashboard handler itself fails
// closed (403) if it is ever mounted without that boundary.
func dashboardAuthorizeFunc(authorized func(*http.Request) bool) func(*http.Request) error {
	return func(r *http.Request) error {
		if !authorized(r) {
			return errors.New("dashboard request not authenticated")
		}
		return nil
	}
}

// dashboardAuthHandler is the outer authentication boundary. It answers 401
// with a WWW-Authenticate challenge so browsers prompt for credentials; the
// inner dashboard handler re-checks the same predicate via Options.Authorize as
// defense in depth.
func dashboardAuthHandler(authorized func(*http.Request) bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			w.Header().Set("WWW-Authenticate", `Basic realm="pipelock dashboard", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// dashboardTokenMatches accepts the operator token as either a Bearer token
// (automation) or the password of an HTTP Basic credential (browsers; the
// username is ignored). Comparisons are constant-time.
func dashboardTokenMatches(r *http.Request, token string) bool {
	if token == "" {
		return false // fail closed: no configured token means no access
	}
	const bearerPrefix = "bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) > len(bearerPrefix) && strings.EqualFold(auth[:len(bearerPrefix)], bearerPrefix) {
		got := strings.TrimSpace(auth[len(bearerPrefix):])
		return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
	}
	if _, pass, ok := r.BasicAuth(); ok {
		return subtle.ConstantTimeCompare([]byte(pass), []byte(token)) == 1
	}
	return false
}

// dashboardRuntimeHasFeature wraps the boot-time-verified license's feature
// check with a runtime expiry re-check so a license that expires while the
// server is running stops serving. Mirrors the AgentRegistry.Lookup expiry
// rule; the startup Verify only proves validity at boot.
func dashboardRuntimeHasFeature(lic license.License) func(string) bool {
	return func(feature string) bool {
		if lic.ExpiresAt > 0 && time.Now().Unix() > lic.ExpiresAt {
			return false
		}
		return lic.HasFeature(feature)
	}
}

// parseTrustedSigners parses repeated --trusted-signer values into the
// operator trusted-key set. An empty flag list returns nil: the dashboard then
// honestly renders every signer as Unverified (never trust-on-first-use).
func parseTrustedSigners(values []string) (map[string]dashboard.TrustedKey, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make(map[string]dashboard.TrustedKey, len(values))
	for _, raw := range values {
		keyHex, source, err := parseTrustedSignerSpec(raw)
		if err != nil {
			return nil, fmt.Errorf("--trusted-signer %q: %w", raw, err)
		}
		if _, dup := out[keyHex]; dup {
			return nil, fmt.Errorf("--trusted-signer %q: duplicate key %s", raw, keyHex)
		}
		out[keyHex] = dashboard.TrustedKey{Source: source}
	}
	return out, nil
}

// parseTrustedSignerSpec parses one --trusted-signer value: comma-separated
// kv pairs with exactly one key source, '(inline=<hex-or-versioned>|file=/path)',
// plus an optional 'source=LABEL' shown in the UI as the reason the key is
// trusted.
func parseTrustedSignerSpec(raw string) (keyHex, source string, err error) {
	var inline, file string
	var hasInline, hasFile, hasSource bool
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return "", "", fmt.Errorf("expected key=value, got %q", part)
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "inline":
			if hasInline {
				return "", "", errors.New("inline= may appear only once")
			}
			if v == "" {
				return "", "", errors.New("inline= value is empty")
			}
			hasInline = true
			inline = v
		case "file":
			if hasFile {
				return "", "", errors.New("file= may appear only once")
			}
			if v == "" {
				return "", "", errors.New("file= value is empty")
			}
			hasFile = true
			file = v
		case "source":
			if hasSource {
				return "", "", errors.New("source= may appear only once")
			}
			hasSource = true
			source = v
		default:
			return "", "", fmt.Errorf("unknown key %q", k)
		}
	}
	switch {
	case inline != "" && file != "":
		return "", "", errors.New("inline= and file= are mutually exclusive")
	case inline == "" && file == "":
		return "", "", errors.New("one of inline= or file= is required")
	case file != "":
		data, readErr := os.ReadFile(filepath.Clean(file))
		if readErr != nil {
			return "", "", fmt.Errorf("read key file: %w", readErr)
		}
		inline = strings.TrimSpace(string(data))
	}
	// signing.ParsePublicKey enforces the Ed25519 key size on both the
	// versioned and raw-hex paths, so a parsed key is always well-formed.
	pub, err := signing.ParsePublicKey(inline)
	if err != nil {
		return "", "", fmt.Errorf("parse public key: %w", err)
	}
	if source == "" {
		source = trustedSignerDefaultSource
	}
	return hex.EncodeToString(pub), source, nil
}

// loadDashboardTokenFile reads and validates a required operator token file.
// Mirrors the conductor loadTokenFile semantics: trimmed and non-empty.
func loadDashboardTokenFile(flag, path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("%s is required", flag)
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", flag, err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("%s is empty", flag)
	}
	return token, nil
}
