//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
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
	"github.com/luckyPipewrench/pipelock/internal/signingflag"
)

const (
	// dashboardDefaultListen is loopback-only by design: the dashboard is an
	// authenticated admin surface on its own dedicated listener, never the
	// agent-reachable proxy port (same port-isolation principle as
	// kill_switch.api_listen).
	dashboardDefaultListen  = "127.0.0.1:8896"
	dashboardShutdownPeriod = 5 * time.Second
)

// DashboardCmd returns the `pipelock dashboard` command tree (Pro/Enterprise).
func DashboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Web dashboard over Pipelock evidence (Pro/Enterprise)",
	}
	cmd.AddCommand(dashboardServeCmd())
	cmd.AddCommand(coverageCertCmd())
	cmd.AddCommand(exemptionCmd())
	return cmd
}

type dashboardServeOptions struct {
	listen              string
	receiptDir          string
	configFile          string
	authTokenFile       string
	rawTokenFile        string
	runtimeSnapshotFile string
	trustedSigners      []string
	licenseCRLFile      string
	tlsCert             string
	tlsKey              string
	exemptionStore      string
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
			lic, err := verifyDashboardLicenseWithOptions(license.FleetVerifyInputs{CRLFile: opts.licenseCRLFile})
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
	cmd.Flags().StringVar(&opts.exemptionStore, "exemption-store", "",
		"optional exemption lifecycle store file; overlays owner/reason/expiry/status onto the read-only exemptions inventory")
	cmd.Flags().StringVar(&opts.authTokenFile, "auth-token-file", "",
		"file containing the operator token required on every dashboard request (redacted metadata view)")
	cmd.Flags().StringVar(&opts.rawTokenFile, "raw-token-file", "",
		"optional file containing a higher-privilege token that unlocks raw destinations and signed payloads; must differ from --auth-token-file")
	cmd.Flags().StringVar(&opts.runtimeSnapshotFile, "runtime-snapshot-file", "",
		"read-only proxy runtime snapshot file for live dashboard budget data; defaults under --receipt-dir/dashboard/runtime-snapshot.json")
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

func verifyDashboardLicenseWithOptions(in license.FleetVerifyInputs) (license.License, error) {
	lic, agentsErr := license.VerifyAgentsWithOptions(in)
	if agentsErr == nil {
		return lic, nil
	}
	lic, fleetErr := license.VerifyFleetWithOptions(in)
	if fleetErr == nil {
		return lic, nil
	}
	return license.License{}, fmt.Errorf(
		"dashboard requires a license that grants either the %q or %q feature: %w",
		license.FeatureAgents,
		license.FeatureFleet,
		errors.Join(agentsErr, fleetErr),
	)
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
	trusted, err := signingflag.ParseTrustedSigners(opts.trustedSigners)
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
	runtimeSnapshotFile := strings.TrimSpace(opts.runtimeSnapshotFile)
	if runtimeSnapshotFile == "" {
		runtimeSnapshotFile = filepath.Join(opts.receiptDir, "dashboard", "runtime-snapshot.json")
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
	runtimeSnapshotMaxAge := 3 * config.DefaultDashboardSnapshotInterval
	if loadedConfig != nil {
		runtimeSnapshotMaxAge = 3 * loadedConfig.DashboardSnapshot.IntervalDuration()
	}
	var exemptionStore *dashboard.ExemptionStore
	if strings.TrimSpace(opts.exemptionStore) != "" {
		exemptionStore, err = dashboard.OpenExemptionStore(opts.exemptionStore)
		if err != nil {
			return fmt.Errorf("--exemption-store: %w", err)
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
		ReceiptDir:          opts.receiptDir,
		TrustedKeys:         trusted,
		Config:              loadedConfig,
		ExemptionStore:      exemptionStore,
		HasFeature:          dashboardRuntimeHasFeature(lic),
		Authorize:           dashboardAuthorizeFunc(metaAuthorized),
		AuthorizePermission: dashboardAuthorizePermissionFunc(metaAuthorized, rawAuthorized),
		AuthorizeRaw:        dashboardAuthorizeFunc(rawAuthorized),
		// Viewing evidence is itself audited; the access log goes to stderr.
		AuditWriter: cmd.ErrOrStderr(),
		// TODO(DASH-3A): wire live conductor source when dashboard serve owns a
		// conductor audit/status store handle. Until then /fleet renders the
		// read-only empty state instead of inventing a fake conductor client.
		FleetSource: nil,
		// TODO(DASH-3B): wire the read-only conductor decision replay/dry-run
		// source when dashboard serve owns a conductor read handle. Until then
		// /workbench renders its prepare guidance plus the unconfigured-replay
		// state, and /incident renders the unconfigured-decision-source state.
		// The seam is read-only by construction (no publish/kill/rollback
		// method), so the dashboard holds no fleet-control authority even once
		// wired.
		ConductorSource: nil,
		BudgetSource:    dashboard.NewSnapshotBudgetSource(runtimeSnapshotFile, runtimeSnapshotMaxAge),
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

func dashboardAuthorizePermissionFunc(
	metaAuthorized func(*http.Request) bool,
	rawAuthorized func(*http.Request) bool,
) func(*http.Request, dashboard.Permission) error {
	return func(r *http.Request, permission dashboard.Permission) error {
		switch permission {
		case dashboard.PermissionEvidenceRead,
			dashboard.PermissionExemptionsRead,
			dashboard.PermissionAgentsRead,
			dashboard.PermissionBudgetsRead,
			dashboard.PermissionFleetRead,
			dashboard.PermissionSignedActionRead,
			dashboard.PermissionIncidentRead:
			if metaAuthorized(r) {
				return nil
			}
		case dashboard.PermissionRawRead:
			if rawAuthorized(r) {
				return nil
			}
		}
		return fmt.Errorf("dashboard permission %q denied", permission)
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
