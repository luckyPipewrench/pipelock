//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
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
	cmd.AddCommand(dashboardBackupCmd())
	cmd.AddCommand(dashboardRestoreCmd())
	cmd.AddCommand(dashboardRebuildReadModelCmd())
	cmd.AddCommand(coverageCertCmd())
	cmd.AddCommand(exemptionCmd())
	cmd.AddCommand(legalHoldCmd())
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
	anchorExpected      bool
	anchorLocalLog      string
	rekorLogKeys        []string
	tlsCert             string
	tlsKey              string
	clientCAFile        string
	clientCertRoleMap   string
	requireClientCert   bool
	exemptionStore      string
	deliveryInbox       string
	readModelIndex      string
	legalHoldStore      string
	complianceTokenFile string
	oidcIssuer          string
	oidcAudience        string
	oidcClientID        string
	oidcRoleClaim       string
	oidcRoleMap         string
}

func dashboardServeCmd() *cobra.Command {
	opts := dashboardServeOptions{listen: dashboardDefaultListen}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the read-only Evidence dashboard on a dedicated listener",
		Long: `Serve the read-only Evidence dashboard over a flight-recorder evidence
directory. Every request must authenticate through a configured local operator
token, OIDC bearer token, or, when --require-client-cert is enabled, a verified
client certificate mapped to a dashboard role. The license feature check is
entitlement, not identity; the selected authenticator is the identity boundary.

By default the view is redacted: receipt destinations and signed payloads are
hidden, because a destination URL can carry a capability token and the payload
is the largest exfil surface. Supply --raw-token-file to issue a second,
higher-privilege token whose holders see the full raw detail, or grant
dashboard:raw:read to an OIDC role. Every authenticated request is written to
the access log on stderr.

Without --tls-cert/--tls-key the listener refuses non-loopback addresses,
because credentials would transit in cleartext.`,
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
	cmd.Flags().StringVar(&opts.deliveryInbox, "delivery-inbox", "",
		"optional alert delivery inbox file for read-only delivery health")
	cmd.Flags().StringVar(&opts.readModelIndex, "read-model-index", "",
		"optional rebuilt index metadata file for read-only freshness status")
	cmd.Flags().StringVar(&opts.legalHoldStore, "legal-hold-store", "",
		"optional legal-hold metadata store file for read-only compliance display")
	cmd.Flags().StringVar(&opts.authTokenFile, "auth-token-file", "",
		"optional file containing a dashboard operator token (redacted metadata view); required unless OIDC or --require-client-cert is configured")
	cmd.Flags().StringVar(&opts.rawTokenFile, "raw-token-file", "",
		"optional file containing a higher-privilege token that unlocks raw destinations and signed payloads; must differ from --auth-token-file")
	cmd.Flags().StringVar(&opts.complianceTokenFile, "compliance-token-file", "",
		"optional auditor token file granting only dashboard:compliance:read")
	cmd.Flags().StringVar(&opts.runtimeSnapshotFile, "runtime-snapshot-file", "",
		"read-only proxy runtime snapshot file for live dashboard budget data; defaults under --receipt-dir/dashboard/runtime-snapshot.json")
	cmd.Flags().StringArrayVar(&opts.trustedSigners, "trusted-signer", nil,
		"trusted receipt signing key as comma-separated kv pairs: "+
			"'(inline=HEX_OR_VERSIONED_PUBLIC_KEY|file=/path)[,source=LABEL]'; repeatable")
	cmd.Flags().StringVar(&opts.licenseCRLFile, "license-crl-file", "",
		"signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	cmd.Flags().BoolVar(&opts.anchorExpected, "anchor-expected", false,
		"fail the Trust & Keys audit when a receipt session has no anchor-state marker")
	cmd.Flags().StringVar(&opts.anchorLocalLog, "anchor-local-log", "",
		"local anchor log used to verify local-backend anchor bundles")
	cmd.Flags().StringArrayVar(&opts.rekorLogKeys, "rekor-log-key", nil,
		"pinned Rekor log public key used to verify SET, checkpoint, and inclusion proof; repeat for rotations")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "TLS server certificate file")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "TLS server private key file")
	cmd.Flags().StringVar(&opts.clientCAFile, "client-ca-file", "", "PEM trust anchor bundle for dashboard client certificates")
	cmd.Flags().BoolVar(&opts.requireClientCert, "require-client-cert", false, "require and verify a mapped dashboard client certificate")
	cmd.Flags().StringVar(&opts.clientCertRoleMap, "client-cert-role-map", "", "YAML file mapping client certificate SPKI SHA-256 fingerprints to permission roles")
	cmd.Flags().StringVar(&opts.oidcIssuer, "oidc-issuer", "",
		"OIDC issuer URL used for discovery and exact iss validation")
	cmd.Flags().StringVar(&opts.oidcAudience, "oidc-audience", "",
		"expected OIDC aud value for dashboard bearer tokens")
	cmd.Flags().StringVar(&opts.oidcClientID, "oidc-client-id", "",
		"alias for --oidc-audience; both values must match if both are set")
	cmd.Flags().StringVar(&opts.oidcRoleClaim, "oidc-role-claim", "",
		"verified token claim containing role or group values")
	cmd.Flags().StringVar(&opts.oidcRoleMap, "oidc-role-map", "",
		`JSON object: {"claim_values":{"GROUP":"ROLE"},"roles":{"ROLE":["dashboard:evidence:read"]}}`)
	_ = cmd.MarkFlagRequired("receipt-dir")
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
	if err := validateDashboardAuthenticatorConfig(opts); err != nil {
		return err
	}
	var token string
	var err error
	if strings.TrimSpace(opts.authTokenFile) != "" {
		token, err = loadDashboardTokenFile("--auth-token-file", opts.authTokenFile)
		if err != nil {
			return err
		}
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
	var complianceToken string
	if strings.TrimSpace(opts.complianceTokenFile) != "" {
		complianceToken, err = loadDashboardTokenFile("--compliance-token-file", opts.complianceTokenFile)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(complianceToken), []byte(token)) == 1 ||
			(rawToken != "" && subtle.ConstantTimeCompare([]byte(complianceToken), []byte(rawToken)) == 1) {
			return errors.New("--compliance-token-file must differ from operator and raw token files")
		}
	}
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	trusted, err := signingflag.ParseTrustedSigners(opts.trustedSigners)
	if err != nil {
		return err
	}
	if err := validateDashboardListen(opts); err != nil {
		return err
	}
	var clientCertAuth *dashboardClientCertAuthorizer
	if opts.requireClientCert {
		clientCertAuth, err = loadDashboardClientCertRoleMap(opts.clientCertRoleMap)
		if err != nil {
			return err
		}
	}
	info, err := os.Stat(filepath.Clean(opts.receiptDir))
	if err != nil {
		return fmt.Errorf("--receipt-dir: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("--receipt-dir %q is not a directory", opts.receiptDir)
	}
	anchorResolver, err := dashboard.NewFileAnchorResolver(
		opts.receiptDir, opts.anchorLocalLog, opts.rekorLogKeys, opts.anchorExpected,
	)
	if err != nil {
		return fmt.Errorf("anchor verifier: %w", err)
	}
	trustCRLSource, err := dashboardTrustCRLSource(opts.licenseCRLFile)
	if err != nil {
		return err
	}
	tlsConfig, err := dashboardTLSConfig(opts)
	if err != nil {
		return err
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
	var legalHoldStore *dashboard.LegalHoldStore
	if strings.TrimSpace(opts.legalHoldStore) != "" {
		legalHoldStore, err = dashboard.OpenLegalHoldStore(opts.legalHoldStore)
		if err != nil {
			return fmt.Errorf("--legal-hold-store: %w", err)
		}
	}

	var oidcAuthenticator *dashboardOIDCAuthenticator
	if strings.TrimSpace(opts.oidcIssuer) != "" {
		oidcAuthenticator, err = newDashboardOIDCAuthenticator(ctx, dashboardOIDCOptions{
			Issuer:      opts.oidcIssuer,
			Audience:    dashboardOIDCAudience(opts),
			RoleClaim:   opts.oidcRoleClaim,
			RoleMapJSON: opts.oidcRoleMap,
		})
		if err != nil {
			return err
		}
	}
	authorization := newDashboardRequestAuthorization(token, rawToken, complianceToken, oidcAuthenticator)
	// Token/OIDC auth retains its metadata/raw split. When mTLS is enabled, the
	// verified certificate's mapped role supplies both route and raw-view
	// permissions and takes precedence over any token or OIDC principal on the
	// same request.
	complianceAuthorized := func(r *http.Request) bool {
		return clientCertAuth == nil && authorization.complianceAuthorized(r)
	}
	metaAuthorized, authorizePermission, rawAuthorized := dashboardClientCertAuthorizers(
		clientCertAuth, authorization.metaAuthorized, authorization.rawAuthorized, complianceAuthorized,
	)
	authenticated := dashboardGlobalAuthorized(metaAuthorized, complianceAuthorized)

	auditWriter := cmd.ErrOrStderr()
	inner := dashboard.New(dashboard.Options{
		ReceiptDir:          opts.receiptDir,
		TrustedKeys:         trusted,
		TrustCRLSource:      trustCRLSource,
		AnchorResolver:      anchorResolver,
		Config:              loadedConfig,
		ExemptionStore:      exemptionStore,
		DeliveryInboxPath:   opts.deliveryInbox,
		ReadModelIndexPath:  opts.readModelIndex,
		LegalHoldStore:      legalHoldStore,
		HasFeature:          dashboardRuntimeHasFeature(lic),
		Authorize:           dashboardAuthorizeFunc(authenticated),
		AuthorizePermission: authorizePermission,
		AuthorizeRaw:        dashboardAuthorizeFunc(rawAuthorized),
		// Viewing evidence is itself audited; the access log goes to stderr.
		AuditWriter: auditWriter,
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
	authAuditInfo := authorization.authAuditInfo
	if clientCertAuth != nil {
		authAuditInfo = func(r *http.Request) dashboard.AuthAuditInfo {
			return dashboardClientCertAuthAuditInfo(clientCertAuth, r)
		}
	}
	handler := dashboardAuthHandler(authenticated, authAuditInfo, auditWriter, inner)
	if oidcAuthenticator != nil {
		handler = oidcAuthenticator.middleware(handler)
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
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if opts.requireClientCert {
		clientCAs, err := loadDashboardClientCAs(opts.clientCAFile)
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = clientCAs
	}
	return config, nil
}

// validateDashboardListen refuses configurations that would put the operator
// token on the wire in cleartext: without TLS, only loopback addresses are
// allowed. TLS flags must come as a pair.
func validateDashboardListen(opts dashboardServeOptions) error {
	if (opts.tlsCert == "") != (opts.tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be set together")
	}
	if opts.requireClientCert {
		if opts.tlsCert == "" {
			return errors.New("--require-client-cert requires --tls-cert/--tls-key")
		}
		if strings.TrimSpace(opts.clientCAFile) == "" {
			return errors.New("--require-client-cert requires --client-ca-file")
		}
		if strings.TrimSpace(opts.clientCertRoleMap) == "" {
			return errors.New("--require-client-cert requires --client-cert-role-map")
		}
	} else if strings.TrimSpace(opts.clientCAFile) != "" || strings.TrimSpace(opts.clientCertRoleMap) != "" {
		return errors.New("--client-ca-file and --client-cert-role-map require --require-client-cert")
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

func dashboardGlobalAuthorized(
	operatorAuthorized func(*http.Request) bool,
	complianceAuthorized func(*http.Request) bool,
) func(*http.Request) bool {
	return func(r *http.Request) bool {
		if operatorAuthorized(r) {
			return true
		}
		return r.URL.Path == dashboard.CompliancePath && complianceAuthorized != nil && complianceAuthorized(r)
	}
}

func dashboardAuthorizePermissionFunc(
	metaAuthorized func(*http.Request) bool,
	rawAuthorized func(*http.Request) bool,
	complianceAuthorized func(*http.Request) bool,
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
		case dashboard.PermissionComplianceRead:
			if metaAuthorized(r) || (complianceAuthorized != nil && complianceAuthorized(r)) {
				return nil
			}
		case dashboard.PermissionRawRead,
			dashboard.PermissionTrustKeysRead:
			if rawAuthorized(r) {
				return nil
			}
		}
		return fmt.Errorf("dashboard permission %q denied", permission)
	}
}

func dashboardTrustCRLSource(configuredPath string) (func() (*license.CRL, error), error) {
	path := strings.TrimSpace(configuredPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv(license.EnvLicenseCRLFile))
	}
	if path == "" {
		return nil, nil
	}
	root := license.EmbeddedPublicKey()
	if root == nil {
		publicKey := strings.TrimSpace(os.Getenv(license.EnvLicensePublicKey))
		if publicKey == "" {
			return nil, errors.New("license CRL configured but no license root public key is available")
		}
		parsed, err := signing.ParsePublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("parse license root public key for CRL audit: %w", err)
		}
		root = parsed
	}
	pinnedRoot := append([]byte(nil), root...)
	return func() (*license.CRL, error) {
		crl, err := license.LoadAndVerifyCRLMonotonic(path, pinnedRoot, time.Now())
		if err != nil {
			return nil, fmt.Errorf("verify license CRL for trust view: %w", err)
		}
		return &crl, nil
	}, nil
}

// dashboardAuthHandler is the outer authentication boundary. It answers 401
// with a WWW-Authenticate challenge so browsers prompt for credentials; the
// inner dashboard handler re-checks the same predicate via Options.Authorize as
// defense in depth.
func dashboardAuthHandler(
	authorized func(*http.Request) bool,
	authInfo func(*http.Request) dashboard.AuthAuditInfo,
	auditWriter io.Writer,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authorized(r) {
			recordDashboardAuthDenied(auditWriter, r, authInfo)
			w.Header().Set("WWW-Authenticate", `Basic realm="pipelock dashboard", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if authInfo != nil {
			r = r.WithContext(dashboard.WithAuthAuditInfo(r.Context(), authInfo(r)))
		}
		next.ServeHTTP(w, r)
	})
}

func dashboardClientCertAuthAuditInfo(auth *dashboardClientCertAuthorizer, r *http.Request) dashboard.AuthAuditInfo {
	info := dashboard.AuthAuditInfo{
		Method:        "mtls",
		FailureReason: "missing_client_certificate",
	}
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return info
	}
	info.Subject = dashboardClientCertSPKIFingerprint(r.TLS.PeerCertificates[0])
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		info.FailureReason = "unverified_client_certificate"
		return info
	}
	principal, ok := auth.principal(r)
	if !ok {
		info.FailureReason = "unmapped_client_certificate"
		return info
	}
	info.Roles = []string{principal.role}
	info.FailureReason = ""
	return info
}

func recordDashboardAuthDenied(auditWriter io.Writer, r *http.Request, authInfo func(*http.Request) dashboard.AuthAuditInfo) {
	if auditWriter == nil {
		return
	}
	info := dashboard.AuthAuditInfo{Method: "none", FailureReason: "missing_token"}
	if authInfo != nil {
		info = authInfo(r)
	}
	if info.FailureReason == "" {
		info.FailureReason = "unauthorized"
	}
	_, _ = fmt.Fprintf(auditWriter, "%s pipelock-dashboard denied method=%s path=%q auth_method=%s auth_subject=%q auth_roles=%q reason=%s remote=%s\n",
		time.Now().UTC().Format(time.RFC3339), r.Method, r.URL.Path,
		dashboard.AuditLogValue(info.Method), dashboard.AuditLogValue(info.Subject),
		strings.Join(dashboardAuditLogValues(info.Roles), ","), dashboard.AuditLogValue(info.FailureReason), r.RemoteAddr)
}

func dashboardAuditLogValues(values []string) []string {
	if len(values) == 0 {
		return []string{"-"}
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = dashboard.AuditLogValue(value)
	}
	return out
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
