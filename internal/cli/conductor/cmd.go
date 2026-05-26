// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conductor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	conductorcore "github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	defaultListen       = "127.0.0.1:8895"
	defaultProbeListen  = "127.0.0.1:9092"
	defaultTrustDomain  = "pipelock.local"
	serveShutdownPeriod = 10 * time.Second
)

type serveOptions struct {
	listen              string
	probeListen         string
	storageDir          string
	conductorID         string
	followerTrustDomain string
	publisherTokenFile  string
	auditorTokenFile    string
	adminTokenFile      string
	trustedAuditKeys    []string
	tlsCert             string
	tlsKey              string
	clientCA            string
	logWriter           io.Writer
}

type auditKeySpec struct {
	id         string
	inline     string
	file       string
	orgID      string
	fleetID    string
	instanceID string
}

func Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "conductor",
		Short: "Run Conductor control-plane services",
	}
	cmd.AddCommand(serveCmd())
	return cmd
}

func serveCmd() *cobra.Command {
	opts := serveOptions{
		listen:              defaultListen,
		probeListen:         defaultProbeListen,
		conductorID:         "conductor",
		followerTrustDomain: defaultTrustDomain,
	}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve Conductor policy and audit ingest endpoints",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.listen, "listen", opts.listen, "address for the Conductor HTTPS listener")
	cmd.Flags().StringVar(&opts.probeListen, "probe-listen", opts.probeListen, "plain HTTP address for Conductor health, readiness, and metrics probes; empty disables the probe listener")
	cmd.Flags().StringVar(&opts.storageDir, "storage-dir", "", "directory for Conductor policy bundles and audit store")
	cmd.Flags().StringVar(&opts.conductorID, "conductor-id", opts.conductorID, "Conductor ID advertised in capabilities")
	cmd.Flags().StringVar(&opts.followerTrustDomain, "follower-trust-domain", opts.followerTrustDomain, "SPIFFE trust domain for follower mTLS identities")
	cmd.Flags().StringVar(&opts.publisherTokenFile, "publisher-token-file", "", "file containing bearer token required for policy publish requests")
	cmd.Flags().StringVar(&opts.auditorTokenFile, "auditor-token-file", "", "file containing bearer token required for audit metadata query requests")
	cmd.Flags().StringVar(&opts.adminTokenFile, "admin-token-file", "", "file containing bearer token required for Conductor admin requests")
	cmd.Flags().StringArrayVar(&opts.trustedAuditKeys, "trusted-audit-key", nil,
		"trusted audit signing key as comma-separated kv pairs: 'id=ID,(inline=BASE64|file=/path),org=ORG[,fleet=FLEET][,instance=INSTANCE]'; "+
			"org= is required so a key cannot authenticate batches across orgs; repeatable")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "TLS server certificate file")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "TLS server private key file")
	cmd.Flags().StringVar(&opts.clientCA, "client-ca", "", "client CA PEM bundle for follower mTLS")
	return cmd
}

func runServe(cmd *cobra.Command, opts serveOptions) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.logWriter == nil {
		opts.logWriter = cmd.ErrOrStderr()
	}
	handler, probeHandler, tlsConfig, err := buildServeHandler(ctx, opts)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              opts.listen,
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	baseCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runCtx, stop := signal.NotifyContext(baseCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(runCtx, "tcp", opts.listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	var probeLn net.Listener
	if strings.TrimSpace(opts.probeListen) != "" {
		probeLn, err = (&net.ListenConfig{}).Listen(runCtx, "tcp", opts.probeListen)
		if err != nil {
			return fmt.Errorf("probe bind %s: %w", opts.probeListen, err)
		}
		defer func() { _ = probeLn.Close() }()
	}
	var probeServer *http.Server
	if probeLn != nil {
		probeServer = &http.Server{
			Addr:              opts.probeListen,
			Handler:           probeHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    64 * 1024,
		}
	}
	go func() {
		<-runCtx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), serveShutdownPeriod)
		defer cancelShutdown()
		_ = server.Shutdown(shutdownCtx)
		if probeServer != nil {
			_ = probeServer.Shutdown(shutdownCtx)
		}
	}()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: conductor listening on %s\n", opts.listen)
	serverCount := 1
	errCh := make(chan error, 2)
	go func() {
		if err := server.ServeTLS(ln, opts.tlsCert, opts.tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	if probeServer != nil {
		serverCount++
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: conductor probes listening on %s\n", opts.probeListen)
		go func() {
			if err := probeServer.Serve(probeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
	}
	var firstErr error
	for range serverCount {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
			cancel()
		}
	}
	return firstErr
}

func buildServeHandler(ctx context.Context, opts serveOptions) (http.Handler, http.Handler, *tls.Config, error) {
	if strings.TrimSpace(opts.storageDir) == "" {
		return nil, nil, nil, errors.New("--storage-dir is required")
	}
	if err := validateServeTLSFlags(opts); err != nil {
		return nil, nil, nil, err
	}
	publisherToken, err := loadTokenFile("--publisher-token-file", opts.publisherTokenFile)
	if err != nil {
		return nil, nil, nil, err
	}
	authorizer, err := controlplane.BearerPublisherAuthorizer(publisherToken)
	if err != nil {
		return nil, nil, nil, err
	}
	auditorToken, err := loadTokenFile("--auditor-token-file", opts.auditorTokenFile)
	if err != nil {
		return nil, nil, nil, err
	}
	adminToken, err := loadTokenFile("--admin-token-file", opts.adminTokenFile)
	if err != nil {
		return nil, nil, nil, err
	}
	publishAuthorizer, err := controlplane.ScopedBearerBundleAuthorizer([]controlplane.ScopedBearerCredential{{
		Token: publisherToken,
		Role:  controlplane.RolePublisher,
	}})
	if err != nil {
		return nil, nil, nil, err
	}
	auditQueryAuthorizer, err := controlplane.ScopedBearerAuditQueryAuthorizer([]controlplane.ScopedBearerCredential{
		{Token: auditorToken, Role: controlplane.RoleAuditor},
		{Token: adminToken, Role: controlplane.RoleAdmin},
	})
	if err != nil {
		return nil, nil, nil, err
	}
	adminAuthorizer, err := controlplane.ScopedBearerAdminAuthorizer([]controlplane.ScopedBearerCredential{{
		Token: adminToken,
		Role:  controlplane.RoleAdmin,
	}})
	if err != nil {
		return nil, nil, nil, err
	}
	identity, err := controlplane.MTLSFollowerIdentityResolver(opts.followerTrustDomain)
	if err != nil {
		return nil, nil, nil, err
	}
	var auditKeys controlplane.AuditKeyResolver
	if len(opts.trustedAuditKeys) > 0 {
		auditKeys, err = buildAuditKeyResolver(opts.trustedAuditKeys)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	store, err := controlplane.OpenFileBundleStore(filepath.Join(opts.storageDir, "policy-bundles"))
	if err != nil {
		return nil, nil, nil, err
	}
	auditStore, err := controlplane.OpenSQLiteAuditStore(ctx, filepath.Join(opts.storageDir, "audit.db"))
	if err != nil {
		return nil, nil, nil, err
	}
	enrollments, err := controlplane.OpenFileEnrollmentStore(filepath.Join(opts.storageDir, "enrollments.json"))
	if err != nil {
		return nil, nil, nil, err
	}
	m := metrics.New()
	handler, err := controlplane.NewHandler(controlplane.HandlerOptions{
		Store:               store,
		Capabilities:        controlplane.DefaultCapabilities(opts.conductorID),
		FollowerIdentity:    identity,
		AuthorizePublisher:  authorizer,
		AuthorizeBundle:     publishAuthorizer,
		AuthorizeAuditQuery: auditQueryAuthorizer,
		AuthorizeAdmin:      adminAuthorizer,
		AuditSink:           auditStore,
		AuditKeys:           controlplane.CompositeAuditKeyResolver(enrollments, auditKeys),
		Enrollments:         enrollments,
		Metrics:             m,
		Logger:              conductorRequestLogger(opts.logWriter),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	tlsConfig, err := serveTLSConfig(opts.clientCA)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, err
	}
	return handler, handler.ProbeHandler(), tlsConfig, nil
}

func conductorRequestLogger(w io.Writer) *slog.Logger {
	if w == nil {
		return nil
	}
	return slog.New(slog.NewJSONHandler(w, nil))
}

func validateServeTLSFlags(opts serveOptions) error {
	switch {
	case strings.TrimSpace(opts.tlsCert) == "":
		return errors.New("--tls-cert is required")
	case strings.TrimSpace(opts.tlsKey) == "":
		return errors.New("--tls-key is required")
	case strings.TrimSpace(opts.clientCA) == "":
		return errors.New("--client-ca is required")
	default:
		return nil
	}
}

func serveTLSConfig(clientCAPath string) (*tls.Config, error) {
	pemBytes, err := os.ReadFile(filepath.Clean(clientCAPath))
	if err != nil {
		return nil, fmt.Errorf("read client CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("client CA bundle contains no PEM certificates")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}

func loadTokenFile(flag, path string) (string, error) {
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

func buildAuditKeyResolver(values []string) (controlplane.AuditKeyResolver, error) {
	if len(values) == 0 {
		return nil, controlplane.ErrAuditKeyRequired
	}
	keys := make([]controlplane.StaticAuditKey, 0, len(values))
	for _, value := range values {
		spec, err := parseAuditKeySpec(value)
		if err != nil {
			return nil, err
		}
		pub, err := loadAuditPublicKey(spec)
		if err != nil {
			return nil, fmt.Errorf("load trusted audit key %q: %w", spec.id, err)
		}
		keys = append(keys, controlplane.StaticAuditKey{
			KeyID: spec.id,
			Key: conductorcore.SignatureKey{
				PublicKey:  pub,
				KeyPurpose: signing.PurposeAuditBatchSigning,
			},
			OrgID:      spec.orgID,
			FleetID:    spec.fleetID,
			InstanceID: spec.instanceID,
		})
	}
	return controlplane.StaticAuditKeyResolver(keys)
}

func parseAuditKeySpec(raw string) (auditKeySpec, error) {
	if strings.TrimSpace(raw) == "" {
		return auditKeySpec{}, errors.New("invalid --trusted-audit-key: empty")
	}
	spec := auditKeySpec{}
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" {
			return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: expected k=v pairs", raw)
		}
		if _, dup := seen[k]; dup {
			return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: duplicate key %q", raw, k)
		}
		seen[k] = struct{}{}
		switch k {
		case "id":
			spec.id = v
		case "inline":
			spec.inline = v
		case "file":
			spec.file = v
		case "org":
			spec.orgID = v
		case "fleet":
			spec.fleetID = v
		case "instance":
			spec.instanceID = v
		default:
			return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: unknown field %q", raw, k)
		}
	}
	if spec.id == "" {
		return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: id= required", raw)
	}
	if (spec.inline == "" && spec.file == "") || (spec.inline != "" && spec.file != "") {
		return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: exactly one of inline= or file= required", raw)
	}
	if spec.orgID == "" {
		return auditKeySpec{}, fmt.Errorf("invalid --trusted-audit-key %q: org= required so an audit key cannot authenticate batches across orgs", raw)
	}
	return spec, nil
}

func loadAuditPublicKey(spec auditKeySpec) ([]byte, error) {
	if spec.inline != "" {
		return signing.ParsePublicKey(spec.inline)
	}
	return signing.LoadPublicKeyFile(filepath.Clean(spec.file))
}
