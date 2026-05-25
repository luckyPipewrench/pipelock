// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package conductor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	conductorcore "github.com/luckyPipewrench/pipelock/internal/conductor"
	"github.com/luckyPipewrench/pipelock/internal/conductor/controlplane"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	defaultListen      = "127.0.0.1:8895"
	defaultTrustDomain = "pipelock.local"
)

type serveOptions struct {
	listen              string
	storageDir          string
	conductorID         string
	followerTrustDomain string
	publisherTokenFile  string
	trustedAuditKeys    []string
	tlsCert             string
	tlsKey              string
	clientCA            string
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
	cmd.Flags().StringVar(&opts.storageDir, "storage-dir", "", "directory for Conductor policy bundles and audit spool")
	cmd.Flags().StringVar(&opts.conductorID, "conductor-id", opts.conductorID, "Conductor ID advertised in capabilities")
	cmd.Flags().StringVar(&opts.followerTrustDomain, "follower-trust-domain", opts.followerTrustDomain, "SPIFFE trust domain for follower mTLS identities")
	cmd.Flags().StringVar(&opts.publisherTokenFile, "publisher-token-file", "", "file containing bearer token required for policy publish requests")
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
	handler, tlsConfig, err := buildServeHandler(ctx, opts)
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
	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	ln, err := (&net.ListenConfig{}).Listen(runCtx, "tcp", opts.listen)
	if err != nil {
		return err
	}
	defer func() { _ = ln.Close() }()
	go func() {
		<-runCtx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: conductor listening on %s\n", opts.listen)
	if err := server.ServeTLS(ln, opts.tlsCert, opts.tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func buildServeHandler(ctx context.Context, opts serveOptions) (http.Handler, *tls.Config, error) {
	if strings.TrimSpace(opts.storageDir) == "" {
		return nil, nil, errors.New("--storage-dir is required")
	}
	if err := validateServeTLSFlags(opts); err != nil {
		return nil, nil, err
	}
	publisherToken, err := loadTokenFile(opts.publisherTokenFile)
	if err != nil {
		return nil, nil, err
	}
	authorizer, err := controlplane.BearerPublisherAuthorizer(publisherToken)
	if err != nil {
		return nil, nil, err
	}
	identity, err := controlplane.MTLSFollowerIdentityResolver(opts.followerTrustDomain)
	if err != nil {
		return nil, nil, err
	}
	auditKeys, err := buildAuditKeyResolver(opts.trustedAuditKeys)
	if err != nil {
		return nil, nil, err
	}
	store, err := controlplane.OpenFileBundleStore(filepath.Join(opts.storageDir, "policy-bundles"))
	if err != nil {
		return nil, nil, err
	}
	spool, err := controlplane.OpenFileAuditSpool(filepath.Join(opts.storageDir, "audit-spool"))
	if err != nil {
		return nil, nil, err
	}
	handler, err := controlplane.NewHandler(controlplane.HandlerOptions{
		Store:              store,
		Capabilities:       controlplane.DefaultCapabilities(opts.conductorID),
		FollowerIdentity:   identity,
		AuthorizePublisher: authorizer,
		AuditSink:          spool,
		AuditKeys:          auditKeys,
	})
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := serveTLSConfig(opts.clientCA)
	if err != nil {
		return nil, nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return handler, tlsConfig, nil
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

func loadTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("--publisher-token-file is required")
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read publisher token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("publisher token file is empty")
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
