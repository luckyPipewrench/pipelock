//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package fleet

import (
	"context"
	"crypto/ed25519"
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

	"github.com/luckyPipewrench/pipelock/enterprise/conductor"
	"github.com/luckyPipewrench/pipelock/enterprise/fleet/sink"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// sinkReadyHook, when non-nil, is invoked after the store, handler, and
// shutdown goroutine are wired but immediately before the listener blocks.
// Production leaves it nil (zero behavior change). Tests set it to trigger a
// deterministic shutdown once setup has completed, instead of racing setup
// (notably the store migration) against a fixed sleep.
var sinkReadyHook func()

func SinkCmd() *cobra.Command {
	var listenAddr string
	var storageDir string
	var trustedKeys []string
	var maxSkew time.Duration
	var tlsCert string
	var tlsKey string
	var clientCA string
	var readerTokenFile string
	var licenseCRLFile string

	cmd := &cobra.Command{
		Use:   "fleet-sink",
		Short: "Run a Conductor audit batch sink",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// License gate: fleet-sink is the Enterprise audit-sink server.
			// Fail-closed before any listener bind / disk IO so an unlicensed
			// invocation produces a clear entitlement error.
			if _, err := license.VerifyFleet("", "", licenseCRLFile); err != nil {
				return err
			}
			if strings.TrimSpace(storageDir) == "" {
				return errors.New("--storage-dir is required")
			}
			resolver, bindings, err := trustedAuditKeyResolver(trustedKeys)
			if err != nil {
				return err
			}
			readerToken, err := loadReaderToken(readerTokenFile)
			if err != nil {
				return err
			}
			if err := validateTLSFlags(tlsCert, tlsKey, clientCA); err != nil {
				return err
			}
			if err := validateBindAddress(listenAddr, tlsCert, tlsKey, clientCA, readerToken); err != nil {
				return err
			}

			ctx := cmd.Context()
			store, err := sink.OpenStore(ctx, filepath.Join(storageDir, "fleet-sink.db"))
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()

			sc := scanner.New(config.Defaults())
			handler, err := sink.NewHandler(sink.Options{
				Store:       store,
				Resolver:    resolver,
				DLPScanner:  sc,
				MaxSkew:     maxSkew,
				KeyBindings: bindings,
				ReaderToken: readerToken,
			})
			if err != nil {
				return err
			}

			server := &http.Server{
				Addr:              listenAddr,
				Handler:           handler,
				ReadHeaderTimeout: 5 * time.Second,
				ReadTimeout:       15 * time.Second,
				WriteTimeout:      15 * time.Second,
				IdleTimeout:       60 * time.Second,
				MaxHeaderBytes:    64 * 1024,
			}
			tlsConfig, err := listenerTLSConfig(clientCA)
			if err != nil {
				return err
			}
			server.TLSConfig = tlsConfig

			runCtx, stop := signalContext(ctx)
			defer stop()
			go func() {
				<-runCtx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdownCtx)
			}()

			// Setup is complete here (store migrated, handler built, shutdown
			// wired). Tests use this seam to cancel at a deterministic point so
			// ListenAndServe is exercised and exits cleanly via Shutdown.
			if sinkReadyHook != nil {
				sinkReadyHook()
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "pipelock: fleet sink listening on %s\n", listenAddr)
			if tlsCert != "" || tlsKey != "" {
				if err := server.ListenAndServeTLS(tlsCert, tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			}
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&listenAddr, "listen", "127.0.0.1:8894", "address for the fleet sink HTTP listener")
	cmd.Flags().StringVar(&storageDir, "storage-dir", "", "directory for the fleet sink SQLite store")
	cmd.Flags().StringArrayVar(&trustedKeys, "trusted-audit-key", nil,
		"trusted audit signing key as comma-separated kv pairs: 'id=ID,(inline=BASE64|file=/path)[,org=ORG][,fleet=FLEET][,instance=INSTANCE]'; repeatable")
	cmd.Flags().DurationVar(&maxSkew, "max-skew", conductor.DefaultAuditMaxSkew, "maximum allowed audit batch clock skew")
	cmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS server certificate file")
	cmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS server private key file")
	cmd.Flags().StringVar(&clientCA, "client-ca", "", "client CA PEM bundle for mTLS")
	cmd.Flags().StringVar(&readerTokenFile, "reader-token-file", "",
		"path to a file containing the bearer token required for GET requests; required for non-loopback bind without --client-ca")
	cmd.Flags().StringVar(&licenseCRLFile, "license-crl-file", "", "signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE")
	return cmd
}

// auditKeySpec is one parsed --trusted-audit-key value.
type auditKeySpec struct {
	id      string
	inline  string
	file    string
	binding sink.KeyBinding
}

func trustedAuditKeyResolver(values []string) (conductor.SignatureKeyResolver, map[string]sink.KeyBinding, error) {
	if len(values) == 0 {
		return nil, nil, errors.New("at least one --trusted-audit-key is required")
	}
	keys := make(map[string]conductor.SignatureKey, len(values))
	bindings := make(map[string]sink.KeyBinding, len(values))
	for _, raw := range values {
		spec, err := parseAuditKeySpec(raw)
		if err != nil {
			return nil, nil, err
		}
		pub, err := loadAuditPublicKey(spec)
		if err != nil {
			return nil, nil, fmt.Errorf("load trusted audit key %q: %w", spec.id, err)
		}
		if _, exists := keys[spec.id]; exists {
			return nil, nil, fmt.Errorf("duplicate trusted audit key id %q", spec.id)
		}
		keys[spec.id] = conductor.SignatureKey{
			PublicKey:  pub,
			KeyPurpose: signing.PurposeAuditBatchSigning,
		}
		if !spec.binding.IsZero() {
			bindings[spec.id] = spec.binding
		}
	}
	resolver := func(signerKeyID string) (conductor.SignatureKey, error) {
		key, ok := keys[signerKeyID]
		if !ok {
			return conductor.SignatureKey{}, fmt.Errorf("%w: key_id=%q", conductor.ErrInvalidSignature, signerKeyID)
		}
		return key, nil
	}
	return resolver, bindings, nil
}

// parseAuditKeySpec parses one --trusted-audit-key value. The expected
// format is comma-separated key=value pairs with `id=` plus exactly one
// of `inline=` or `file=` required, and optional `org=`, `fleet=`,
// `instance=` tenant binding constraints. The kv format replaces an
// earlier `key_id=value-or-path` shorthand whose parse-or-load fallback
// silently opened files when the value didn't parse as a key.
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
			spec.binding.OrgID = v
		case "fleet":
			spec.binding.FleetID = v
		case "instance":
			spec.binding.InstanceID = v
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
	return spec, nil
}

func loadAuditPublicKey(spec auditKeySpec) (ed25519.PublicKey, error) {
	if spec.inline != "" {
		return signing.ParsePublicKey(spec.inline)
	}
	return signing.LoadPublicKeyFile(filepath.Clean(spec.file))
}

// loadReaderToken reads a bearer token from disk. Reading from a file
// keeps tokens out of process argv and shell history. Empty path
// disables bearer auth.
func loadReaderToken(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("read reader token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", errors.New("reader token file is empty")
	}
	return token, nil
}

// validateBindAddress refuses to bind non-loopback addresses without
// some form of caller authentication. The audit signature authenticates
// ingest; for read endpoints the listener itself MUST be authenticated
// by mTLS (--client-ca) or the GET endpoints MUST be gated by a
// bearer token (--reader-token-file). Allowing 0.0.0.0:8894 with no
// auth is a production footgun that this check exists to prevent.
func validateBindAddress(addr, tlsCert, tlsKey, clientCA, readerToken string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen %q: %w", addr, err)
	}
	if isLoopbackHost(host) {
		return nil
	}
	if tlsCert == "" || tlsKey == "" {
		return fmt.Errorf("--listen %q is non-loopback; --tls-cert and --tls-key are required", addr)
	}
	if clientCA == "" && readerToken == "" {
		return fmt.Errorf("--listen %q is non-loopback; --client-ca (mTLS) or --reader-token-file is required", addr)
	}
	return nil
}

func validateTLSFlags(tlsCert, tlsKey, clientCA string) error {
	if (tlsCert == "") != (tlsKey == "") {
		return errors.New("--tls-cert and --tls-key must be provided together")
	}
	if clientCA != "" && (tlsCert == "" || tlsKey == "") {
		return errors.New("--client-ca requires --tls-cert and --tls-key")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func listenerTLSConfig(clientCAPath string) (*tls.Config, error) {
	if strings.TrimSpace(clientCAPath) == "" {
		return &tls.Config{MinVersion: tls.VersionTLS13}, nil
	}
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

func signalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
}
