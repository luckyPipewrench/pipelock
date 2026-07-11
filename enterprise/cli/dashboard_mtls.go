//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

const dashboardClientCertRoleMapMaxBytes = 1 << 20

type dashboardClientCertRoleMapFile struct {
	Version      int                                `yaml:"version"`
	Roles        map[string]dashboardClientCertRole `yaml:"roles"`
	Certificates map[string]string                  `yaml:"certificates"`
}

type dashboardClientCertRole struct {
	Permissions []dashboard.Permission `yaml:"permissions"`
}

type dashboardClientCertPrincipal struct {
	role        string
	permissions map[dashboard.Permission]struct{}
}

type dashboardClientCertAuthorizer struct {
	principals map[[sha256.Size]byte]dashboardClientCertPrincipal
}

func loadDashboardClientCertRoleMap(path string) (*dashboardClientCertAuthorizer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--client-cert-role-map is required when --require-client-cert is set")
	}
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read --client-cert-role-map: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, dashboardClientCertRoleMapMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read --client-cert-role-map: %w", err)
	}
	if len(data) > dashboardClientCertRoleMapMaxBytes {
		return nil, fmt.Errorf("--client-cert-role-map exceeds %d bytes", dashboardClientCertRoleMapMaxBytes)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, errors.New("--client-cert-role-map is empty")
	}

	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	var mapping dashboardClientCertRoleMapFile
	if err := decoder.Decode(&mapping); err != nil {
		return nil, fmt.Errorf("parse --client-cert-role-map: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return nil, fmt.Errorf("parse --client-cert-role-map: %w", err)
		}
		return nil, errors.New("--client-cert-role-map must contain exactly one YAML document")
	}
	if mapping.Version != 1 {
		return nil, fmt.Errorf("--client-cert-role-map version must be 1, got %d", mapping.Version)
	}
	if len(mapping.Certificates) == 0 {
		return nil, errors.New("--client-cert-role-map must map at least one certificate")
	}

	knownPermissions := dashboardPermissionSet()
	roles := make(map[string]dashboardClientCertPrincipal, len(mapping.Roles))
	for roleName, role := range mapping.Roles {
		if strings.TrimSpace(roleName) == "" || roleName != strings.TrimSpace(roleName) {
			return nil, fmt.Errorf("--client-cert-role-map contains invalid role name %q", roleName)
		}
		if len(role.Permissions) == 0 {
			return nil, fmt.Errorf("--client-cert-role-map role %q must grant at least one permission", roleName)
		}
		permissions := make(map[dashboard.Permission]struct{}, len(role.Permissions))
		for _, permission := range role.Permissions {
			if _, ok := knownPermissions[permission]; !ok {
				return nil, fmt.Errorf("--client-cert-role-map role %q has unknown permission %q", roleName, permission)
			}
			if _, duplicate := permissions[permission]; duplicate {
				return nil, fmt.Errorf("--client-cert-role-map role %q has duplicate permission %q", roleName, permission)
			}
			permissions[permission] = struct{}{}
		}
		roles[roleName] = dashboardClientCertPrincipal{role: roleName, permissions: permissions}
	}

	principals := make(map[[sha256.Size]byte]dashboardClientCertPrincipal, len(mapping.Certificates))
	for fingerprintText, roleName := range mapping.Certificates {
		fingerprint, err := parseDashboardClientCertFingerprint(fingerprintText)
		if err != nil {
			return nil, fmt.Errorf("--client-cert-role-map certificate fingerprint %q: %w", fingerprintText, err)
		}
		principal, ok := roles[roleName]
		if !ok {
			return nil, fmt.Errorf("--client-cert-role-map certificate fingerprint %q references unknown role %q", fingerprintText, roleName)
		}
		if _, duplicate := principals[fingerprint]; duplicate {
			return nil, fmt.Errorf("--client-cert-role-map contains duplicate normalized fingerprint %q", fingerprintText)
		}
		principals[fingerprint] = principal
	}
	return &dashboardClientCertAuthorizer{principals: principals}, nil
}

func dashboardPermissionSet() map[dashboard.Permission]struct{} {
	permissions := dashboard.AllPermissions()
	known := make(map[dashboard.Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		known[permission] = struct{}{}
	}
	return known
}

func parseDashboardClientCertFingerprint(value string) ([sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	normalized := strings.TrimSpace(value)
	if len(normalized) >= len("sha256:") && strings.EqualFold(normalized[:len("sha256:")], "sha256:") {
		normalized = normalized[len("sha256:"):]
	}
	normalized = strings.ReplaceAll(normalized, ":", "")
	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != sha256.Size {
		return fingerprint, errors.New("SPKI SHA-256 fingerprint must be 32 bytes of hexadecimal")
	}
	copy(fingerprint[:], decoded)
	return fingerprint, nil
}

func dashboardClientCertSPKIFingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	fingerprint := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(fingerprint[:])
}

func (a *dashboardClientCertAuthorizer) principal(r *http.Request) (dashboardClientCertPrincipal, bool) {
	if a == nil || r == nil || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return dashboardClientCertPrincipal{}, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil {
		return dashboardClientCertPrincipal{}, false
	}
	fingerprint := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	principal, ok := a.principals[fingerprint]
	return principal, ok
}

func (a *dashboardClientCertAuthorizer) authorized(r *http.Request) bool {
	_, ok := a.principal(r)
	return ok
}

func (a *dashboardClientCertAuthorizer) authorizePermission(r *http.Request, permission dashboard.Permission) error {
	principal, ok := a.principal(r)
	if !ok {
		return errors.New("dashboard client certificate not authenticated")
	}
	if _, ok := principal.permissions[permission]; !ok {
		return fmt.Errorf("dashboard client certificate role %q denied permission %q", principal.role, permission)
	}
	return nil
}

func (a *dashboardClientCertAuthorizer) authorizeRaw(r *http.Request) error {
	return a.authorizePermission(r, dashboard.PermissionRawRead)
}

func dashboardClientCertAuthorizers(
	clientCertAuth *dashboardClientCertAuthorizer,
	tokenMetaAuthorized func(*http.Request) bool,
	tokenRawAuthorized func(*http.Request) bool,
	tokenComplianceAuthorized func(*http.Request) bool,
) (
	func(*http.Request) bool,
	func(*http.Request, dashboard.Permission) error,
	func(*http.Request) bool,
) {
	// When mutual TLS is enabled the verified client certificate is
	// authoritative: authorization never falls back to the operator token, so a
	// server-wiring, proxy, or ordering bug that lets a request reach the handler
	// without a verified certificate fails closed instead of silently degrading
	// to token access. The TLS layer already rejects certificate-less handshakes;
	// this keeps the application layer fail-closed independently of it.
	metaAuthorized := func(r *http.Request) bool {
		if clientCertAuth != nil {
			return clientCertAuth.authorized(r)
		}
		return tokenMetaAuthorized(r)
	}
	rawAuthorized := func(r *http.Request) bool {
		if clientCertAuth != nil {
			return clientCertAuth.authorizeRaw(r) == nil
		}
		return tokenRawAuthorized(r)
	}
	tokenAuthorizePermission := dashboardAuthorizePermissionFunc(tokenMetaAuthorized, tokenRawAuthorized, tokenComplianceAuthorized)
	authorizePermission := func(r *http.Request, permission dashboard.Permission) error {
		if clientCertAuth != nil {
			return clientCertAuth.authorizePermission(r, permission)
		}
		return tokenAuthorizePermission(r, permission)
	}
	return metaAuthorized, authorizePermission, rawAuthorized
}

func loadDashboardClientCAs(path string) (*x509.CertPool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("--client-ca-file is required when --require-client-cert is set")
	}
	pemBytes, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read --client-ca-file: %w", err)
	}
	// Parse every certificate block explicitly instead of AppendCertsFromPEM,
	// which silently skips malformed blocks and would start the dashboard with a
	// partial trust set. A trust anchor bundle must load completely or fail loud.
	pool := x509.NewCertPool()
	var added int
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("--client-ca-file contains a non-certificate PEM block %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("--client-ca-file contains a malformed certificate: %w", err)
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 {
		return nil, errors.New("--client-ca-file contains no valid PEM certificates")
	}
	return pool, nil
}
