// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Chromium documents the per-user NSS Shared DB and these certutil operations:
// https://chromium.googlesource.com/chromium/src/+/main/docs/linux/cert_management.md
// A machine policy would broaden trust beyond the contained user, so containment
// uses the browser-publisher-documented per-user control instead.
const (
	browserCANSSNickname   = "Pipelock Containment CA"
	browserCATrustArgs     = "C,,"
	browserCACertutilName  = "certutil"
	nssDatabaseFile        = "cert9.db"
	nssKeyDatabaseFile     = "key4.db"
	nssPKCS11File          = "pkcs11.txt"
	browserCAMarkerFile    = ".pipelock-ca-managed"
	probeBrowserCATrustNum = 20
	probeBrowserCATrust    = "agent_browser_ca_trust"
)

var nssDatabaseFiles = []string{nssDatabaseFile, nssKeyDatabaseFile, nssPKCS11File}

func certutilPackageForFamily(family string) string {
	switch family {
	case platformFamilyDebian:
		return "libnss3-tools"
	case platformFamilySUSE:
		return "mozilla-nss-tools"
	case platformFamilyArch:
		return "nss"
	default:
		return "nss-tools"
	}
}

func missingCertutilError(family string) error {
	return fmt.Errorf("certutil not found; install %s and rerun pipelock contain install so the contained agent browser trusts the Pipelock CA", certutilPackageForFamily(family))
}

func nssDBRelLegacy() string { return filepath.Join(".pki", "nssdb") }
func nssDBRelXDG() string    { return filepath.Join(".local", "share", "pki", "nssdb") }

func nssDatabaseExists(stat func(string) (os.FileInfo, error), dir string) bool {
	if stat == nil {
		return false
	}
	info, err := stat(filepath.Join(dir, nssDatabaseFile))
	return err == nil && info.Mode().IsRegular()
}

func agentNSSDatabaseDir(home string, stat func(string) (os.FileInfo, error)) string {
	legacy := filepath.Join(home, nssDBRelLegacy())
	if nssDatabaseExists(stat, legacy) {
		return legacy
	}
	xdg := filepath.Join(home, nssDBRelXDG())
	if nssDatabaseExists(stat, xdg) {
		return xdg
	}
	return legacy
}

func firstCertFingerprint(data []byte) (string, error) {
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return "", fmt.Errorf("parse certificate: %w", err)
		}
		sum := sha256.Sum256(block.Bytes)
		return hex.EncodeToString(sum[:]), nil
	}
	return "", errors.New("no CERTIFICATE PEM block")
}

func resolveCertutil(lookPath func(string) (string, error)) error {
	_, err := lookPath(browserCACertutilName)
	return err
}

func runBrowserCertutil(ctx context.Context, run runCommand, family string, args ...string) (string, error) {
	out, code, err := run(ctx, browserCACertutilName, args...)
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return out, missingCertutilError(family)
		}
		return out, fmt.Errorf("exec certutil: %w", err)
	}
	if code != 0 {
		return out, fmt.Errorf("certutil %s exited %d: %s", strings.Join(args, " "), code, oneLine(out))
	}
	return out, nil
}

func managedTrustFromList(out string) (string, bool) {
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		trust := fields[len(fields)-1]
		if strings.Count(trust, ",") != 2 {
			continue
		}
		if strings.TrimSpace(strings.TrimSuffix(line, trust)) == browserCANSSNickname {
			return trust, true
		}
	}
	return "", false
}

type browserCAState struct {
	present     bool
	exact       bool
	serverTrust bool
	trust       string
}

func inspectBrowserCA(ctx context.Context, run runCommand, family, db, wantFingerprint string) (browserCAState, error) {
	out, err := runBrowserCertutil(ctx, run, family, "-d", "sql:"+db, "-L")
	if err != nil {
		return browserCAState{}, err
	}
	trust, present := managedTrustFromList(out)
	if !present {
		return browserCAState{}, nil
	}
	pemOut, err := runBrowserCertutil(ctx, run, family, "-d", "sql:"+db, "-L", "-n", browserCANSSNickname, "-a")
	if err != nil {
		return browserCAState{}, err
	}
	fingerprint, err := firstCertFingerprint([]byte(pemOut))
	if err != nil {
		return browserCAState{}, fmt.Errorf("parse NSS certificate %q: %w", browserCANSSNickname, err)
	}
	return browserCAState{
		present:     true,
		exact:       fingerprint == wantFingerprint,
		serverTrust: strings.Contains(strings.SplitN(trust, ",", 2)[0], "C"),
		trust:       trust,
	}, nil
}

func browserCAMarkerPath(db string) string { return filepath.Join(db, browserCAMarkerFile) }

func markerOwnedBy(env *installEnv, db string) (bool, error) {
	data, err := env.readFile(browserCAMarkerPath(db))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read browser CA ownership marker: %w", err)
	}
	if string(data) != "managed\n" {
		return false, fmt.Errorf("browser CA ownership marker in %s is invalid; refusing to change trust state", db)
	}
	return true, nil
}

func writeBrowserCAMarker(env *installEnv, db string) error {
	path := browserCAMarkerPath(db)
	if err := env.writeFile(path, []byte("managed\n"), 0o600); err != nil {
		return fmt.Errorf("write browser CA ownership marker: %w", err)
	}
	return nil
}

func removeBrowserCAMarker(env *installEnv, db string) error {
	err := env.removeFile(browserCAMarkerPath(db))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove browser CA ownership marker: %w", err)
	}
	return nil
}

func ownNSSFiles(env *installEnv, db string, uid, gid int) error {
	for _, name := range nssDatabaseFiles {
		path := filepath.Join(db, name)
		if err := ensureAgentConfigLeaf(env, path); err != nil {
			return err
		}
		if err := env.chmod(path, 0o600); err != nil {
			return fmt.Errorf("chmod %s: %w", path, err)
		}
		if err := env.lchown(path, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
	}
	return nil
}

func establishAgentBrowserCATrust(ctx context.Context, env *installEnv) (bool, error) {
	if err := resolveCertutil(env.lookPath); err != nil {
		return false, missingCertutilError(env.platformFamily)
	}
	caPath := filepath.Clean(env.caExportPath)
	caPEM, err := env.readFile(caPath)
	if err != nil {
		return false, fmt.Errorf("read Pipelock CA %s: %w", caPath, err)
	}
	fingerprint, err := firstCertFingerprint(caPEM)
	if err != nil {
		return false, fmt.Errorf("parse Pipelock CA %s: %w", caPath, err)
	}
	uid, gid, err := uidGidFor(env, env.agentUserName)
	if err != nil {
		return false, err
	}
	db := agentNSSDatabaseDir(agentHomeDir(env), env.stat)
	if err := ensureAgentConfigDir(env, db, uid, gid); err != nil {
		return false, err
	}

	createdDB := !nssDatabaseExists(env.stat, db)
	if !createdDB {
		state, err := inspectBrowserCA(ctx, env.runCmd, env.platformFamily, db, fingerprint)
		if err != nil {
			return false, err
		}
		if state.present {
			if !state.exact {
				return false, fmt.Errorf("NSS nickname %q in %s belongs to a different certificate; refusing to overwrite operator-managed trust", browserCANSSNickname, db)
			}
			if !state.serverTrust {
				return false, fmt.Errorf("pipelock CA is present in %s with SSL trust %q, not C; refusing to overwrite operator-managed trust", db, state.trust)
			}
			_, err = markerOwnedBy(env, db)
			return false, err
		}
	} else if _, err := runBrowserCertutil(ctx, env.runCmd, env.platformFamily, "-d", "sql:"+db, "-N", "--empty-password"); err != nil {
		return true, fmt.Errorf("initialize NSS database %s: %w", db, err)
	}

	if err := writeBrowserCAMarker(env, db); err != nil {
		return true, err
	}
	if _, err := runBrowserCertutil(ctx, env.runCmd, env.platformFamily, "-d", "sql:"+db, "-A", "-t", browserCATrustArgs, "-n", browserCANSSNickname, "-i", caPath); err != nil {
		return true, fmt.Errorf("add Pipelock CA to NSS database %s: %w", db, err)
	}
	state, err := inspectBrowserCA(ctx, env.runCmd, env.platformFamily, db, fingerprint)
	if err != nil {
		return true, err
	}
	if !state.present || !state.exact || !state.serverTrust {
		return true, fmt.Errorf("certutil did not list the Pipelock CA with SSL CA trust C in %s (control: certutil -L -d sql:%s)", db, db)
	}
	if createdDB {
		if err := ownNSSFiles(env, db, uid, gid); err != nil {
			return true, err
		}
	}
	return true, nil
}

func removeManagedBrowserCA(ctx context.Context, env *installEnv) error {
	db := agentNSSDatabaseDir(agentHomeDir(env), env.stat)
	if !nssDatabaseExists(env.stat, db) {
		return removeBrowserCAMarker(env, db)
	}
	caPEM, err := env.readFile(filepath.Clean(env.caExportPath))
	if err != nil {
		return fmt.Errorf("read Pipelock CA before removing browser trust: %w", err)
	}
	fingerprint, err := firstCertFingerprint(caPEM)
	if err != nil {
		return fmt.Errorf("parse Pipelock CA before removing browser trust: %w", err)
	}
	owned, err := markerOwnedBy(env, db)
	if err != nil || !owned {
		return err
	}
	if err := resolveCertutil(env.lookPath); err != nil {
		return missingCertutilError(env.platformFamily)
	}
	state, err := inspectBrowserCA(ctx, env.runCmd, env.platformFamily, db, fingerprint)
	if err != nil {
		return err
	}
	if state.present && !state.exact {
		return fmt.Errorf("NSS nickname %q in %s no longer contains the Pipelock CA; refusing to remove operator-managed trust", browserCANSSNickname, db)
	}
	if state.present {
		if _, err := runBrowserCertutil(ctx, env.runCmd, env.platformFamily, "-d", "sql:"+db, "-D", "-n", browserCANSSNickname); err != nil {
			return fmt.Errorf("remove Pipelock CA from %s: %w", db, err)
		}
	}
	return removeBrowserCAMarker(env, db)
}

func stepEstablishBrowserCATrust() step {
	return step{
		name:  "establish-agent-browser-ca-trust",
		desc:  "establish contained-agent NSS database trust for the Pipelock CA",
		apply: establishAgentBrowserCATrust,
		undo:  removeManagedBrowserCA,
	}
}

func probeBrowserCATrustState(ctx context.Context, env *probeEnv) (string, string) {
	if env.browserCATrust != nil {
		return env.browserCATrust(ctx, env)
	}
	if err := resolveCertutil(env.lookPath); err != nil {
		return statusFail, missingCertutilError(env.platformFamily).Error()
	}
	home := env.agentHome
	if home == "" {
		u, err := env.lookupUser(env.agentUserName)
		if err != nil {
			return statusFail, fmt.Sprintf("lookup %s: %v", env.agentUserName, err)
		}
		home = filepath.Clean(u.HomeDir)
	}
	db := agentNSSDatabaseDir(home, env.stat)
	if !nssDatabaseExists(env.stat, db) {
		return statusFail, fmt.Sprintf("contained agent NSS database %s is missing (control: certutil -L -d sql:%s); rerun pipelock contain install", db, db)
	}
	caPath := filepath.Clean(env.caExportPath)
	caPEM, err := env.readFile(caPath)
	if err != nil {
		return statusFail, fmt.Sprintf("read Pipelock CA %s: %v", caPath, err)
	}
	fingerprint, err := firstCertFingerprint(caPEM)
	if err != nil {
		return statusFail, fmt.Sprintf("parse Pipelock CA %s: %v", caPath, err)
	}
	state, err := inspectBrowserCA(ctx, env.runCmd, env.platformFamily, db, fingerprint)
	if err != nil {
		return statusFail, err.Error()
	}
	control := fmt.Sprintf("certutil -L -d sql:%s", db)
	if !state.present || !state.exact {
		return statusFail, fmt.Sprintf("Pipelock CA is not listed in NSS database %s (control: %s); rerun pipelock contain install", db, control)
	}
	if !state.serverTrust {
		return statusFail, fmt.Sprintf("Pipelock CA has SSL trust %q, not C, in NSS database %s (control: %s); rerun pipelock contain install", state.trust, db, control)
	}
	return statusPass, fmt.Sprintf("NSS database %s lists %q with SSL CA trust C (control: %s)", db, browserCANSSNickname, control)
}

func actionRemoveBrowserCATrust() step {
	return step{
		name: "remove-agent-browser-ca-trust",
		desc: "remove Pipelock-managed CA trust from the contained agent NSS database",
		undo: removeManagedBrowserCA,
	}
}
