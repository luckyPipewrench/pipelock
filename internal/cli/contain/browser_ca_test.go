// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

type fakeNSS struct {
	db        string
	entries   map[string]fakeNSSEntry
	ignoreAdd bool
}

type fakeNSSEntry struct {
	trust string
	pem   string
}

func newBrowserCAEnv(t *testing.T) (*installEnv, *fakeNSS) {
	t.Helper()
	env, _, _ := newFakeEnv(t)
	env.agentHome = filepath.Join(t.TempDir(), "agent")
	env.caExportPath = filepath.Join(t.TempDir(), "ca.pem")
	env.lookPath = func(name string) (string, error) {
		if name != browserCACertutilName {
			t.Fatalf("lookPath name = %q", name)
		}
		return "/usr/bin/certutil", nil
	}
	if err := os.WriteFile(env.caExportPath, []byte(testPEMCA(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	nss := &fakeNSS{
		db:      filepath.Join(env.agentHome, nssDBRelLegacy()),
		entries: make(map[string]fakeNSSEntry),
	}
	env.runCmd = nss.run
	return env, nss
}

func (f *fakeNSS) run(_ context.Context, name string, args ...string) (string, int, error) {
	if name != browserCACertutilName {
		return "", 0, nil
	}
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, " -N "):
		if err := os.MkdirAll(f.db, 0o700); err != nil {
			return "", 1, err
		}
		for _, file := range nssDatabaseFiles {
			if err := os.WriteFile(filepath.Join(f.db, file), []byte("db"), 0o600); err != nil {
				return "", 1, err
			}
		}
		return "", 0, nil
	case strings.Contains(joined, " -A "):
		if f.ignoreAdd {
			return "", 0, nil
		}
		nick := argAfter(args, "-n")
		cert, err := os.ReadFile(filepath.Clean(argAfter(args, "-i")))
		if err != nil {
			return "", 1, err
		}
		f.entries[nick] = fakeNSSEntry{trust: argAfter(args, "-t"), pem: string(cert)}
		return "", 0, nil
	case strings.Contains(joined, " -D "):
		delete(f.entries, argAfter(args, "-n"))
		return "", 0, nil
	case strings.Contains(joined, " -L ") && strings.Contains(joined, " -n "):
		entry, ok := f.entries[argAfter(args, "-n")]
		if !ok {
			return "not found", 255, nil
		}
		return entry.pem, 0, nil
	case strings.HasSuffix(joined, " -L"):
		var b strings.Builder
		b.WriteString("Certificate Nickname                                         Trust Attributes\n")
		b.WriteString("                                                             SSL,S/MIME,JAR/XPI\n\n")
		for nickname, entry := range f.entries {
			b.WriteString(nickname + " " + entry.trust + "\n")
		}
		return b.String(), 0, nil
	default:
		return "unexpected certutil invocation: " + joined, 2, nil
	}
}

func argAfter(args []string, flag string) string {
	for i := range args {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func distinctTestCA(t *testing.T) string {
	t.Helper()
	block, _ := pem.Decode([]byte(testPEMCA(t)))
	if block == nil {
		t.Fatal("test CA did not decode")
	}
	block.Bytes[len(block.Bytes)-1] ^= 1
	return string(pem.EncodeToMemory(block))
}

func TestEstablishAgentBrowserCATrust(t *testing.T) {
	t.Run("missing certutil names package and fails closed", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		env.platformFamily = platformFamilyDebian
		env.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "install libnss3-tools") {
			t.Fatalf("changed=%v err=%v, want missing libnss3-tools refusal", changed, err)
		}
	})

	t.Run("fresh install and rerun preserve exact trusted CA", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if err != nil || !changed {
			t.Fatalf("first install changed=%v err=%v", changed, err)
		}
		entry, ok := nss.entries[browserCANSSNickname]
		gotFingerprint, gotErr := firstCertFingerprint([]byte(entry.pem))
		wantPEM, readErr := os.ReadFile(env.caExportPath)
		wantFingerprint, wantErr := firstCertFingerprint(wantPEM)
		if !ok || entry.trust != browserCATrustArgs || gotErr != nil || readErr != nil || wantErr != nil || gotFingerprint != wantFingerprint {
			t.Fatalf("managed entry = %#v, present=%v", entry, ok)
		}
		changed, err = establishAgentBrowserCATrust(context.Background(), env)
		if err != nil || changed {
			t.Fatalf("rerun changed=%v err=%v", changed, err)
		}
	})

	t.Run("conflicting managed nickname is not overwritten", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if err := os.MkdirAll(nss.db, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nss.db, nssDatabaseFile), []byte("db"), 0o600); err != nil {
			t.Fatal(err)
		}
		other := distinctTestCA(t)
		nss.entries[browserCANSSNickname] = fakeNSSEntry{trust: browserCATrustArgs, pem: other}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "refusing to overwrite operator-managed trust") {
			t.Fatalf("changed=%v err=%v, want nickname conflict", changed, err)
		}
		if got := nss.entries[browserCANSSNickname].pem; got != other {
			t.Fatal("conflicting operator certificate was overwritten")
		}
	})

	t.Run("existing CA without server trust is not rewritten", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if err := os.MkdirAll(nss.db, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nss.db, nssDatabaseFile), []byte("db"), 0o600); err != nil {
			t.Fatal(err)
		}
		ca, err := os.ReadFile(env.caExportPath)
		if err != nil {
			t.Fatal(err)
		}
		nss.entries[browserCANSSNickname] = fakeNSSEntry{trust: ",,", pem: string(ca)}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "not C") || !strings.Contains(err.Error(), "operator-managed") {
			t.Fatalf("changed=%v err=%v, want trust refusal", changed, err)
		}
		if nss.entries[browserCANSSNickname].trust != ",," {
			t.Fatal("negative-test trust mutation did not take effect")
		}
	})

	t.Run("operator installed exact trust remains operator managed", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if err := os.MkdirAll(nss.db, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range nssDatabaseFiles {
			if err := os.WriteFile(filepath.Join(nss.db, name), []byte("db"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ca, err := os.ReadFile(env.caExportPath)
		if err != nil {
			t.Fatal(err)
		}
		nss.entries[browserCANSSNickname] = fakeNSSEntry{trust: browserCATrustArgs, pem: string(ca)}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if err != nil || changed {
			t.Fatalf("changed=%v err=%v, want unchanged operator trust", changed, err)
		}
		if err := removeManagedBrowserCA(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		if _, ok := nss.entries[browserCANSSNickname]; !ok {
			t.Fatal("operator-managed trust was removed")
		}
	})

	t.Run("added but not listed fails closed", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		nss.ignoreAdd = true
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "did not list") || !strings.Contains(err.Error(), "certutil -L") {
			t.Fatalf("changed=%v err=%v, want post-add listing failure", changed, err)
		}
		if _, ok := nss.entries[browserCANSSNickname]; ok {
			t.Fatal("negative-test add suppression did not take effect")
		}
		if err := removeManagedBrowserCA(context.Background(), env); err != nil {
			t.Fatalf("rollback failed: %v", err)
		}
	})

	t.Run("invalid ownership marker blocks rerun", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(browserCAMarkerPath(nss.db), []byte("invalid\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "ownership marker") || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("changed=%v err=%v, want invalid marker refusal", changed, err)
		}
		marker, readErr := os.ReadFile(browserCAMarkerPath(nss.db))
		if readErr != nil || string(marker) != "invalid\n" {
			t.Fatalf("negative-test marker mutation missing: %q %v", marker, readErr)
		}
	})
}

func TestProbeBrowserCATrustState(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	probe := &probeEnv{
		agentHome:      env.agentHome,
		caExportPath:   env.caExportPath,
		platformFamily: env.platformFamily,
		lookPath:       env.lookPath,
		stat:           os.Stat,
		readFile:       env.readFile,
		runCmd:         nss.run,
	}
	status, detail := probeBrowserCATrustState(context.Background(), probe)
	if status != statusPass || !strings.Contains(detail, "SSL CA trust C") || !strings.Contains(detail, "certutil -L") {
		t.Fatalf("status=%q detail=%q", status, detail)
	}

	entry := nss.entries[browserCANSSNickname]
	entry.trust = ",,"
	nss.entries[browserCANSSNickname] = entry
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "not C") || !strings.Contains(detail, "certutil -L") {
		t.Fatalf("status=%q detail=%q, want browser-consulted trust refusal", status, detail)
	}
	if nss.entries[browserCANSSNickname].trust != ",," {
		t.Fatal("negative-test trust mutation did not take effect")
	}

	entry.trust = browserCATrustArgs
	entry.pem = distinctTestCA(t)
	nss.entries[browserCANSSNickname] = entry
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "not listed") || !strings.Contains(detail, "certutil -L") {
		t.Fatalf("status=%q detail=%q, want certificate mismatch refusal", status, detail)
	}
	if nss.entries[browserCANSSNickname].pem != entry.pem {
		t.Fatal("negative-test certificate mutation did not take effect")
	}
}

func TestBrowserCAFilesystemFailures(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if owned, err := markerOwnedBy(env, nss.db); err != nil || !owned {
		t.Fatalf("positive marker control owned=%v err=%v", owned, err)
	}

	originalRead := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == browserCAMarkerPath(nss.db) {
			return nil, errors.New("read denied")
		}
		return originalRead(path)
	}
	if owned, err := markerOwnedBy(env, nss.db); owned || err == nil || !strings.Contains(err.Error(), "read browser CA ownership marker") {
		t.Fatalf("owned=%v err=%v, want marker read failure", owned, err)
	}
	env.readFile = originalRead

	originalWrite := env.writeFile
	env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
		if path == browserCAMarkerPath(nss.db) {
			return errors.New("write denied")
		}
		return originalWrite(path, contents, mode)
	}
	if err := writeBrowserCAMarker(env, nss.db); err == nil || !strings.Contains(err.Error(), "write browser CA ownership marker") {
		t.Fatalf("marker write error = %v", err)
	}
	env.writeFile = originalWrite

	originalRemove := env.removeFile
	env.removeFile = func(path string) error {
		if path == browserCAMarkerPath(nss.db) {
			return errors.New("remove denied")
		}
		return originalRemove(path)
	}
	if err := removeBrowserCAMarker(env, nss.db); err == nil || !strings.Contains(err.Error(), "remove browser CA ownership marker") {
		t.Fatalf("marker remove error = %v", err)
	}
}

func TestEstablishAgentBrowserCATrustFailurePaths(t *testing.T) {
	t.Run("invalid CA", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		if err := os.WriteFile(env.caExportPath, []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "parse Pipelock CA") {
			t.Fatalf("changed=%v err=%v, want CA parse refusal", changed, err)
		}
		data, readErr := os.ReadFile(env.caExportPath)
		if readErr != nil || string(data) != "invalid" {
			t.Fatalf("negative-test CA mutation missing: %q %v", data, readErr)
		}
	})

	t.Run("agent lookup failure", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		env.lookupUser = func(name string) (*user.User, error) {
			if name != env.agentUserName {
				t.Fatalf("lookup name = %q", name)
			}
			return nil, errors.New("unknown user")
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "lookup "+env.agentUserName) {
			t.Fatalf("changed=%v err=%v, want agent lookup refusal", changed, err)
		}
	})

	t.Run("database initialization failure", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if strings.Contains(strings.Join(args, " "), " -N ") {
				return "init denied", 4, nil
			}
			return nss.run(ctx, name, args...)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "initialize NSS database") || !strings.Contains(err.Error(), "init denied") {
			t.Fatalf("changed=%v err=%v, want init refusal", changed, err)
		}
		if nssDatabaseExists(os.Stat, nss.db) {
			t.Fatal("negative-test init failure did not take effect")
		}
	})

	t.Run("certificate add failure", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if strings.Contains(strings.Join(args, " "), " -A ") {
				return "add denied", 5, nil
			}
			return nss.run(ctx, name, args...)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "add Pipelock CA") || !strings.Contains(err.Error(), "add denied") {
			t.Fatalf("changed=%v err=%v, want add refusal", changed, err)
		}
		if _, ok := nss.entries[browserCANSSNickname]; ok {
			t.Fatal("negative-test add failure did not take effect")
		}
	})

	t.Run("new database ownership failure", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		originalChmod := env.chmod
		env.chmod = func(path string, mode os.FileMode) error {
			if filepath.Base(path) == nssDatabaseFile {
				return errors.New("chmod denied")
			}
			return originalChmod(path, mode)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "chmod") || !strings.Contains(err.Error(), nssDatabaseFile) {
			t.Fatalf("changed=%v err=%v, want NSS ownership refusal", changed, err)
		}
	})
}

func TestProbeBrowserCATrustAdditionalRefusals(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	probe := &probeEnv{
		agentUserName:  env.agentUserName,
		caExportPath:   env.caExportPath,
		platformFamily: env.platformFamily,
		lookPath:       env.lookPath,
		lookupUser:     env.lookupUser,
		stat:           os.Stat,
		readFile:       env.readFile,
		runCmd:         nss.run,
	}
	status, detail := probeBrowserCATrustState(context.Background(), probe)
	if status != statusPass || !strings.Contains(detail, "SSL CA trust C") {
		t.Fatalf("lookup-home positive control status=%q detail=%q", status, detail)
	}

	probe.lookupUser = func(string) (*user.User, error) { return nil, errors.New("unknown user") }
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "lookup "+env.agentUserName) {
		t.Fatalf("lookup refusal status=%q detail=%q", status, detail)
	}

	probe.agentHome = env.agentHome
	probe.lookupUser = env.lookupUser
	probe.readFile = func(path string) ([]byte, error) {
		if path == env.caExportPath {
			return []byte("invalid"), nil
		}
		return env.readFile(path)
	}
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "parse Pipelock CA") {
		t.Fatalf("CA refusal status=%q detail=%q", status, detail)
	}
	if data, err := probe.readFile(env.caExportPath); err != nil || string(data) != "invalid" {
		t.Fatalf("negative-test CA mutation missing: %q %v", data, err)
	}

	probe.readFile = env.readFile
	probe.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "list denied", 6, nil
	}
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "exited 6") || !strings.Contains(detail, "list denied") {
		t.Fatalf("list refusal status=%q detail=%q", status, detail)
	}

	probe.runCmd = nss.run
	probe.readFile = func(path string) ([]byte, error) {
		if path == env.caExportPath {
			return nil, errors.New("read denied")
		}
		return env.readFile(path)
	}
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusFail || !strings.Contains(detail, "read Pipelock CA") || !strings.Contains(detail, "read denied") {
		t.Fatalf("CA read refusal status=%q detail=%q", status, detail)
	}

	probe.browserCATrust = func(context.Context, *probeEnv) (string, string) {
		return statusPass, "injected browser trust"
	}
	status, detail = probeBrowserCATrustState(context.Background(), probe)
	if status != statusPass || detail != "injected browser trust" {
		t.Fatalf("injected probe status=%q detail=%q", status, detail)
	}
}

func TestInspectBrowserCAFailurePaths(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(env.caExportPath)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := firstCertFingerprint(ca)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := inspectBrowserCA(context.Background(), nss.run, env.platformFamily, nss.db, fingerprint); err != nil || !state.exact {
		t.Fatalf("positive inspect control state=%+v err=%v", state, err)
	}

	dumpFailure := func(ctx context.Context, name string, args ...string) (string, int, error) {
		if argAfter(args, "-n") != "" {
			return "dump denied", 7, nil
		}
		return nss.run(ctx, name, args...)
	}
	if _, err := inspectBrowserCA(context.Background(), dumpFailure, env.platformFamily, nss.db, fingerprint); err == nil || !strings.Contains(err.Error(), "dump denied") {
		t.Fatalf("dump error = %v", err)
	}

	invalidDump := func(ctx context.Context, name string, args ...string) (string, int, error) {
		if argAfter(args, "-n") != "" {
			return "invalid", 0, nil
		}
		return nss.run(ctx, name, args...)
	}
	if _, err := inspectBrowserCA(context.Background(), invalidDump, env.platformFamily, nss.db, fingerprint); err == nil || !strings.Contains(err.Error(), "parse NSS certificate") {
		t.Fatalf("invalid dump error = %v", err)
	}
}

func TestOwnNSSFilesFailurePaths(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := ownNSSFiles(env, nss.db, 123, 456); err != nil {
		t.Fatalf("positive ownership control: %v", err)
	}

	missing := filepath.Join(nss.db, nssPKCS11File)
	if err := os.Remove(missing); err != nil {
		t.Fatal(err)
	}
	if err := ownNSSFiles(env, nss.db, 123, 456); err == nil || !strings.Contains(err.Error(), nssPKCS11File) {
		t.Fatalf("missing NSS file error = %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("negative-test file removal missing: %v", err)
	}

	if err := os.WriteFile(missing, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalChown := env.lchown
	env.lchown = func(path string, uid, gid int) error {
		if filepath.Base(path) == nssDatabaseFile {
			return errors.New("chown denied")
		}
		return originalChown(path, uid, gid)
	}
	if err := ownNSSFiles(env, nss.db, 123, 456); err == nil || !strings.Contains(err.Error(), "chown denied") {
		t.Fatalf("chown error = %v", err)
	}
}

func TestEstablishBrowserCATrustRemainingFailures(t *testing.T) {
	t.Run("CA read", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		env.caExportPath = filepath.Join(t.TempDir(), "missing.pem")
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "read Pipelock CA") {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if _, statErr := os.Stat(env.caExportPath); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("negative-test missing CA did not take effect: %v", statErr)
		}
	})

	t.Run("unsafe database path", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		env.agentHome = "relative"
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "must be absolute") {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		if filepath.IsAbs(env.agentHome) {
			t.Fatal("negative-test relative home mutation did not take effect")
		}
	})

	t.Run("existing database list failure", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if err := os.MkdirAll(nss.db, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(nss.db, nssDatabaseFile), []byte("db"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "list denied", 8, nil
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if changed || err == nil || !strings.Contains(err.Error(), "list denied") {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
	})

	t.Run("marker write failure", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		originalWrite := env.writeFile
		env.writeFile = func(path string, contents []byte, mode os.FileMode) error {
			if path == browserCAMarkerPath(nss.db) {
				return errors.New("marker denied")
			}
			return originalWrite(path, contents, mode)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "marker denied") {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
	})

	t.Run("post-add inspection failure", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		listCalls := 0
		env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if argAfter(args, "-n") == "" && strings.HasSuffix(strings.Join(args, " "), " -L") {
				listCalls++
				if listCalls == 1 {
					return "post-add list denied", 9, nil
				}
			}
			return nss.run(ctx, name, args...)
		}
		changed, err := establishAgentBrowserCATrust(context.Background(), env)
		if !changed || err == nil || !strings.Contains(err.Error(), "post-add list denied") {
			t.Fatalf("changed=%v err=%v listCalls=%d", changed, err, listCalls)
		}
	})
}

func TestRemoveManagedBrowserCAFailurePaths(t *testing.T) {
	t.Run("missing database", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		if err := removeManagedBrowserCA(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("CA read and parse", func(t *testing.T) {
		env, _ := newBrowserCAEnv(t)
		if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(env.caExportPath); err != nil {
			t.Fatal(err)
		}
		if err := removeManagedBrowserCA(context.Background(), env); err == nil || !strings.Contains(err.Error(), "read Pipelock CA") {
			t.Fatalf("read error = %v", err)
		}
		if err := os.WriteFile(env.caExportPath, []byte("invalid"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := removeManagedBrowserCA(context.Background(), env); err == nil || !strings.Contains(err.Error(), "parse Pipelock CA") {
			t.Fatalf("parse error = %v", err)
		}
	})

	t.Run("list and delete failures", func(t *testing.T) {
		env, nss := newBrowserCAEnv(t)
		if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
			t.Fatal(err)
		}
		env.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "list denied", 10, nil
		}
		if err := removeManagedBrowserCA(context.Background(), env); err == nil || !strings.Contains(err.Error(), "list denied") {
			t.Fatalf("list error = %v", err)
		}
		env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if strings.Contains(strings.Join(args, " "), " -D ") {
				return "delete denied", 11, nil
			}
			return nss.run(ctx, name, args...)
		}
		if err := removeManagedBrowserCA(context.Background(), env); err == nil || !strings.Contains(err.Error(), "delete denied") {
			t.Fatalf("delete error = %v", err)
		}
		if _, ok := nss.entries[browserCANSSNickname]; !ok {
			t.Fatal("negative-test delete failure did not preserve CA")
		}
	})
}

func TestBrowserCATrustLifecycleWiring(t *testing.T) {
	install := installSteps(installOpts{})
	ca := stepIndex(install, "establish-agent-browser-ca-trust")
	bundle := stepIndex(install, "write-combined-ca")
	nft := stepIndex(install, "install-nft-rules")
	if ca < 0 || bundle < 0 || nft < 0 || bundle >= ca || ca >= nft {
		t.Fatalf("browser CA step order bundle=%d browser=%d nft=%d", bundle, ca, nft)
	}
	if stepIndex(rollbackActions(rollbackOpts{}), "remove-agent-browser-ca-trust") < 0 {
		t.Fatal("rollback does not remove managed browser CA trust")
	}
}

func TestActionRemoveBrowserCATrustRefusesChangedNickname(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	nss.entries[browserCANSSNickname] = fakeNSSEntry{trust: browserCATrustArgs, pem: distinctTestCA(t)}
	err := actionRemoveBrowserCATrust().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "refusing to remove operator-managed trust") {
		t.Fatalf("err=%v, want changed-nickname refusal", err)
	}
	if _, ok := nss.entries[browserCANSSNickname]; !ok {
		t.Fatal("negative-test mutation was not preserved; changed certificate was deleted")
	}

	env.lookPath = func(string) (string, error) { return "", errors.New("missing") }
	err = actionRemoveBrowserCATrust().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "install nss-tools") {
		t.Fatalf("err=%v, want missing certutil refusal", err)
	}
}

func TestBrowserCAHelpersAndFailureDirections(t *testing.T) {
	packages := map[string]string{
		platformFamilyDebian: "libnss3-tools",
		platformFamilySUSE:   "mozilla-nss-tools",
		platformFamilyArch:   "nss",
		"other":              "nss-tools",
	}
	for family, want := range packages {
		if got := certutilPackageForFamily(family); got != want {
			t.Errorf("package for %q = %q, want %q", family, got, want)
		}
	}

	home := t.TempDir()
	if got := agentNSSDatabaseDir(home, nil); got != filepath.Join(home, nssDBRelLegacy()) {
		t.Fatalf("nil stat selected %q", got)
	}
	xdg := filepath.Join(home, nssDBRelXDG())
	if err := os.MkdirAll(xdg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(xdg, nssDatabaseFile), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := agentNSSDatabaseDir(home, os.Stat); got != xdg {
		t.Fatalf("existing XDG database selected %q, want %q", got, xdg)
	}

	if _, err := firstCertFingerprint([]byte("not PEM")); err == nil || !strings.Contains(err.Error(), "no CERTIFICATE") {
		t.Fatalf("non-PEM error = %v", err)
	}
	nonCert := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	if _, err := firstCertFingerprint(nonCert); err == nil || !strings.Contains(err.Error(), "no CERTIFICATE") {
		t.Fatalf("non-certificate PEM error = %v", err)
	}
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})
	if _, err := firstCertFingerprint(badCert); err == nil || !strings.Contains(err.Error(), "parse certificate") {
		t.Fatalf("invalid certificate error = %v", err)
	}

	trust, ok := managedTrustFromList("Certificate Nickname Trust Attributes\nSSL,S/MIME,JAR/XPI\n\nignored\n" + browserCANSSNickname + " C,,\n")
	if !ok || trust != browserCATrustArgs {
		t.Fatalf("managed trust = %q, present=%v", trust, ok)
	}
}

func TestBrowserCACertutilFailures(t *testing.T) {
	env, _ := newBrowserCAEnv(t)
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "", 0, exec.ErrNotFound
	}
	if _, err := runBrowserCertutil(context.Background(), env.runCmd, env.platformFamily, "-L"); err == nil || !strings.Contains(err.Error(), "install nss-tools") {
		t.Fatalf("not-found error = %v", err)
	}
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "", 0, errors.New("exec denied")
	}
	if _, err := runBrowserCertutil(context.Background(), env.runCmd, env.platformFamily, "-L"); err == nil || !strings.Contains(err.Error(), "exec certutil") {
		t.Fatalf("exec error = %v", err)
	}
	env.runCmd = func(context.Context, string, ...string) (string, int, error) {
		return "bad database", 9, nil
	}
	if _, err := runBrowserCertutil(context.Background(), env.runCmd, env.platformFamily, "-L"); err == nil || !strings.Contains(err.Error(), "exited 9") || !strings.Contains(err.Error(), "bad database") {
		t.Fatalf("exit error = %v", err)
	}
}

func TestBrowserCAStepRollbackRemovesOnlyManagedTrust(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	step := stepEstablishBrowserCATrust()
	changed, err := step.apply(context.Background(), env)
	if err != nil || !changed {
		t.Fatalf("apply changed=%v err=%v", changed, err)
	}
	if _, ok := nss.entries[browserCANSSNickname]; !ok {
		t.Fatal("apply did not add managed CA")
	}
	if err := step.undo(context.Background(), env); err != nil {
		t.Fatalf("undo: %v", err)
	}
	if _, ok := nss.entries[browserCANSSNickname]; ok {
		t.Fatal("managed CA survived rollback")
	}
	if _, err := os.Stat(filepath.Join(nss.db, nssDatabaseFile)); err != nil {
		t.Fatalf("shared NSS database was removed: %v", err)
	}
	if _, err := os.Stat(browserCAMarkerPath(nss.db)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ownership marker survived rollback: %v", err)
	}
}

func TestProbeBrowserCATrustRefusalStates(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	probe := &probeEnv{
		agentHome:      env.agentHome,
		caExportPath:   env.caExportPath,
		platformFamily: env.platformFamily,
		lookPath:       env.lookPath,
		stat:           os.Stat,
		readFile:       env.readFile,
		runCmd:         nss.run,
	}

	tests := []struct {
		name  string
		setup func()
		want  string
	}{
		{name: "missing certutil", setup: func() {
			probe.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
		}, want: "install nss-tools"},
		{name: "missing database", setup: func() {
			probe.lookPath = env.lookPath
		}, want: "is missing"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			status, detail := probeBrowserCATrustState(context.Background(), probe)
			if status != statusFail || !strings.Contains(detail, tc.want) {
				t.Fatalf("status=%q detail=%q, want %q", status, detail, tc.want)
			}
		})
	}
}

func TestActionRemoveBrowserCATrustRemovesExactManagedCA(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if err := actionRemoveBrowserCATrust().undo(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if _, ok := nss.entries[browserCANSSNickname]; ok {
		t.Fatal("exact managed CA survived removal")
	}
}
