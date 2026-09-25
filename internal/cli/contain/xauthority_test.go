// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEncodeDisplayAuthorityMatchesXauthorityFormat(t *testing.T) {
	cookie := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	got, err := encodeDisplayAuthority("host", "7", cookie)
	if err != nil {
		t.Fatalf("encodeDisplayAuthority: %v", err)
	}
	want, err := hex.DecodeString("01000004686f737400013700124d49542d4d414749432d434f4f4b49452d310010000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Xauthority bytes = %x, want %x", got, want)
	}
	if _, err := encodeDisplayAuthority("host", "7", cookie[:15]); err == nil || !strings.Contains(err.Error(), "want 16") {
		t.Fatalf("short cookie error = %v, want a 16-byte requirement", err)
	}
}

func TestWriteDisplayAuthorityCreatesAgentOwned0600File(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	env.displayNumber = 7
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(current.Uid)
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	env.lookupUser = func(name string) (*user.User, error) {
		return &user.User{Uid: strconv.Itoa(uid), Gid: strconv.Itoa(gid), Username: name}, nil
	}
	env.chown = os.Chown
	cookie := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	if err := writeDisplayAuthority(env, bytes.NewReader(cookie)); err != nil {
		t.Fatalf("writeDisplayAuthority: %v", err)
	}
	info, err := os.Stat(env.displayAuthorityPath)
	if err != nil {
		t.Fatalf("stat Xauthority file: %v", err)
	}
	if got := info.Mode().Perm(); got != displayAuthorityFileMode {
		t.Fatalf("Xauthority mode = %#o, want %#o", got, displayAuthorityFileMode)
	}
	owner, ok := fileOwnerUID(info)
	if !ok || strconv.FormatUint(uint64(owner), 10) != current.Uid {
		t.Fatalf("Xauthority owner = %d (known=%v), want agent uid %d", owner, ok, uid)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	want, err := encodeDisplayAuthority(hostname, "7", cookie)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Clean(env.displayAuthorityPath))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("Xauthority contents = %x, read err %v, want %x", got, err, want)
	}
}

func TestEnsureDisplayAuthorityDirRejectsWritableParent(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	dir := filepath.Dir(env.displayAuthorityPath)
	parent := filepath.Dir(dir)
	realLstat := env.lstat
	env.lstat = func(path string) (os.FileInfo, error) {
		info, err := realLstat(path)
		if err == nil && filepath.Clean(path) == filepath.Clean(parent) {
			return fakeFileInfo{mode: os.ModeDir | 0o770, sys: fakeFileSysWithUID(0)}, nil
		}
		return info, err
	}
	if err := ensureDisplayAuthorityDir(env, dir); err == nil || !strings.Contains(err.Error(), "writable by non-root users") {
		t.Fatalf("ensureDisplayAuthorityDir error = %v, want writable-parent refusal", err)
	}
}

func TestRenderAgentDisplayUnitRequiresAuthAtStartup(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	env.displayNumber = 7
	body := renderAgentDisplayUnit(env)
	want := " -auth " + env.displayAuthorityPath + " -screen "
	if !strings.Contains(body, want) {
		t.Fatalf("Xvfb ExecStart lacks startup authorization %q:\n%s", want, body)
	}
}

func TestActionRemoveAgentDisplayRemovesAuthority(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.displayAuthorityPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.displayAuthorityPath, []byte("cookie"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := actionRemoveAgentDisplay().undo(context.Background(), env); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if _, err := os.Stat(env.displayAuthorityPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Xauthority file survived rollback: stat err %v", err)
	}
}
