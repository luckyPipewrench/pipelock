// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenNoFollowDirRejectsIntermediateSymlink(t *testing.T) {
	base := writableSymlinkFreeDir(t)
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(real, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	linkedChild := filepath.Join(link, "child")

	opened, err := openNoFollowDir(child)
	if err != nil {
		t.Fatalf("real directory: %v", err)
	}
	opened.close()

	if _, err := openNoFollowDir(linkedChild); err == nil {
		t.Fatal("intermediate symlink was followed")
	}
}

func writableSymlinkFreeDir(t *testing.T) string {
	t.Helper()
	candidates := []string{t.TempDir(), "/var/tmp", "/dev/shm"}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, home)
	}
	var reasons []string
	for _, dir := range candidates {
		if err := pathSymlink(dir); err != nil {
			reasons = append(reasons, dir+": "+err.Error())
			continue
		}
		sub, err := os.MkdirTemp(dir, "plk-nofollow-")
		if err != nil {
			reasons = append(reasons, dir+": "+err.Error())
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(sub) })
		if err := pathSymlink(sub); err != nil {
			reasons = append(reasons, sub+": "+err.Error())
			continue
		}
		return sub
	}
	t.Fatalf("no writable directory without a symlink component: %s", strings.Join(reasons, "; "))
	return ""
}

func pathSymlink(path string) error {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return errors.New("path is not absolute")
	}
	cur := "/"
	rest := strings.TrimPrefix(cleaned, "/")
	for _, name := range strings.Split(rest, "/") {
		if name == "" {
			continue
		}
		cur = filepath.Join(cur, name)
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink component " + cur)
		}
	}
	return nil
}
