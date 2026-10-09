// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package localservice

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

// nonFilePrefixes are held paths that are kernel or anonymous objects rather
// than files an operator could pin.
var nonFilePrefixes = []string{"/dev/", "/proc/", "/sys/", "/memfd:", "/SYSV"}

// Observe describes the owner of the server end of conn with the same owner
// discovery, retry and race guard VerifyConnContext uses, but with no pin to
// compare against. It is the discovery half of registering a service: the
// operator reviews what it reports before pinning any of it.
func (v *Verifier) Observe(ctx context.Context, conn net.Conn) (Observation, error) {
	var obs Observation
	err := v.retryPending(ctx, func() error {
		var attemptErr error
		obs, attemptErr = v.observeOnce(conn)
		return attemptErr
	})
	if err != nil {
		return Observation{}, err
	}
	return obs, nil
}

func (v *Verifier) observeOnce(conn net.Conn) (Observation, error) {
	local, remote, err := loopbackEndpoints(conn)
	if err != nil {
		return Observation{}, err
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	srv, err := v.findServerRow(local, remote)
	if err != nil {
		return Observation{}, err
	}
	own, err := v.findOwner(srv.inode)
	if err != nil {
		return Observation{}, err
	}
	first, err := v.readIncarnation(own.pid)
	if err != nil {
		return Observation{}, err
	}

	obs := Observation{PID: own.pid, StartTime: first.startTime, BootID: first.bootID}
	if obs.UID, err = v.effectiveUID(own.pid); err != nil {
		return Observation{}, err
	}
	var image Evidence
	if image.ExecutableDev, image.ExecutableIno, obs.ExecutableSHA256, err = v.executableDigest(own.pid); err != nil {
		return Observation{}, err
	}
	image.ExecutableSHA256 = obs.ExecutableSHA256
	held, err := v.heldFiles(own.pid)
	if err != nil {
		return Observation{}, err
	}
	obs.Files = observeFiles(held)
	if obs.ControlEnvironment, err = v.controlEnvironmentNames(own.pid); err != nil {
		return Observation{}, err
	}

	if v.beforeRecheck != nil {
		v.beforeRecheck()
	}
	if err = v.confirmOwner(own, first, srv.inode, image); err != nil {
		return Observation{}, err
	}
	return obs, nil
}

// controlEnvironmentNames returns the sorted names of deny-listed variables in
// the process environment. Values are discarded.
func (v *Verifier) controlEnvironmentNames(pid int) ([]string, error) {
	data, err := v.readEnviron(pid)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range bytes.Split(data, []byte{0}) {
		name, _, ok := strings.Cut(string(entry), "=")
		if !ok {
			continue
		}
		if _, deny := controlEnvironmentSet[name]; deny {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// observeFiles reduces the held files to the distinct regular files, hashing
// each one only through Pipelock's own open of the very same inode.
func observeFiles(held []heldFile) []ObservedFile {
	type key struct{ dev, ino uint64 }
	seen := make(map[key]bool, len(held))
	var files []ObservedFile
	for _, h := range held {
		if h.special || !filepath.IsAbs(h.path) || hasAnyPrefix(h.path, nonFilePrefixes) {
			continue
		}
		k := key{h.dev, h.ino}
		if seen[k] {
			continue
		}
		seen[k] = true
		file := ObservedFile{Path: filepath.Clean(h.path), Dev: h.dev, Ino: h.ino}
		file.SHA256, file.Path = hashIfSameInode(file)
		if file.SHA256 == "" && file.Path == "" {
			continue
		}
		files = append(files, file)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// hashIfSameInode opens the path without blocking, requires a regular file with
// the held device and inode, and hashes that opened descriptor. It returns the
// digest and the path; an empty digest means the path is not tied to the held
// file. A path that is no regular file at all returns both empty.
func hashIfSameInode(file ObservedFile) (sum, path string) {
	f, err := os.OpenFile(file.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", file.Path
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", file.Path
	}
	if !fi.Mode().IsRegular() {
		return "", ""
	}
	dev, ino, _, ok := fileIdentity(fi)
	if !ok || dev != file.Dev || ino != file.Ino {
		return "", file.Path
	}
	sum, err = hashFile(f)
	if err != nil {
		return "", file.Path
	}
	return sum, file.Path
}
