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

type observedFileKey struct {
	dev, ino uint64
}

// heldObservationKey reconciles descriptor and maps reports even when their
// devices differ. It only suppresses duplicate observations, never verifies
// an identity or supplies a digest. Paths separate btrfs subvolumes whose
// inode numbers can coincide.
type heldObservationKey struct {
	ino  uint64
	path string
}

// observeFiles reduces the held files to the distinct regular files, hashing
// each one only through Pipelock's own open of the very same inode.
func observeFiles(held []heldFile) []ObservedFile {
	seen := make(map[observedFileKey]bool, len(held))
	verifiedHeld := make(map[heldObservationKey]bool, len(held))
	unverified := make(map[heldObservationKey]ObservedFile, len(held))
	var files []ObservedFile
	for _, h := range held {
		if h.special || !filepath.IsAbs(h.path) || hasAnyPrefix(h.path, nonFilePrefixes) {
			continue
		}
		file := ObservedFile{Path: filepath.Clean(h.path), Dev: h.dev, Ino: h.ino}
		file, verified := hashIfSameInode(file, h, seen)
		if file.SHA256 == "" && file.Path == "" {
			continue
		}
		heldKey := heldObservationKey{ino: h.ino, path: file.Path}
		if !verified {
			unverified[heldKey] = file
			continue
		}
		verifiedHeld[heldKey] = true
		k := observedFileKey{dev: file.Dev, ino: file.Ino}
		if seen[k] {
			continue
		}
		seen[k] = true
		files = append(files, file)
	}
	for k, file := range unverified {
		if !verifiedHeld[k] {
			files = append(files, file)
		}
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

// hashIfSameInode opens the path without blocking, requires a regular file that
// is the held one (heldMatches: stat identity for a descriptor, maps identity
// for a mapping), and hashes that opened descriptor. A verified file carries
// the opened descriptor's stat identity so descriptors and mappings deduplicate
// even when their held devices differ. The boolean reports whether that identity
// was verified, independently of hashing success. An unverified file retains its
// held identity; a non-regular path returns an empty observation.
func hashIfSameInode(file ObservedFile, held heldFile, seen map[observedFileKey]bool) (ObservedFile, bool) {
	f, err := os.OpenFile(file.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return file, false
	}
	defer func() { _ = f.Close() }()
	return hashOpenedIfSameInode(file, held, f, seen)
}

func hashOpenedIfSameInode(file ObservedFile, held heldFile, f *os.File, seen map[observedFileKey]bool) (ObservedFile, bool) {
	fi, err := f.Stat()
	if err != nil {
		return file, false
	}
	if !fi.Mode().IsRegular() {
		return ObservedFile{}, false
	}
	dev, ino, _, ok := fileIdentity(fi)
	var mapsID heldFile
	var mapsOK bool
	if held.mapped && ok {
		mapsID, mapsOK = mapsIdentity(f, fi.Size())
	}
	if !ok || !heldMatches(held, dev, ino, mapsID, mapsOK) {
		return file, false
	}
	file.Dev, file.Ino = dev, ino
	if seen[observedFileKey{dev: dev, ino: ino}] {
		return file, true
	}
	sum, err := hashFile(f)
	if err != nil {
		return file, true
	}
	file.SHA256 = sum
	return file, true
}
