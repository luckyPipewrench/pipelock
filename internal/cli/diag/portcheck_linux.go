// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package diag

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// enumerateListenerHolders builds a map of TCP listen port -> holding
// process by reading /proc/net/tcp and /proc/net/tcp6 (the inode column),
// then walking /proc/<pid>/fd/ to map inodes back to PIDs.
//
// The check is best-effort. Running without privileges to read another
// user's /proc/<pid>/fd entries leaves those holders identified by inode
// but unmapped (PID=0); callers surface that as "another process - re-run
// as root to identify".
func enumerateListenerHolders() (map[uint16][]procListener, error) {
	holders := make(map[uint16][]procListener)

	// First pass: read /proc/net/tcp[6] for ports in LISTEN state with
	// their backing socket inodes. The kernel format documented in
	// proc(5): hex remote/local addresses, state column at index 3,
	// inode column at index 9.
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if err := parseProcNetTCP(file, holders); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}
	}
	if len(holders) == 0 {
		// No listen sockets in /proc/net/tcp[6] - unusual but possible in
		// minimal containers. Return empty map (callers treat as "no
		// holder," not as an error) so configured listeners are reported
		// as free.
		return holders, nil
	}

	// Second pass: invert /proc/<pid>/fd/ symlinks to map socket inode -> PID.
	// Skipping unreadable entries is intentional; running without root
	// privileges restricts visibility to PIDs the calling user owns.
	matchInodeToPID(holders)
	return holders, nil
}

// parseProcNetTCP appends listening sockets from one /proc/net/tcp* file
// into holders. The local-port column (split[1]) is in the form
// "ADDR:PORT" with port encoded as 4 uppercase hex digits.
func parseProcNetTCP(path string, holders map[uint16][]procListener) error {
	const tcpStateListen = "0A" // hex 10, LISTEN per include/net/tcp_states.h
	f, err := os.Open(path)     // #nosec G304 -- /proc path is constant
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	first := true
	for scanner.Scan() {
		if first {
			first = false // header row
			continue
		}
		fields := strings.Fields(scanner.Text())
		// Required columns: local_address, state (index 3), inode (index 9).
		if len(fields) < 10 {
			continue
		}
		if fields[3] != tcpStateListen {
			continue
		}
		// fields[1] is "ADDR:PORT" hex. Take last 4 chars (port).
		localCol := fields[1]
		idx := strings.LastIndex(localCol, ":")
		if idx < 0 || idx+1 >= len(localCol) {
			continue
		}
		ip := parseProcNetIP(localCol[:idx], strings.HasSuffix(path, "tcp6"))
		port64, err := strconv.ParseUint(localCol[idx+1:], 16, 16)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		// Record the inode keyed under the holder slot. PID is filled in
		// by the second pass; we encode the inode in Cmdline temporarily
		// so the inode->PID step can find it back.
		port := uint16(port64)
		holders[port] = append(holders[port], procListener{Port: port, IP: ip, Cmdline: "inode:" + strconv.FormatUint(inode, 10)})
	}
	return scanner.Err()
}

func parseProcNetIP(hexAddr string, isIPv6 bool) net.IP {
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return nil
	}
	if !isIPv6 {
		if len(raw) != net.IPv4len {
			return nil
		}
		return net.IPv4(raw[3], raw[2], raw[1], raw[0])
	}
	if len(raw) != net.IPv6len {
		return nil
	}
	// /proc/net/tcp6 prints each 32-bit word in host byte order. Convert
	// little-endian host words back to network byte order for net.IP.
	if binary.NativeEndian.Uint16([]byte{1, 0}) == 1 {
		for i := 0; i < len(raw); i += 4 {
			raw[i], raw[i+3] = raw[i+3], raw[i]
			raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
		}
	}
	return net.IP(raw)
}

// matchInodeToPID walks /proc/<pid>/fd/ and looks for symlink targets of
// the form "socket:[INODE]". When we find one whose inode matches a
// holder we recorded from /proc/net/tcp, we replace the placeholder
// Cmdline with the real PID + cmdline. PIDs the calling user cannot
// readdir on are silently skipped.
func matchInodeToPID(holders map[uint16][]procListener) {
	// Build inverse map: inode -> port for the holders we still need PIDs for.
	type holderRef struct {
		port uint16
		idx  int
	}
	pending := make(map[uint64]holderRef, len(holders))
	for port, portHolders := range holders {
		for i, h := range portHolders {
			if strings.HasPrefix(h.Cmdline, "inode:") {
				inodeStr := strings.TrimPrefix(h.Cmdline, "inode:")
				n, err := strconv.ParseUint(inodeStr, 10, 64)
				if err == nil {
					pending[n] = holderRef{port: port, idx: i}
				}
			}
		}
	}
	if len(pending) == 0 {
		return
	}

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, ent := range procEntries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", ent.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue // typical when run as non-root against another user's process
		}
		for _, fd := range fdEntries {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			if ref, ok := pending[inode]; ok {
				cmdline := readProcCmdline(pid)
				holders[ref.port][ref.idx].PID = pid
				holders[ref.port][ref.idx].Cmdline = cmdline
				delete(pending, inode)
			}
		}
		if len(pending) == 0 {
			return
		}
	}
	// Any holder still keyed by inode is one whose PID we couldn't see -
	// reset its Cmdline to empty so callers surface "unknown holder (PID 0)"
	// rather than the internal inode marker.
	for port, portHolders := range holders {
		for i, h := range portHolders {
			if strings.HasPrefix(h.Cmdline, "inode:") {
				holders[port][i].PID = 0
				holders[port][i].Cmdline = ""
			}
		}
	}
}
