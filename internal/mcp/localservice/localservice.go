// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package localservice proves which local process serves the far end of one
// loopback TCP connection and checks it against an operator registration.
//
// A loopback address names a place, not a program: any local process can bind a
// port. After Pipelock dials a loopback MCP upstream, VerifyConn asks the
// kernel who owns the server end of that exact connection (matched by the
// connected 4-tuple in the dialer's network namespace, then by socket inode)
// and compares the owner with a Pin. The Pin is vendor-agnostic: it describes a
// native binary, a Node, Python or JVM application, or anything else by what
// the kernel observes, never by command-line text.
//
// What a successful verification proves, at the moment of the check:
//
//   - the owning process runs as the registered OS principal (effective uid and
//     the uid recorded in the kernel socket table);
//   - the executable it is running (opened through the process's own exe link,
//     so a binary replaced on disk after launch does not mask it) hashes to the
//     registered value;
//   - every registered file is held by that process (open file descriptor or
//     memory mapping) as the very same device and inode that Pipelock just
//     opened and hashed, so an interpreter hosting an application bundle is
//     pinned through the bundle entry and not through a bare interpreter hash;
//   - the process environment carries none of the loader or interpreter
//     control variables listed by ControlEnvironmentDenyList unless the
//     registration names that variable with exactly that value;
//   - the process incarnation (start time within one boot) did not change while
//     the checks ran.
//
// What it does not prove:
//
//   - It does not stop code already running as the registered principal from
//     impersonating the service. Such code can load the same pinned files and
//     run the same executable, and the same principal can already read that
//     service's memory and files. Run services whose identity matters under
//     their own principal.
//   - The environment check reads the initial environment of the process; a
//     process can change its own environment later, and an interpreter can
//     still load code from sources the pins do not name. The deny list is a
//     floor, not a proof that no hook exists.
//   - A pinned file that the owner holds can be rewritten in place by the same
//     principal after the check; the result describes the state at check time.
//
// Verification is implemented on Linux only. Every other platform refuses with
// ErrUnsupportedPlatform: there is no weaker fallback.
package localservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/envcontrol"
)

// Field names of the operator registration, quoted in error text so a refusal
// points at the setting to correct.
const (
	fieldPrincipalUID = "verified_local_service.principal_uid"
	fieldExecutable   = "verified_local_service.executable_sha256"
	fieldMappedFiles  = "verified_local_service.mapped_files"
	fieldControlEnv   = "verified_local_service.control_environment"
)

const sha256HexLen = 64

// Sentinel errors. Every error returned by this package wraps exactly one of
// them with context; test with errors.Is.
var (
	// ErrUnsupportedPlatform: the platform cannot verify socket ownership.
	ErrUnsupportedPlatform = errors.New("verified local service is not supported on this platform")
	// ErrNotLoopback: the connection is not a TCP connection between loopback addresses.
	ErrNotLoopback = errors.New("connection is not a loopback TCP connection")
	// ErrSocketNotFound: the connection has no established entry in the kernel socket table.
	ErrSocketNotFound = errors.New("connection not found in the kernel socket table")
	// ErrOwnerNotVisible: the process holding the server end cannot be seen or inspected.
	ErrOwnerNotVisible = errors.New("socket owner is not visible")
	// ErrMultipleOwners: more than one process holds the server end.
	ErrMultipleOwners = errors.New("socket is held by more than one process")
	// ErrOwnerChanged: the owning process changed or exited while it was checked.
	ErrOwnerChanged = errors.New("socket owner changed during verification")
	// ErrPrincipalMismatch: the owner runs as a different OS principal than registered.
	ErrPrincipalMismatch = errors.New("socket owner principal does not match the registration")
	// ErrApplicationMismatch: the owner's executable or pinned files do not match the registration.
	ErrApplicationMismatch = errors.New("socket owner application does not match the registration")
	// ErrControlEnvironment: the owner carries unregistered loader or interpreter control variables.
	ErrControlEnvironment = errors.New("socket owner environment carries unregistered control variables")
	// ErrInvalidPin: the registration itself is malformed.
	ErrInvalidPin = errors.New("invalid verified local service registration")
)

// FilePin pins one file the owning process must hold open or mapped.
type FilePin struct {
	Path   string // absolute path
	SHA256 string // lowercase hex digest of the file contents
}

// Pin is the operator registration the owner of a connection is compared with.
type Pin struct {
	// PrincipalUID is verified_local_service.principal_uid.
	PrincipalUID uint32
	// ExecutableSHA256 is verified_local_service.executable_sha256: the digest
	// of the executable image the owning process is running.
	ExecutableSHA256 string
	// MappedFiles is verified_local_service.mapped_files: files the owner must
	// hold open or mapped, each hashed against its registered digest.
	MappedFiles []FilePin
	// ControlEnvironment is verified_local_service.control_environment: control
	// variables (see ControlEnvironmentDenyList) the owner may carry, each with
	// the exact value it is registered with.
	ControlEnvironment map[string]string
}

// Evidence records what was observed about a verified owner.
type Evidence struct {
	PID              int
	StartTime        uint64 // process start, clock ticks since boot
	BootID           string
	UID              uint32 // effective uid
	ExecutableDev    uint64
	ExecutableIno    uint64
	ExecutableSHA256 string
	MappedFiles      []FilePin // each verified file with the digest observed
}

// ObservedFile is a regular file an observed process holds open or mapped.
type ObservedFile struct {
	Path     string
	Dev, Ino uint64
	// SHA256 is the digest of the file, set only when Pipelock's own open of
	// Path is the very same device and inode the process holds. An empty digest
	// means the path could not be tied to the held file.
	SHA256 string
}

// Observation describes the owner of the server end of a loopback connection
// without comparing it with a registration.
type Observation struct {
	PID              int
	UID              uint32 // effective uid
	StartTime        uint64 // process start, clock ticks since boot
	BootID           string
	ExecutableSHA256 string
	// Files are the regular files the process holds, sorted by path.
	Files []ObservedFile
	// ControlEnvironment holds the NAMES of the deny-listed control variables the
	// process carries. Values are never read into the result.
	ControlEnvironment []string
}

// controlEnvironmentDenyList names variables that make a loader or an
// interpreter load code or change behavior outside the pinned files: every
// code-loading variable, plus the ones that change what the pinned code does
// without choosing other code (glibc tunables, loader profiling, and extra
// Node trust anchors).
var controlEnvironmentDenyList = slices.Concat(envcontrol.CodeLoadingNames(),
	[]string{"GLIBC_TUNABLES", "LD_PROFILE", "NODE_EXTRA_CA_CERTS"},
)

var controlEnvironmentSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(controlEnvironmentDenyList))
	for _, name := range controlEnvironmentDenyList {
		set[name] = struct{}{}
	}
	return set
}()

// ControlEnvironmentDenyList returns the sorted names of the loader and
// interpreter control variables an owner may not carry unless the registration
// names them in Pin.ControlEnvironment with the exact value. The list covers
// the glibc loader, Node.js, Bun, Python, the JVM, Ruby, Perl, Lua, PHP, .NET
// and shell startup files. It is a floor: a runtime not listed here is pinned
// through its executable and bundle files, not through this list.
func ControlEnvironmentDenyList() []string {
	out := make([]string, len(controlEnvironmentDenyList))
	copy(out, controlEnvironmentDenyList)
	sort.Strings(out)
	return out
}

func isLowerHexSHA256(s string) bool {
	if len(s) != sha256HexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validate rejects a registration that cannot be verified against.
func (p Pin) validate() error {
	if !isLowerHexSHA256(p.ExecutableSHA256) {
		return fmt.Errorf("%s must be %d lowercase hex characters: %w", fieldExecutable, sha256HexLen, ErrInvalidPin)
	}
	for i, f := range p.MappedFiles {
		if !path.IsAbs(f.Path) {
			return fmt.Errorf("%s[%d].path must be an absolute path: %w", fieldMappedFiles, i, ErrInvalidPin)
		}
		if !isLowerHexSHA256(f.SHA256) {
			return fmt.Errorf("%s[%d].sha256 must be %d lowercase hex characters: %w", fieldMappedFiles, i, sha256HexLen, ErrInvalidPin)
		}
	}
	for name := range p.ControlEnvironment {
		if name == "" || strings.ContainsAny(name, "=\x00") {
			return fmt.Errorf("%s has an invalid variable name: %w", fieldControlEnv, ErrInvalidPin)
		}
	}
	return nil
}

// DialContextFunc is the signature of net.Dialer.DialContext.
type DialContextFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

var errNilDialHook = errors.New("verifying dialer needs both a dial function and a verify function")

// VerifyingDialContext wraps inner so that every connection it returns has
// passed verify. A connection that fails verification is closed and its error
// returned; an unverified connection is never returned. An error from inner
// passes through unchanged. verify receives the dial's context, so a bounded
// retry inside it ends when the caller's deadline does.
func VerifyingDialContext(inner DialContextFunc, verify func(context.Context, net.Conn) error) DialContextFunc {
	if inner == nil || verify == nil {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errNilDialHook
		}
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := inner(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if err := verify(ctx, conn); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}
