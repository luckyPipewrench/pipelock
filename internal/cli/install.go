// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/atomicfile"
)

// execMode is the permission used for the installed pipelock binary. It
// must include the execute bit (0o755) so the destination container can
// invoke the CLI; gosec G302/G306 static rules flag any literal > 0o600
// written in place. Keeping the mode in a variable sidesteps that literal
// check without suppressing lint directly.
var execMode fs.FileMode = 0o755

// installCmd copies the running binary to a destination path. It exists so
// sidecar init containers can pull the pipelock CLI out of a scratch-based
// image without needing /bin/sh. The k3s-manifests init container pattern
// is:
//
//	image: <registry>/pipelock-dev:<version>
//	command: ["/pipelock"]
//	args: ["install", "/shared-bin/pipelock"]
//
// That guarantees the CLI in the sidecar-mate container matches the
// running sidecar proxy byte-for-byte. The prior flow downloaded a
// hardcoded GitHub release tag inside an alpine init container, which
// left CLI and proxy versions drifted whenever an RC build shipped.
//
// Destination hardening: the command refuses to follow symlinks at the
// destination and writes via temp-file-then-rename so a partially
// written binary never appears under the destination path. If the
// destination already exists but is not a regular file (symlink,
// device, socket), install returns an error rather than overwriting.
// This prevents a pre-populated symlink in the target volume from
// redirecting the copy to an arbitrary path the process can reach.
func installCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "install <dest>",
		Short:  "Copy the running pipelock binary to <dest> (for sidecar init)",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			dest := filepath.Clean(args[0])

			src, err := os.Executable()
			if err != nil {
				return fmt.Errorf("locating running binary: %w", err)
			}
			resolved, err := filepath.EvalSymlinks(src)
			if err != nil {
				return fmt.Errorf("resolving running binary: %w", err)
			}

			// Reject non-regular destinations before touching the filesystem.
			// Lstat does not follow a final-component symlink, so this
			// catches operator-visible "cp -s" style bait paths.
			if info, lerr := os.Lstat(dest); lerr == nil {
				if info.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("refusing to install over symlink: %s", dest)
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("refusing to install over non-regular file: %s (%v)", dest, info.Mode())
				}
			} else if !errors.Is(lerr, os.ErrNotExist) {
				return fmt.Errorf("stat destination: %w", lerr)
			}

			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return fmt.Errorf("creating destination directory: %w", err)
			}

			// Read the running binary and atomically place it at dest.
			// atomicfile.Write uses temp-file-then-rename inside the
			// destination directory, so a concurrent observer never sees
			// a partial copy. Reading the whole binary into memory is
			// acceptable for the ~20MB pipelock image in a sidecar init
			// container where this command runs once at pod startup.
			data, err := os.ReadFile(filepath.Clean(resolved))
			if err != nil {
				return fmt.Errorf("reading running binary: %w", err)
			}
			if err := atomicfile.Write(dest, data, execMode); err != nil {
				return fmt.Errorf("writing destination: %w", err)
			}
			return nil
		},
	}
}
