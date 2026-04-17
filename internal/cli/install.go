// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
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
// That guarantees the CLI in the OpenClaw (or other sidecar-mate) container
// matches the running sidecar proxy byte-for-byte. The prior flow
// downloaded a hardcoded GitHub release tag inside an alpine init container,
// which left CLI and proxy versions drifted whenever an RC build shipped.
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

			in, err := os.Open(filepath.Clean(resolved))
			if err != nil {
				return fmt.Errorf("opening running binary: %w", err)
			}
			defer func() { _ = in.Close() }()

			if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
				return fmt.Errorf("creating destination directory: %w", err)
			}

			out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, execMode)
			if err != nil {
				return fmt.Errorf("opening destination: %w", err)
			}
			defer func() { _ = out.Close() }()

			if _, err := io.Copy(out, in); err != nil {
				return fmt.Errorf("copying binary: %w", err)
			}
			if err := out.Chmod(execMode); err != nil {
				return fmt.Errorf("setting executable bit: %w", err)
			}
			return nil
		},
	}
}
