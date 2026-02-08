package cli

import (
	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		Long: `Display Pipelock version, build date, commit hash, and Go version.

The build metadata is injected via ldflags when building with "make build".
When building with plain "go build", default values are shown.`,
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Printf("pipelock version %s\n", Version)
			cmd.Printf("  build date: %s\n", BuildDate)
			cmd.Printf("  git commit: %s\n", GitCommit)
			cmd.Printf("  go version: %s\n", GoVersion)
		},
	}
}
