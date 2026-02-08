package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		Long: `Display Pipelock version, build date, commit hash, and Go version.

The build metadata is injected via ldflags when building with "make build".
When building with plain "go build", default values are shown.`,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("pipelock version %s\n", Version)
			fmt.Printf("  build date: %s\n", BuildDate)
			fmt.Printf("  git commit: %s\n", GitCommit)
			fmt.Printf("  go version: %s\n", GoVersion)
		},
	}
}
