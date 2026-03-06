package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/certgen"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/spf13/cobra"
)

func tlsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "TLS certificate management for CONNECT tunnel interception",
	}
	cmd.AddCommand(tlsInitCmd())
	cmd.AddCommand(tlsInstallCACmd())
	cmd.AddCommand(tlsShowCACmd())
	return cmd
}

func tlsInitCmd() *cobra.Command {
	var (
		org      string
		validity string
		outDir   string
		force    bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a TLS CA certificate and private key",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dur, err := time.ParseDuration(validity)
			if err != nil {
				return fmt.Errorf("invalid validity: %w", err)
			}
			if outDir == "" {
				outDir, err = signing.DefaultKeystorePath()
				if err != nil {
					return fmt.Errorf("resolve default path: %w", err)
				}
			}
			certPath := filepath.Join(outDir, "ca.pem")
			keyPath := filepath.Join(outDir, "ca-key.pem")

			ca, key, _, err := certgen.GenerateCA(org, dur)
			if err != nil {
				return fmt.Errorf("generate CA: %w", err)
			}

			if force {
				err = certgen.SaveCAForce(certPath, keyPath, ca, key)
			} else {
				err = certgen.SaveCA(certPath, keyPath, ca, key)
			}
			if err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CA certificate: %s\n", certPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "CA private key: %s\n", keyPath)
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\nNext: run 'pipelock tls install-ca' to add the CA to your system trust store.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&org, "org", "Pipelock", "Organization name for CA subject")
	cmd.Flags().StringVar(&validity, "validity", "87600h", "CA certificate validity period")
	cmd.Flags().StringVar(&outDir, "out", "", "Output directory (default $HOME/.pipelock)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing CA files")
	return cmd
}

func tlsInstallCACmd() *cobra.Command {
	var certPath string
	cmd := &cobra.Command{
		Use:   "install-ca",
		Short: "Install the Pipelock CA certificate in the system trust store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certPath == "" {
				dir, err := signing.DefaultKeystorePath()
				if err != nil {
					return err
				}
				certPath = filepath.Join(dir, "ca.pem")
			}
			return certgen.InstallCA(cmd.OutOrStdout(), filepath.Clean(certPath))
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "Path to CA certificate (default ~/.pipelock/ca.pem)")
	return cmd
}

func tlsShowCACmd() *cobra.Command {
	var certPath string
	cmd := &cobra.Command{
		Use:   "show-ca",
		Short: "Print the Pipelock CA certificate PEM to stdout",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if certPath == "" {
				dir, err := signing.DefaultKeystorePath()
				if err != nil {
					return err
				}
				certPath = filepath.Join(dir, "ca.pem")
			}
			data, err := os.ReadFile(filepath.Clean(certPath))
			if err != nil {
				return fmt.Errorf("read CA cert: %w", err)
			}
			_, _ = fmt.Fprint(cmd.OutOrStdout(), string(data))
			return nil
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "Path to CA certificate (default ~/.pipelock/ca.pem)")
	return cmd
}
