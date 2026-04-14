// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// sidecarOptions holds all flags for the sidecar subcommand.
type sidecarOptions struct {
	injectSpec    string
	emit          string
	output        string
	dryRun        bool
	force         bool
	image         string
	preset        string
	skipCanary    bool
	skipVerify    bool
	jsonOutput    bool
	agentIdentity string
}

// sidecarResult holds the outcome of each phase for JSON reporting.
type sidecarResult struct {
	Detect *sidecarDetectResult `json:"detect"`
	Patch  *sidecarPatchSummary `json:"patch"`
	Verify *sidecarVerifyResult `json:"verify,omitempty"`
	Canary *sidecarCanaryResult `json:"canary,omitempty"`
}

type sidecarDetectResult struct {
	Kind           string `json:"kind"`
	Name           string `json:"name"`
	AlreadyPatched bool   `json:"already_patched"`
}

type sidecarPatchSummary struct {
	EmitFormat    string `json:"emit_format"`
	OutputPath    string `json:"output_path,omitempty"`
	AgentIdentity string `json:"agent_identity"`
	Written       bool   `json:"written"`
	DryRun        bool   `json:"dry_run"`
}

// SidecarCmd returns the "pipelock init sidecar" subcommand.
func SidecarCmd() *cobra.Command {
	var opts sidecarOptions

	cmd := &cobra.Command{
		Use:   "sidecar",
		Short: "Generate an enforced pipelock companion proxy for a Kubernetes workload",
		Long: `Generate an enforced companion-proxy topology for Kubernetes workloads.

Supported workload kinds: Deployment, StatefulSet, Job, CronJob.

Phases:
  1. Detect:   parse the input manifest, identify workload kind
  2. Generate: patch the agent workload and build companion proxy resources
  3. Preview:  show the workload diff plus generated companion resources
  4. Apply:    write the enforced topology bundle
  5. Verify:   statically verify proxy config and network policy boundaries
  6. Canary:   inject a synthetic secret and confirm DLP catches it
  7. Summary:  show results

Examples:
  pipelock init sidecar --inject-spec deployment.yaml --dry-run
  pipelock init sidecar --inject-spec deployment.yaml --emit kustomize --output ./pipelock-overlay
  pipelock init sidecar --inject-spec statefulset.yaml --emit helm-values --output ./pipelock-helm-bundle
  pipelock init sidecar --inject-spec cronjob.yaml --preset strict --agent-identity my-team/bot`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSidecar(cmd, opts)
		},
	}

	cmd.Flags().StringVar(&opts.injectSpec, "inject-spec", "", "path to the Kubernetes workload manifest (required)")
	cmd.Flags().StringVar(&opts.emit, "emit", emitPatch, "output format: patch, kustomize, helm-values")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "output path (default: stdout)")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "show diff without writing files or running canary")
	cmd.Flags().BoolVar(&opts.force, "force", false, "overwrite existing output files")
	cmd.Flags().StringVar(&opts.image, "image", "", "companion proxy image (default: ghcr.io/luckypipewrench/pipelock:<version>)")
	cmd.Flags().StringVar(&opts.preset, "preset", config.ModeBalanced, "config preset: strict, balanced, audit")
	cmd.Flags().BoolVar(&opts.skipCanary, "skip-canary", false, "skip the canary detection test")
	cmd.Flags().BoolVar(&opts.skipVerify, "skip-verify", false, "skip static topology verification")
	cmd.Flags().BoolVar(&opts.jsonOutput, "json", false, "machine-readable JSON output")
	cmd.Flags().StringVar(&opts.agentIdentity, "agent-identity", "", "default agent identity (default: <kind>/<name>)")

	_ = cmd.MarkFlagRequired("inject-spec")

	return cmd
}

func runSidecar(cmd *cobra.Command, opts sidecarOptions) error {
	w := cmd.OutOrStdout()

	// Validate preset.
	switch opts.preset {
	case config.ModeStrict, config.ModeBalanced, config.ModeAudit:
		// valid
	default:
		return cliutil.ExitCodeError(initExitError,
			fmt.Errorf("unknown preset %q: choose strict, balanced, or audit", opts.preset))
	}

	// Validate emit format.
	switch opts.emit {
	case emitPatch, emitKustomize, emitHelmValues:
		// valid
	default:
		return cliutil.ExitCodeError(initExitError,
			fmt.Errorf("unknown emit format %q: choose patch, kustomize, or helm-values", opts.emit))
	}

	result := &sidecarResult{}

	// Phase 1: Detect
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "Pipelock Sidecar Init")
		_, _ = fmt.Fprintln(w, "=====================")
		_, _ = fmt.Fprintln(w)
		_, _ = fmt.Fprintln(w, "[1/7] Detecting workload type...")
	}

	manifest, err := detectWorkload(opts.injectSpec)
	if err != nil {
		return cliutil.ExitCodeError(initExitError, err)
	}

	alreadyPatched := hasPipelockTopology(manifest.Raw)

	result.Detect = &sidecarDetectResult{
		Kind:           manifest.Kind,
		Name:           manifest.Name,
		AlreadyPatched: alreadyPatched,
	}

	if !opts.jsonOutput {
		_, _ = fmt.Fprintf(w, "  Kind: %s\n", manifest.Kind)
		_, _ = fmt.Fprintf(w, "  Name: %s\n", manifest.Name)
		if alreadyPatched {
			_, _ = fmt.Fprintln(w, "  Status: already patched (companion proxy annotations found)")
		}
		_, _ = fmt.Fprintln(w)
	}

	// Phase 2: Generate
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[2/7] Generating companion proxy topology...")
	}

	patchResult, err := generateSidecarPatch(manifest, opts)
	if err != nil {
		return cliutil.ExitCodeError(initExitError, err)
	}

	if !opts.jsonOutput {
		_, _ = fmt.Fprintf(w, "  Agent identity: %s\n", patchResult.AgentIdentity)
		_, _ = fmt.Fprintf(w, "  Proxy name: %s\n", patchResult.ProxyName)
		_, _ = fmt.Fprintf(w, "  Proxy URL: %s\n", patchResult.ProxyURL)
		_, _ = fmt.Fprintf(w, "  Image: %s\n", resolveImage(opts))
		_, _ = fmt.Fprintf(w, "  Preset: %s\n\n", opts.preset)
	}

	// Phase 3: Preview
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[3/7] Diff preview:")
		if alreadyPatched {
			_, _ = fmt.Fprintln(w, "  No changes (manifest already patched).")
		} else {
			diff, err := renderDiff(manifest, patchResult)
			if err != nil {
				_, _ = fmt.Fprintf(w, "  (diff generation failed: %v)\n", err)
			} else {
				_, _ = fmt.Fprintln(w, diff)
			}
		}
		_, _ = fmt.Fprintln(w)
	}

	// Phase 4: Apply or Emit
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[4/7] Emitting output...")
	}

	patchSummary := &sidecarPatchSummary{
		EmitFormat:    opts.emit,
		OutputPath:    opts.output,
		AgentIdentity: patchResult.AgentIdentity,
		DryRun:        opts.dryRun,
	}

	if opts.dryRun {
		patchSummary.Written = false
		if !opts.jsonOutput {
			_, _ = fmt.Fprintf(w, "  Dry run: would emit %s format\n\n", opts.emit)
		}
	} else if alreadyPatched {
		patchSummary.Written = false
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "  Skipped: manifest already patched.")
		}
	} else {
		if opts.jsonOutput && opts.output == "" {
			return cliutil.ExitCodeError(initExitError,
				fmt.Errorf("--json requires --output when emitting %s content", opts.emit))
		}
		if err := emitPatched(w, patchResult, opts); err != nil {
			return cliutil.ExitCodeError(initExitError, fmt.Errorf("emit: %w", err))
		}
		patchSummary.Written = true
		if !opts.jsonOutput {
			if opts.output != "" {
				_, _ = fmt.Fprintf(w, "  Written to: %s\n\n", opts.output)
			} else {
				// Output was written to stdout in emitPatched.
				_, _ = fmt.Fprintln(w)
			}
		}
	}
	result.Patch = patchSummary

	// Phase 5: Verify (skipped in dry-run)
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[5/7] Verifying enforced topology...")
	}
	if opts.dryRun {
		result.Verify = &sidecarVerifyResult{Skipped: true, Detail: "skipped (--dry-run)"}
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "  Skipped (--dry-run)")
		}
	} else {
		result.Verify = runSidecarVerify(w, patchResult, opts, opts.jsonOutput)
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w)
		}
	}

	// Phase 6: Canary (skipped in dry-run)
	if !opts.jsonOutput {
		_, _ = fmt.Fprintln(w, "[6/7] Testing canary detection...")
	}
	if opts.dryRun {
		result.Canary = &sidecarCanaryResult{Skipped: true, Detail: "skipped (--dry-run)"}
		if !opts.jsonOutput {
			_, _ = fmt.Fprintln(w, "  Skipped (--dry-run)")
		}
	} else {
		result.Canary = runSidecarCanary(w, patchResult.Config, opts, opts.jsonOutput)
		if !opts.jsonOutput {
			if result.Canary.Detected {
				_, _ = fmt.Fprintln(w, "  Canary secret detected in URL scan. DLP is working.")
			}
			_, _ = fmt.Fprintln(w)
		}
	}

	if result.Verify != nil && !result.Verify.Skipped && !result.Verify.Healthy {
		return &cliutil.ExitError{Err: errors.New(result.Verify.Detail), Code: initExitFailure}
	}
	if result.Canary != nil && !result.Canary.Skipped && !result.Canary.Detected {
		return &cliutil.ExitError{Err: fmt.Errorf("canary secret was not detected by DLP"), Code: initExitFailure}
	}

	// Phase 7: Summary
	if opts.jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	printSidecarSummary(w, result, opts)
	return nil
}

// renderDiff produces a simple before/after comparison.
func renderDiff(manifest *workloadManifest, patchResult *sidecarPatchResult) (string, error) {
	patched, err := yaml.Marshal(patchResult.PatchedManifest)
	if err != nil {
		return "", err
	}

	original := string(manifest.RawBytes)
	patchedStr := string(patched)

	// Simple line-by-line diff indicator (not a full unified diff).
	origLines := strings.Split(original, "\n")
	patchLines := strings.Split(patchedStr, "\n")

	var sb strings.Builder

	// Show additions (lines in patched but not in original).
	origSet := make(map[string]bool, len(origLines))
	for _, l := range origLines {
		origSet[strings.TrimSpace(l)] = true
	}

	for _, l := range patchLines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" {
			continue
		}
		if !origSet[trimmed] {
			_, _ = fmt.Fprintf(&sb, "  + %s\n", l)
		}
	}

	if patchResult.ProxyName != "" {
		_, _ = fmt.Fprintf(&sb, "  + companion Deployment: %s\n", patchResult.ProxyName)
		_, _ = fmt.Fprintf(&sb, "  + companion Service: %s\n", patchResult.ProxyName)
		_, _ = fmt.Fprintln(&sb, "  + agent NetworkPolicy: DNS + proxy-only egress")
		_, _ = fmt.Fprintln(&sb, "  + proxy NetworkPolicy: agent ingress + web-only egress")
		_, _ = fmt.Fprintln(&sb, "  + companion PodDisruptionBudget: minAvailable=1")
	}

	if sb.Len() == 0 {
		return "  (no changes)", nil
	}
	return sb.String(), nil
}

func printSidecarSummary(w io.Writer, result *sidecarResult, opts sidecarOptions) {
	_, _ = fmt.Fprintln(w, "[7/7] Summary")
	_, _ = fmt.Fprintln(w, "=============")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintf(w, "  Workload:        %s/%s\n", result.Detect.Kind, result.Detect.Name)
	_, _ = fmt.Fprintf(w, "  Agent identity:  %s\n", result.Patch.AgentIdentity)
	_, _ = fmt.Fprintf(w, "  Emit format:     %s\n", result.Patch.EmitFormat)

	if result.Patch.DryRun {
		_, _ = fmt.Fprintln(w, "  Mode:            dry-run")
	} else if result.Patch.Written {
		if result.Patch.OutputPath != "" {
			_, _ = fmt.Fprintf(w, "  Output:          %s\n", result.Patch.OutputPath)
		} else {
			_, _ = fmt.Fprintln(w, "  Output:          stdout")
		}
	} else if result.Detect.AlreadyPatched {
		_, _ = fmt.Fprintln(w, "  Status:          already patched (no changes)")
	}

	if result.Verify != nil {
		if result.Verify.Skipped {
			_, _ = fmt.Fprintln(w, "  Verify:          skipped")
		} else if result.Verify.Healthy {
			_, _ = fmt.Fprintln(w, "  Verify:          healthy")
		} else {
			_, _ = fmt.Fprintf(w, "  Verify:          %s\n", result.Verify.Detail)
		}
	}

	if result.Canary != nil {
		if result.Canary.Skipped {
			_, _ = fmt.Fprintln(w, "  Canary:          skipped")
		} else if result.Canary.Detected {
			_, _ = fmt.Fprintln(w, "  Canary:          detected (DLP working)")
		} else {
			_, _ = fmt.Fprintln(w, "  Canary:          not detected (check config)")
		}
	}

	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Next steps:")
	if !result.Patch.Written && !result.Detect.AlreadyPatched {
		_, _ = fmt.Fprintf(w, "  pipelock init sidecar --inject-spec %s\n", opts.injectSpec)
	}
	switch result.Patch.EmitFormat {
	case emitKustomize:
		if result.Patch.OutputPath != "" {
			_, _ = fmt.Fprintf(w, "  kubectl apply -k %s\n", result.Patch.OutputPath)
		} else {
			_, _ = fmt.Fprintln(w, "  kubectl apply -k <overlay-dir>")
		}
	case emitHelmValues:
		if result.Patch.OutputPath != "" {
			_, _ = fmt.Fprintf(w, "  helm upgrade --install <release-name> pipelock/pipelock -f %s/values.yaml\n", result.Patch.OutputPath)
			_, _ = fmt.Fprintln(w, "  kubectl rollout status deployment/<release-name>")
			_, _ = fmt.Fprintf(w, "  kubectl apply -f %s/pipelock-networkpolicy.yaml -f %s/pipelock-pdb.yaml\n", result.Patch.OutputPath, result.Patch.OutputPath)
			_, _ = fmt.Fprintf(w, "  kubectl apply -f %s/agent-networkpolicy.yaml\n", result.Patch.OutputPath)
			_, _ = fmt.Fprintf(w, "  kubectl apply -f %s/agent-workload.yaml\n", result.Patch.OutputPath)
		} else {
			_, _ = fmt.Fprintln(w, "  helm upgrade --install <release-name> pipelock/pipelock -f <bundle-dir>/values.yaml")
		}
	default:
		_, _ = fmt.Fprintln(w, "  kubectl apply -f <patched-manifest>")
	}
	_, _ = fmt.Fprintln(w, "  kubectl get networkpolicy")
	_, _ = fmt.Fprintln(w, "  kubectl port-forward deploy/<proxy-name> 8888:8888")
	_, _ = fmt.Fprintln(w)
}
