// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package emit serializes compiled contracts into deterministic signed
// transport artifacts.
package emit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/contract"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

const (
	inferenceAlgorithmWilsonV1 = "wilson_lb_v1"
	ed25519Prefix              = "ed25519:"
	moduleDigestUnavailableKey = "build_info_unavailable"
)

var (
	// ErrNilSigner rejects EmitContract calls that cannot produce a detached
	// signature.
	ErrNilSigner = errors.New("emit: signer is nil")

	// ErrInvalidArtifact rejects a contract or manifest that fails its typed
	// validation before signing.
	ErrInvalidArtifact = errors.New("emit: invalid artifact")

	readBuildInfo = debug.ReadBuildInfo
)

// Signer is the narrow signing authority EmitContract needs. Tests can inject
// a deterministic fixture signer without depending on filesystem keystores.
type Signer interface {
	KeyID() string
	Sign(message []byte) ([]byte, error)
}

// EmitOptions controls deterministic metadata and manifest construction.
type EmitOptions struct {
	StartedAt         time.Time
	FinishedAt        time.Time
	CompileConfigHash string
	Inputs            []contract.InputRef
	Settings          map[string]any
}

// Result contains the serialized transport bytes plus the canonical preimages
// used by deterministic recompile tests.
type Result struct {
	YAML             []byte
	ManifestJSON     []byte
	ContractPreimage []byte
	ManifestPreimage []byte
	Contract         contract.Contract
	Manifest         contract.CompileManifest
}

// EmitContract validates, canonicalizes, signs, and serializes the compiled
// contract body and sibling compile manifest.
func EmitContract(c contract.Contract, signer Signer, opts EmitOptions) (Result, error) {
	if signer == nil {
		return Result{}, ErrNilSigner
	}
	c.SignerKeyID = signer.KeyID()
	c.KeyPurpose = signing.PurposeContractCompileSigning.String()
	var err error
	c.Compile, err = fillCompileProvenance(c.Compile, opts)
	if err != nil {
		return Result{}, err
	}
	c.ContractHash, err = hashContractWithEmptyHash(c)
	if err != nil {
		return Result{}, err
	}

	if err := c.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: contract: %w", ErrInvalidArtifact, err)
	}
	contractPreimage, err := c.SignablePreimage()
	if err != nil {
		return Result{}, fmt.Errorf("contract preimage: %w", err)
	}
	contractSig, err := signer.Sign(contractPreimage)
	if err != nil {
		return Result{}, fmt.Errorf("sign contract: %w", err)
	}

	manifest, err := buildManifest(c, signer.KeyID(), opts)
	if err != nil {
		return Result{}, err
	}
	if err := manifest.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: manifest: %w", ErrInvalidArtifact, err)
	}
	manifestPreimage, err := manifest.SignablePreimage()
	if err != nil {
		return Result{}, fmt.Errorf("manifest preimage: %w", err)
	}
	manifestSig, err := signer.Sign(manifestPreimage)
	if err != nil {
		return Result{}, fmt.Errorf("sign manifest: %w", err)
	}

	yamlBytes, err := marshalDeterministicYAML(contract.ContractEnvelope{
		Body:      c,
		Signature: signatureString(contractSig),
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal contract yaml: %w", err)
	}
	manifestBytes, err := marshalDeterministicJSON(contract.CompileManifestEnvelope{
		Body:      manifest,
		Signature: signatureString(manifestSig),
	})
	if err != nil {
		return Result{}, fmt.Errorf("marshal manifest json: %w", err)
	}

	return Result{
		YAML:             yamlBytes,
		ManifestJSON:     manifestBytes,
		ContractPreimage: contractPreimage,
		ManifestPreimage: manifestPreimage,
		Contract:         c,
		Manifest:         manifest,
	}, nil
}

func fillCompileProvenance(in contract.ContractCompile, opts EmitOptions) (contract.ContractCompile, error) {
	if in.PipelockVersion == "" {
		in.PipelockVersion = cliutil.Version
	}
	if in.PipelockBuildSHA == "" {
		in.PipelockBuildSHA = cliutil.GitCommit
	}
	if in.GoVersion == "" {
		in.GoVersion = runtime.Version()
	}
	if in.ModuleDigestRoot == "" {
		digests := moduleDigests()
		root, err := (contract.CompileManifest{ModuleDigests: digests}).ComputeModuleDigestRoot()
		if err != nil {
			return contract.ContractCompile{}, fmt.Errorf("compute module digest root: %w", err)
		}
		in.ModuleDigestRoot = root
	}
	if in.CompileConfigHash == "" {
		in.CompileConfigHash = opts.CompileConfigHash
	}
	if in.InferenceAlgorithm == "" {
		in.InferenceAlgorithm = inferenceAlgorithmWilsonV1
	}
	if in.NormalizationAlgorithm == "" {
		in.NormalizationAlgorithm = "frequency_weighted_entropy_v1"
	}
	return in, nil
}

func buildManifest(c contract.Contract, signerKeyID string, opts EmitOptions) (contract.CompileManifest, error) {
	digests := moduleDigests()
	root, err := (contract.CompileManifest{ModuleDigests: digests}).ComputeModuleDigestRoot()
	if err != nil {
		return contract.CompileManifest{}, fmt.Errorf("compute module digest root: %w", err)
	}
	started := opts.StartedAt.UTC()
	finished := opts.FinishedAt.UTC()
	if started.IsZero() {
		started = finished
	}
	if finished.IsZero() {
		finished = started
	}
	return contract.CompileManifest{
		SchemaVersion:         1,
		ContractHash:          c.ContractHash,
		CompileStartedAt:      started,
		CompileFinishedAt:     finished,
		PipelockVersion:       c.Compile.PipelockVersion,
		PipelockBuildSHA:      c.Compile.PipelockBuildSHA,
		GoVersion:             c.Compile.GoVersion,
		ModuleDigestRoot:      root,
		ModuleDigests:         digests,
		CompileConfigHash:     c.Compile.CompileConfigHash,
		Inputs:                append([]contract.InputRef(nil), opts.Inputs...),
		ObservationWindowRoot: c.ObservationWindow.ObservationWindowRoot,
		Settings:              cloneSettings(opts.Settings),
		SignerKeyID:           signerKeyID,
		KeyPurpose:            signing.PurposeContractCompileSigning.String(),
	}, nil
}

func hashContractWithEmptyHash(c contract.Contract) (string, error) {
	c.ContractHash = ""
	preimage, err := c.SignablePreimage()
	if err != nil {
		return "", fmt.Errorf("compute contract hash: %w", err)
	}
	sum := sha256.Sum256(preimage)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func signatureString(sig []byte) string {
	return ed25519Prefix + hex.EncodeToString(sig)
}

func moduleDigests() map[string]string {
	out := map[string]string{}
	if info, ok := readBuildInfo(); ok {
		out = moduleDigestsFromBuildInfo(info)
	}
	if len(out) == 0 {
		// Test binaries may not carry module dependency metadata. Use an
		// explicit marker rather than CWD-relative files so signed provenance
		// does not depend on the caller's working directory.
		out[moduleDigestUnavailableKey] = digestString("build-info unavailable")
	}
	return out
}

func moduleDigestsFromBuildInfo(info *debug.BuildInfo) map[string]string {
	out := map[string]string{}
	if info == nil {
		return out
	}
	if info.Main.Path != "" {
		out[info.Main.Path] = digestString(info.Main.Version)
	}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			out[dep.Path+"=>"+dep.Replace.Path] = digestString(dep.Replace.Version)
			continue
		}
		out[dep.Path] = digestString(dep.Version)
	}
	return out
}

func digestString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func cloneSettings(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = cloneSettingValue(v)
	}
	return out
}

func cloneSettingValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return cloneSettings(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = cloneSettingValue(item)
		}
		return out
	default:
		return v
	}
}

func marshalDeterministicJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func marshalDeterministicYAML(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return nil, err
	}
	node := yamlNode(tree)
	out, err := yaml.Marshal(node)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func yamlNode(v any) *yaml.Node {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		for _, k := range keys {
			n.Content = append(n.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
				yamlNode(x[k]),
			)
		}
		return n
	case []any:
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, item := range x {
			n.Content = append(n.Content, yamlNode(item))
		}
		return n
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: x}
	case bool:
		if x {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"}
	case json.Number:
		if bytes.ContainsAny([]byte(x.String()), ".eE") {
			return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!float", Value: x.String()}
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: x.String()}
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
	default:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(x)}
	}
}
