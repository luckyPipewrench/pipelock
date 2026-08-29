// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package capabilitymanifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli"
)

func TestManifestParity(t *testing.T) {
	root := repositoryRoot(t)
	manifestPath := filepath.Join(root, "docs/security/capability-manifest.json")
	manifest, err := Load(manifestPath)
	if err != nil {
		t.Fatalf("Load(%q): %v", manifestPath, err)
	}

	for _, capability := range manifest.Capabilities {
		t.Run(capability.ID, func(t *testing.T) {
			implementation := declaration(t, root, capability.Implementation)
			entryPoint := *capability.OperatorEntryPoint
			switch entryPoint.Kind {
			case "command":
				assertCommandEntryPoint(t, root, entryPoint)
			case "config":
				assertConfigEntryPoint(t, root, entryPoint)
			default:
				t.Fatalf("unsupported operator entry point kind %q", entryPoint.Kind)
			}

			switch capability.Gate.Kind {
			case GateFree:
				assertNoLicenseGate(t, implementation)
			case GateLicense:
				for _, feature := range capability.Gate.Features {
					enforcement := declaration(t, root, feature.Enforcement.Source)
					assertSelector(t, enforcement, feature.Enforcement.Call)
					proof := declaration(t, root, feature.Proof)
					assertFeatureConstant(t, proof, feature.Name)
				}
			default:
				t.Fatalf("unsupported gate kind %q", capability.Gate.Kind)
			}
		})
	}

	agentsPath := filepath.Join(root, "AGENTS.md")
	agents, err := os.ReadFile(filepath.Clean(agentsPath))
	if err != nil {
		t.Fatalf("read %q: %v", agentsPath, err)
	}
	updated, err := ReplaceAgentsSection(string(agents), RenderAgentsSection(manifest))
	if err != nil {
		t.Fatalf("ReplaceAgentsSection(%q): %v", agentsPath, err)
	}
	if updated != string(agents) {
		t.Fatalf("AGENTS.md capability section is stale; run go generate ./internal/capabilitymanifest")
	}
}

func TestManifestCoversDirectRuntimeLicenseGates(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := Load(filepath.Join(root, "docs/security/capability-manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}

	usedCoverage := make([]bool, len(manifest.GateCoverage))
	usedExclusions := make([]bool, len(manifest.GateExclusions))
	var unknown []string
	for _, sourceRoot := range []string{"internal", "enterprise"} {
		err := filepath.WalkDir(filepath.Join(root, sourceRoot), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			fileSet := token.NewFileSet()
			file, err := parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				return fmt.Errorf("parse %s: %w", relative, err)
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				feature := directLicenseGateFeature(call)
				if feature == "" {
					return true
				}
				for i, scope := range manifest.GateCoverage {
					if scope.Feature == feature && strings.HasPrefix(relative, scope.Prefix) {
						usedCoverage[i] = true
						return true
					}
				}
				for i, scope := range manifest.GateExclusions {
					if scope.Feature == feature && strings.HasPrefix(relative, scope.Prefix) {
						usedExclusions[i] = true
						return true
					}
				}
				unknown = append(unknown, fmt.Sprintf("%s:%d (%s)", relative, fileSet.Position(call.Pos()).Line, feature))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sourceRoot, err)
		}
	}
	if len(unknown) > 0 {
		t.Fatalf("direct runtime license gates are not represented by the capability manifest: %s", strings.Join(unknown, ", "))
	}
	for i, used := range usedCoverage {
		if !used {
			t.Fatalf("gate_coverage scope %q for %q matches no direct runtime license gate", manifest.GateCoverage[i].Prefix, manifest.GateCoverage[i].Feature)
		}
	}
	for i, used := range usedExclusions {
		if !used {
			t.Fatalf("gate exclusion %q for %q matches no direct runtime license gate", manifest.GateExclusions[i].Prefix, manifest.GateExclusions[i].Feature)
		}
	}
}

func TestManifestCoversEnumeratedOperatorSurfaces(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := Load(filepath.Join(root, "docs/security/capability-manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}

	configSections := rootConfigSections(t, root)
	commands := make([]string, 0)
	for _, name := range cli.RegisteredTopLevelCommandNames() {
		commands = append(commands, "pipelock "+name)
	}

	assertSurfaceCoverage(t, manifest, SurfaceConfigSection, configSections)
	assertSurfaceCoverage(t, manifest, SurfaceCommand, commands)
}

func rootConfigSections(t *testing.T, root string) []string {
	t.Helper()
	config := declaration(t, root, SourceReference{File: "internal/config/schema.go", Symbol: "Config"})
	typeSpec, ok := config.(*ast.TypeSpec)
	if !ok {
		t.Fatal("Config declaration is not a type")
	}
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		t.Fatal("Config declaration is not a struct")
	}

	sections := make([]string, 0)
	for _, field := range structType.Fields.List {
		if field.Tag == nil || !isConfigSectionType(field.Type) {
			continue
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			t.Fatalf("unquote Config tag: %v", err)
		}
		yamlField := strings.Split(reflect.StructTag(tag).Get("yaml"), ",")[0]
		if yamlField != "" && yamlField != "-" {
			sections = append(sections, yamlField)
		}
	}
	sort.Strings(sections)
	return sections
}

func isConfigSectionType(expr ast.Expr) bool {
	switch value := expr.(type) {
	case *ast.Ident:
		switch value.Name {
		case "bool", "int", "int64", "string":
			return false
		default:
			return true
		}
	case *ast.SelectorExpr, *ast.MapType:
		return true
	case *ast.ArrayType:
		return isConfigSectionType(value.Elt)
	default:
		return false
	}
}

func assertSurfaceCoverage(t *testing.T, manifest Manifest, kind string, enumerated []string) {
	t.Helper()
	known := make(map[string]struct{}, len(enumerated))
	for _, value := range enumerated {
		known[value] = struct{}{}
	}

	covered := make(map[string]string)
	for _, capability := range manifest.Capabilities {
		entry := *capability.OperatorEntryPoint
		if entry.Kind == "config" && kind == SurfaceConfigSection {
			if _, ok := known[entry.Field]; ok {
				covered[entry.Field] = capability.ID
			}
		}
		if entry.Kind == "command" && kind == SurfaceCommand {
			if _, ok := known[entry.Value]; ok {
				covered[entry.Value] = capability.ID
			}
		}
		for _, surface := range capability.SurfaceCoverage {
			if surface.Kind != kind {
				continue
			}
			if _, ok := known[surface.Value]; !ok {
				// Enterprise-only root commands are absent from the default build.
				// The enterprise-tagged run enumerates the superset and rejects a
				// genuinely stale command coverage record.
				if kind == SurfaceCommand {
					continue
				}
				t.Errorf("capability %q maps stale %s %q", capability.ID, kind, surface.Value)
				continue
			}
			if owner, exists := covered[surface.Value]; exists && owner != capability.ID {
				t.Errorf("%s %q is mapped by both %q and %q", kind, surface.Value, owner, capability.ID)
				continue
			}
			covered[surface.Value] = capability.ID
		}
	}

	excluded := make(map[string]string)
	for _, exclusion := range manifest.SurfaceExclusions {
		if exclusion.Kind != kind {
			continue
		}
		if _, ok := known[exclusion.Value]; !ok {
			if kind == SurfaceCommand {
				continue
			}
			t.Errorf("surface exclusion %q names no enumerated %s", exclusion.Value, kind)
			continue
		}
		if owner, exists := covered[exclusion.Value]; exists {
			t.Errorf("%s %q is both mapped by %q and excluded", kind, exclusion.Value, owner)
			continue
		}
		if reason, exists := excluded[exclusion.Value]; exists {
			t.Errorf("%s %q is excluded twice (%q and %q)", kind, exclusion.Value, reason, exclusion.Reason)
			continue
		}
		excluded[exclusion.Value] = exclusion.Reason
	}

	for _, value := range enumerated {
		if _, ok := covered[value]; ok {
			continue
		}
		if _, ok := excluded[value]; ok {
			continue
		}
		t.Errorf("%s %q has no manifest capability or documented exclusion", kind, value)
	}
	if len(enumerated) > 0 && len(covered)*4 < len(enumerated) {
		t.Errorf("%s coverage is diluted: %d of %d surfaces map to capabilities; at least 25%% must be mapped rather than excluded", kind, len(covered), len(enumerated))
	}
}

func TestLoadRejectsUnknownFieldsAndTrailingDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	for _, content := range []string{
		"{\"schema_version\":1,\"capabilities\":[],\"unexpected\":true}",
		"{\"schema_version\":1,\"capabilities\":[]} {}",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write malformed manifest: %v", err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("Load(%q) succeeded for malformed manifest %q", path, content)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat repository root candidate %q: %v", dir, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}

func declaration(t *testing.T, root string, ref SourceReference) ast.Node {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(ref.File))
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, path, nil, 0)
	if err != nil {
		t.Fatalf("parse source %q for %s: %v", ref.File, ref.Symbol, err)
	}
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			if decl.Name.Name == ref.Symbol {
				return decl
			}
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if ok && typeSpec.Name.Name == ref.Symbol {
					return typeSpec
				}
			}
		}
	}
	t.Fatalf("source %q does not declare symbol %q", ref.File, ref.Symbol)
	return nil
}

func assertCommandEntryPoint(t *testing.T, root string, entry OperatorEntryPoint) {
	t.Helper()
	decl, ok := declaration(t, root, entry.Source).(*ast.FuncDecl)
	if !ok {
		t.Fatalf("command entry point %q source %s must be a function", entry.Value, entry.Source.Symbol)
	}
	want := lastCommandWord(entry.Value)
	var found bool
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		keyValue, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := keyValue.Key.(*ast.Ident)
		if !ok || key.Name != "Use" {
			return true
		}
		value, ok := keyValue.Value.(*ast.BasicLit)
		if !ok || value.Kind != token.STRING {
			return true
		}
		use, err := strconv.Unquote(value.Value)
		if err != nil {
			t.Fatalf("unquote Use value for %q: %v", entry.Value, err)
		}
		words := strings.Fields(use)
		if len(words) > 0 && words[0] == want {
			found = true
		}
		return true
	})
	if !found {
		t.Fatalf("command %q is not declared by %s:%s", entry.Value, entry.Source.File, entry.Source.Symbol)
	}
}

func assertConfigEntryPoint(t *testing.T, root string, entry OperatorEntryPoint) {
	t.Helper()
	typeSpec, ok := declaration(t, root, entry.Source).(*ast.TypeSpec)
	if !ok {
		t.Fatalf("config entry point %q source %s must be a type", entry.Value, entry.Source.Symbol)
	}
	structType, ok := typeSpec.Type.(*ast.StructType)
	if !ok {
		t.Fatalf("config entry point %q source %s is not a struct", entry.Value, entry.Source.Symbol)
	}
	for _, field := range structType.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			t.Fatalf("unquote struct tag for %q: %v", entry.Value, err)
		}
		yamlField := strings.Split(reflect.StructTag(tag).Get("yaml"), ",")[0]
		if yamlField == entry.Field {
			return
		}
	}
	t.Fatalf("config field %q for %q is not declared by %s:%s", entry.Field, entry.Value, entry.Source.File, entry.Source.Symbol)
}

func assertNoLicenseGate(t *testing.T, declaration ast.Node) {
	t.Helper()
	var found []string
	ast.Inspect(declaration, func(node ast.Node) bool {
		ident, ok := node.(*ast.Ident)
		if !ok {
			return true
		}
		switch ident.Name {
		case "FeatureAgents", "FeatureAssess", "FeatureFleet", "HasFeature", "VerifyAgents", "VerifyFleet", "VerifyAgentsWithOptions", "VerifyFleetWithOptions":
			found = append(found, ident.Name)
		}
		return true
	})
	if len(found) > 0 {
		t.Fatalf("free capability implementation declares license gate symbols: %s", strings.Join(found, ", "))
	}
}

func assertSelector(t *testing.T, declaration ast.Node, want string) {
	t.Helper()
	parts := strings.Split(want, ".")
	if len(parts) != 2 {
		t.Fatalf("invalid selector %q", want)
	}
	var found bool
	ast.Inspect(declaration, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		prefix, ok := selector.X.(*ast.Ident)
		if ok && prefix.Name == parts[0] && selector.Sel.Name == parts[1] {
			found = true
		}
		return true
	})
	if !found {
		t.Fatalf("declared gate call %q is absent", want)
	}
}

func assertFeatureConstant(t *testing.T, declaration ast.Node, feature string) {
	t.Helper()
	want := featureConstant(feature)
	var found bool
	ast.Inspect(declaration, func(node ast.Node) bool {
		ident, ok := node.(*ast.Ident)
		if ok && ident.Name == want {
			found = true
		}
		return true
	})
	if !found {
		t.Fatalf("proof declaration does not reference license.%s", want)
	}
}

func directLicenseGateFeature(call *ast.CallExpr) string {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	switch selector.Sel.Name {
	case "VerifyAgents", "VerifyAgentsWithOptions":
		return "agents"
	case "VerifyFleet", "VerifyFleetWithOptions":
		return "fleet"
	case "HasFeature":
		if len(call.Args) == 1 {
			return featureNameFromExpression(call.Args[0])
		}
	}
	return ""
}

func featureNameFromExpression(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		switch expression.Name {
		case "FeatureAgents":
			return "agents"
		case "FeatureAssess":
			return "assess"
		case "FeatureFleet":
			return "fleet"
		}
	case *ast.SelectorExpr:
		switch expression.Sel.Name {
		case "FeatureAgents":
			return "agents"
		case "FeatureAssess":
			return "assess"
		case "FeatureFleet":
			return "fleet"
		}
	}
	return ""
}

func lastCommandWord(command string) string {
	words := strings.Fields(command)
	if len(words) < 2 {
		panic(fmt.Sprintf("invalid manifest command %q", command))
	}
	return words[len(words)-1]
}

func TestLoadRejectsUnreadableManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := Load(path); err == nil {
		t.Fatal("Load succeeded for missing manifest")
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte("{\"schema_version\":"), 0o600); err != nil {
		t.Fatalf("write malformed manifest: %v", err)
	}
	if _, err := Load(path); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("Load(%q) error = %v, want malformed JSON error", path, err)
	}
}

func TestManifestJSONCanBeDecodedByExternalConsumers(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Clean(filepath.Join(root, "docs/security/capability-manifest.json"))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("external JSON decode: %v", err)
	}
	if document["schema_version"] != float64(SchemaVersion) {
		t.Fatalf("schema_version = %v, want %d", document["schema_version"], SchemaVersion)
	}
}

func TestREADMEFreeTierClaim(t *testing.T) {
	root := repositoryRoot(t)
	manifest, err := Load(filepath.Join(root, "docs/security/capability-manifest.json"))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	var coverageCertificate *Capability
	for i := range manifest.Capabilities {
		if manifest.Capabilities[i].ID == "coverage-certificates" {
			coverageCertificate = &manifest.Capabilities[i]
			break
		}
	}
	if coverageCertificate == nil {
		t.Fatal("coverage certificate capability is missing from the manifest")
	}
	if coverageCertificate.Tier != "Pro" {
		t.Fatalf("coverage certificate tier = %q, want Pro", coverageCertificate.Tier)
	}

	readmePath := filepath.Clean(filepath.Join(root, "README.md"))
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	const freeTierClaim = "All detection, enforcement, containment, receipt verification, and the free single-agent evidence viewer are free forever under Apache 2.0. Pro adds named-agent operations, including per-agent coverage certificates; Enterprise adds fleet governance and compliance."
	if !strings.Contains(string(readme), freeTierClaim) {
		t.Fatalf("README.md free-tier claim is stale or omits the Pro coverage-certificate limit")
	}

	keyGeneratePath := filepath.Clean(filepath.Join(root, "internal/cli/signing/key_generate.go"))
	keyGenerate, err := os.ReadFile(keyGeneratePath)
	if err != nil {
		t.Fatalf("read signing key generator help: %v", err)
	}
	const coverageCertTierClaim = "coverage-cert-signing          Coverage Certificate signing (verify is free; mint is Pro)"
	if !strings.Contains(string(keyGenerate), coverageCertTierClaim) {
		t.Fatalf("coverage certificate signing help is stale or disagrees with the Pro manifest tier")
	}
}
