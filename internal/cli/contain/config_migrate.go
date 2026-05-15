// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/signing"
	"gopkg.in/yaml.v3"
)

type migratedConfigArtifact struct {
	path string
	dir  bool
}

type configMigrationContext struct {
	env          *installEnv
	configDir    string
	operatorHome string
	artifacts    []migratedConfigArtifact
}

func migratePipelockConfigForContain(env *installEnv, configSource string, data []byte) ([]byte, []migratedConfigArtifact, error) {
	root, err := parseSingleYAMLDocument(data)
	if err != nil {
		return nil, nil, err
	}
	mapping := documentMapping(root)
	if mapping == nil {
		return nil, nil, errors.New("pipelock config must be a YAML mapping")
	}

	ctx := &configMigrationContext{
		env:       env,
		configDir: filepath.Dir(configSource),
	}
	home, err := operatorHomeDir(env)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve operator home for config migration: %w", err)
	}
	ctx.operatorHome = home

	if err := migrateScalarFile(ctx, mapping, []string{"license_file"}, filepath.Join(env.configDir, "license.token"), modeConfigSecret); err != nil {
		return nil, nil, err
	}
	if err := migrateFlightRecorderSigningKey(ctx, mapping); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarFile(ctx, mapping, []string{"mediation_envelope", "signing_key_path"}, filepath.Join(env.configDir, "keys", "mediation-envelope-signing.key"), modePinSecret); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarFile(ctx, mapping, []string{"mcp_binary_integrity", "manifest_path"}, filepath.Join(env.configDir, "integrity", "manifest.json"), modeConfigSecret); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarFile(ctx, mapping, []string{"learn_lock", "roster_path"}, filepath.Join(env.configDir, "roster.json"), modeConfigSecret); err != nil {
		return nil, nil, err
	}
	if err := migrateSaltSource(ctx, mapping); err != nil {
		return nil, nil, err
	}
	if err := migrateTLSCA(ctx, mapping); err != nil {
		return nil, nil, err
	}

	if err := migrateScalarDir(ctx, mapping, []string{"rules", "rules_dir"}, filepath.Join(env.dataDir, "rules")); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarDir(ctx, mapping, []string{"flight_recorder", "dir"}, filepath.Join(env.dataDir, "recorder")); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarDir(ctx, mapping, []string{"learn", "capture_dir"}, filepath.Join(env.dataDir, "captures", "local")); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarDir(ctx, mapping, []string{"behavioral_baseline", "profile_dir"}, filepath.Join(env.dataDir, "baselines")); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarDir(ctx, mapping, []string{"learn_lock", "store_dir"}, filepath.Join(env.dataDir, "contracts", "active")); err != nil {
		return nil, nil, err
	}
	if err := migrateScalarDir(ctx, mapping, []string{"mcp_tool_policy", "quarantine_dir"}, filepath.Join(env.dataDir, "quarantine")); err != nil {
		return nil, nil, err
	}
	if err := migrateLoggingFile(ctx, mapping); err != nil {
		return nil, nil, err
	}
	migrateRedirectProfiles(ctx, mapping)

	out, err := encodeYAML(root)
	if err != nil {
		return nil, nil, err
	}
	return out, ctx.artifacts, nil
}

func parseSingleYAMLDocument(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse pipelock config: %w", err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return nil, errors.New("pipelock config must be a single YAML document")
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse pipelock config: %w", err)
	}
	return &root, nil
}

func encodeYAML(root *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		_ = enc.Close()
		return nil, fmt.Errorf("encode migrated pipelock config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("close migrated pipelock config encoder: %w", err)
	}
	return buf.Bytes(), nil
}

func documentMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil
	}
	return root
}

func operatorHomeDir(env *installEnv) (string, error) {
	if env.operatorUser == "" {
		return "", errors.New("operator user not set")
	}
	u, err := env.lookupUser(env.operatorUser)
	if err != nil {
		return "", err
	}
	return filepath.Clean(u.HomeDir), nil
}

func migrateScalarFile(ctx *configMigrationContext, root *yaml.Node, path []string, dest string, mode os.FileMode) error {
	n := getMappingPath(root, path)
	if n == nil || n.Kind != yaml.ScalarNode || strings.TrimSpace(n.Value) == "" {
		return nil
	}
	src, ok := ctx.resolveMigratablePath(n.Value)
	if !ok {
		return nil
	}
	if err := copyConfigFile(ctx, src, dest, mode); err != nil {
		return fmt.Errorf("migrate %s: %w", strings.Join(path, "."), err)
	}
	n.Value = dest
	return nil
}

func migrateFlightRecorderSigningKey(ctx *configMigrationContext, root *yaml.Node) error {
	const field = "flight_recorder.signing_key_path"

	n := getMappingPath(root, []string{"flight_recorder", "signing_key_path"})
	if n == nil || n.Kind != yaml.ScalarNode || strings.TrimSpace(n.Value) == "" {
		return nil
	}
	src, ok := ctx.resolveMigratablePath(n.Value)
	if !ok {
		return nil
	}
	dest := filepath.Join(ctx.env.configDir, "keys", "flight-recorder-signing.key")
	if err := copyConfigFile(ctx, src, dest, modePinSecret); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("migrate %s: %w", field, err)
		}
		if err := ensureFlightRecorderSigningKey(ctx, dest); err != nil {
			return fmt.Errorf("migrate %s: %w", field, err)
		}
	} else if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
		return fmt.Errorf("migrate %s: validate migrated signing key %s: %w", field, dest, err)
	}
	n.Value = dest
	return nil
}

func ensureFlightRecorderSigningKey(ctx *configMigrationContext, dest string) error {
	if info, err := ctx.env.lstat(dest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("existing target %s is a symlink; refusing to use as signing key", dest)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("existing target %s is not a regular file", dest)
		}
		if err := ctx.env.chmod(dest, modePinSecret); err != nil {
			return fmt.Errorf("chmod %s: %w", dest, err)
		}
		if _, err := signing.LoadPrivateKeyFile(dest); err != nil {
			return fmt.Errorf("validate existing signing key %s: %w", dest, err)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat existing target %s: %w", dest, err)
	}

	if err := ensureMigratedDir(ctx, filepath.Dir(dest), migrationDirMode(ctx.env, filepath.Dir(dest))); err != nil {
		return err
	}
	_, priv, err := signing.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	if wrote, err := backupAndWriteIfChanged(ctx.env, dest, []byte(signing.EncodePrivateKey(priv)), modePinSecret); err != nil {
		return err
	} else if wrote {
		ctx.artifacts = append(ctx.artifacts, migratedConfigArtifact{path: dest})
	}
	return nil
}

func migrateScalarDir(ctx *configMigrationContext, root *yaml.Node, path []string, dest string) error {
	n := getMappingPath(root, path)
	if n == nil || n.Kind != yaml.ScalarNode || strings.TrimSpace(n.Value) == "" {
		return nil
	}
	src, ok := ctx.resolveMigratablePath(n.Value)
	if !ok {
		return nil
	}
	if err := copyConfigDir(ctx, src, dest); err != nil {
		return fmt.Errorf("migrate %s: %w", strings.Join(path, "."), err)
	}
	n.Value = dest
	return nil
}

func migrateSaltSource(ctx *configMigrationContext, root *yaml.Node) error {
	n := getMappingPath(root, []string{"learn", "privacy", "salt_source"})
	if n == nil || n.Kind != yaml.ScalarNode {
		return nil
	}
	value := strings.TrimSpace(n.Value)
	if !strings.HasPrefix(value, "file:") {
		return nil
	}
	src, ok := ctx.resolveMigratablePath(strings.TrimPrefix(value, "file:"))
	if !ok {
		return nil
	}
	dest := filepath.Join(ctx.env.configDir, "learn-privacy-salt")
	if err := copyConfigFile(ctx, src, dest, modePinSecret); err != nil {
		return fmt.Errorf("migrate learn.privacy.salt_source: %w", err)
	}
	n.Value = "file:" + dest
	return nil
}

func migrateTLSCA(ctx *configMigrationContext, root *yaml.Node) error {
	tlsNode := getMappingPath(root, []string{"tls_interception"})
	if tlsNode == nil || tlsNode.Kind != yaml.MappingNode {
		return nil
	}
	certNode := getMappingPath(tlsNode, []string{"ca_cert"})
	keyNode := getMappingPath(tlsNode, []string{"ca_key"})

	certValue := scalarValue(certNode)
	keyValue := scalarValue(keyNode)
	if certValue == "" && keyValue == "" && !yamlBool(getMappingPath(tlsNode, []string{"enabled"})) {
		return nil
	}
	if certValue == "" {
		certValue = filepath.Join(ctx.operatorHome, ".pipelock", "ca.pem")
		certNode = setMappingScalar(tlsNode, "ca_cert", certValue)
	}
	if keyValue == "" {
		keyValue = filepath.Join(ctx.operatorHome, ".pipelock", "ca-key.pem")
		keyNode = setMappingScalar(tlsNode, "ca_key", keyValue)
	}
	if err := migrateScalarFileValue(ctx, certNode, certValue, filepath.Join(ctx.env.configDir, "tls", "ca.pem"), modeConfigSecret); err != nil {
		return fmt.Errorf("migrate tls_interception.ca_cert: %w", err)
	}
	if err := migrateScalarFileValue(ctx, keyNode, keyValue, filepath.Join(ctx.env.configDir, "tls", "ca-key.pem"), modePinSecret); err != nil {
		return fmt.Errorf("migrate tls_interception.ca_key: %w", err)
	}
	return nil
}

func migrateScalarFileValue(ctx *configMigrationContext, n *yaml.Node, value, dest string, mode os.FileMode) error {
	src, ok := ctx.resolveMigratablePath(value)
	if !ok {
		return nil
	}
	if err := copyConfigFile(ctx, src, dest, mode); err != nil {
		return err
	}
	n.Value = dest
	return nil
}

func migrateLoggingFile(ctx *configMigrationContext, root *yaml.Node) error {
	n := getMappingPath(root, []string{"logging", "file"})
	if n == nil || n.Kind != yaml.ScalarNode || strings.TrimSpace(n.Value) == "" {
		return nil
	}
	_, ok := ctx.resolveMigratablePath(n.Value)
	if !ok {
		return nil
	}
	dest := filepath.Join(ctx.env.dataDir, "logs", "audit.log")
	if err := ensureMigratedDir(ctx, filepath.Dir(dest), migrationDirMode(ctx.env, filepath.Dir(dest))); err != nil {
		return err
	}
	n.Value = dest
	return nil
}

func migrateRedirectProfiles(ctx *configMigrationContext, root *yaml.Node) {
	profiles := getMappingPath(root, []string{"mcp_tool_policy", "redirect_profiles"})
	if profiles == nil || profiles.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(profiles.Content); i += 2 {
		profile := profiles.Content[i+1]
		execNode := getMappingPath(profile, []string{"exec"})
		if execNode == nil || execNode.Kind != yaml.SequenceNode || len(execNode.Content) == 0 {
			continue
		}
		first := execNode.Content[0]
		if first.Kind != yaml.ScalarNode {
			continue
		}
		src, ok := ctx.resolveMigratablePath(first.Value)
		if !ok {
			continue
		}
		if filepath.Base(src) == "pipelock" {
			first.Value = ctx.env.pipelockTarget
		}
	}
}

func (ctx *configMigrationContext) resolveMigratablePath(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" {
		return "", false
	}
	if strings.HasPrefix(raw, "~") {
		if ctx.operatorHome == "" {
			return "", false
		}
		switch {
		case raw == "~":
			raw = ctx.operatorHome
		case strings.HasPrefix(raw, "~/"):
			raw = filepath.Join(ctx.operatorHome, strings.TrimPrefix(raw, "~/"))
		default:
			return "", false
		}
	}
	if !filepath.IsAbs(raw) {
		raw = filepath.Join(ctx.configDir, raw)
	}
	clean := filepath.Clean(raw)
	if ctx.operatorHome == "" {
		return clean, false
	}
	rel, err := filepath.Rel(ctx.operatorHome, clean)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return clean, false
	}
	return clean, true
}

func copyConfigFile(ctx *configMigrationContext, src, dest string, mode os.FileMode) error {
	if err := rejectSymlinkComponents(ctx, src); err != nil {
		return err
	}
	info, err := ctx.env.lstat(src)
	if err != nil {
		return fmt.Errorf("stat source %s: %w", src, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source %s is a symlink; refusing to copy as root", src)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("source %s is not a regular file", src)
	}
	data, err := readRegularFileNoFollow(src)
	if err != nil {
		return fmt.Errorf("read source %s: %w", src, err)
	}
	after, err := ctx.env.lstat(src)
	if err != nil {
		return fmt.Errorf("stat source %s after read: %w", src, err)
	}
	if !os.SameFile(info, after) || !after.Mode().IsRegular() {
		return fmt.Errorf("source %s changed during migration; retry after quiescing config writes", src)
	}
	if err := ensureMigratedDir(ctx, filepath.Dir(dest), migrationDirMode(ctx.env, filepath.Dir(dest))); err != nil {
		return err
	}
	if wrote, err := backupAndWriteIfChanged(ctx.env, dest, data, mode); err != nil {
		return err
	} else if wrote {
		ctx.artifacts = append(ctx.artifacts, migratedConfigArtifact{path: dest})
	}
	return nil
}

func copyConfigDir(ctx *configMigrationContext, src, dest string) error {
	info, err := ctx.env.lstat(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ensureMigratedDir(ctx, dest, migrationDirMode(ctx.env, dest))
		}
		return fmt.Errorf("stat source %s: %w", src, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source %s is a symlink; refusing to copy as root", src)
	}
	if !info.IsDir() {
		return fmt.Errorf("source %s is not a directory", src)
	}
	if err := rejectSymlinkComponents(ctx, src); err != nil {
		return err
	}
	if err := ensureMigratedDir(ctx, dest, migrationDirMode(ctx.env, dest)); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if rel == "." {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source %s is a symlink; refusing to copy as root", path)
		}
		if d.IsDir() {
			return ensureMigratedDir(ctx, target, migrationDirMode(ctx.env, target))
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		data, err := readRegularFileNoFollow(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		after, err := ctx.env.lstat(path)
		if err != nil {
			return fmt.Errorf("stat source %s after read: %w", path, err)
		}
		if !os.SameFile(info, after) || !after.Mode().IsRegular() {
			return fmt.Errorf("source %s changed during migration; retry after quiescing config writes", path)
		}
		if wrote, err := backupAndWriteIfChanged(ctx.env, target, data, modeConfigSecret); err != nil {
			return err
		} else if wrote {
			ctx.artifacts = append(ctx.artifacts, migratedConfigArtifact{path: target})
		}
		return nil
	})
}

func cleanupMigratedConfigArtifacts(env *installEnv, artifacts []migratedConfigArtifact) error {
	var errs []error
	for i := len(artifacts) - 1; i >= 0; i-- {
		artifact := artifacts[i]
		var err error
		if artifact.dir {
			err = env.removeFile(artifact.path)
			if errors.Is(err, os.ErrNotExist) || isDirectoryNotEmpty(err) {
				err = nil
			}
		} else {
			err = restoreBackup(env, artifact.path)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func isDirectoryNotEmpty(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "directory not empty") || strings.Contains(msg, "not empty")
}

func backupAndWriteIfChanged(env *installEnv, path string, contents []byte, mode os.FileMode) (bool, error) {
	clean := filepath.Clean(path)
	if info, err := env.lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return false, fmt.Errorf("%s is a symlink; refusing privileged write", clean)
		}
		if info.IsDir() {
			return false, fmt.Errorf("%s is a directory", clean)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("stat existing %s: %w", clean, err)
	}
	if existing, err := env.readFile(clean); err == nil {
		if bytesEqual(existing, contents) {
			if err := env.chmod(clean, mode); err != nil {
				return false, fmt.Errorf("chmod %s: %w", clean, err)
			}
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read existing %s: %w", clean, err)
	}
	if err := backupAndWrite(env, clean, contents, mode); err != nil {
		return false, err
	}
	return true, nil
}

func ensureMigratedDir(ctx *configMigrationContext, path string, mode os.FileMode) error {
	if info, err := ctx.env.lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to create migrated directory", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
		return ctx.env.chmod(path, mode)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if err := rejectSymlinkParents(ctx.env, path); err != nil {
		return err
	}
	for _, dir := range missingDirs(ctx, path) {
		ctx.artifacts = append(ctx.artifacts, migratedConfigArtifact{path: dir, dir: true})
	}
	if err := ctx.env.mkdirAll(path, mode); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	if err := ctx.env.chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

func rejectSymlinkParents(env *installEnv, path string) error {
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	for parent != "." && parent != string(os.PathSeparator) {
		info, err := env.lstat(parent)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("path %s has symlink parent %s; refusing to create as root", clean, parent)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat parent %s: %w", parent, err)
		}
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	return nil
}

func migrationDirMode(env *installEnv, path string) os.FileMode {
	clean := filepath.Clean(path)
	switch clean {
	case filepath.Clean(env.configDir), filepath.Join(filepath.Clean(env.configDir), "contain"):
		return modeDirTraversable
	default:
		return modeDirPrivate
	}
}

func missingDirs(ctx *configMigrationContext, path string) []string {
	var base string
	switch {
	case pathWithin(ctx.env.configDir, path):
		base = ctx.env.configDir
	case pathWithin(ctx.env.dataDir, path):
		base = ctx.env.dataDir
	default:
		return nil
	}
	rel, err := filepath.Rel(base, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return nil
	}
	var out []string
	cur := base
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		if _, err := ctx.env.stat(cur); errors.Is(err, os.ErrNotExist) {
			out = append(out, cur)
		}
	}
	return out
}

func pathWithin(base, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func rejectSymlinkComponents(ctx *configMigrationContext, path string) error {
	if ctx.operatorHome == "" {
		return nil
	}
	rel, err := filepath.Rel(ctx.operatorHome, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil
	}
	cur := ctx.operatorHome
	if info, err := ctx.env.lstat(cur); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("source %s has symlink component %s; refusing to copy as root", path, cur)
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		cur = filepath.Join(cur, part)
		info, err := ctx.env.lstat(cur)
		if err != nil {
			return fmt.Errorf("stat source %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("source %s has symlink component %s; refusing to copy as root", path, cur)
		}
	}
	return nil
}

func getMappingPath(root *yaml.Node, path []string) *yaml.Node {
	cur := root
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return nil
		}
		cur = mappingValue(cur, key)
	}
	return cur
}

func mappingValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func setMappingScalar(m *yaml.Node, key, value string) *yaml.Node {
	if n := mappingValue(m, key); n != nil {
		n.Kind = yaml.ScalarNode
		n.Tag = "!!str"
		n.Value = value
		return n
	}
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, n)
	return n
}

func scalarValue(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return strings.TrimSpace(n.Value)
}

func yamlBool(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(n.Value), "true")
}
