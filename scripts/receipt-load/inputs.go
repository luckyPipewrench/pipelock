// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// harnessContractVersion is bumped by hand whenever the measurement contract
// (what is measured, how it is timed, what integrity means) changes. The
// source hash below changes on any edit; this number names the contract.
const harnessContractVersion = "5"

//go:embed *.go
var harnessSource embed.FS

// harnessSourceSHA256 hashes the harness's own non-test source so a result can
// be tied to the exact code that produced it.
func harnessSourceSHA256() (string, error) {
	entries, err := harnessSource.ReadDir(".")
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		data, readErr := harnessSource.ReadFile(name)
		if readErr != nil {
			return "", readErr
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(data))
		_, _ = h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// passthroughEnv is the only part of the host environment the proxy child
// inherits: command lookup, the clock zone, Go scheduling, and proxy routing.
// Everything else, including every host secret, is dropped.
var passthroughEnv = []string{
	"PATH", "TZ", "GOMAXPROCS",
	"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
	"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy",
}

// runDirs are the fresh, empty directories one run points its child at. Every
// location Pipelock could consult for per-user state lives inside the run
// directory, so a host profile cannot leak in.
type runDirs struct {
	root          string
	home          string
	scanHome      string
	xdgConfig     string
	xdgData       string
	xdgCache      string
	xdgState      string
	xdgRuntime    string
	xdgConfigDirs string
	xdgDataDirs   string
	tmp           string
	cwd           string
	rules         string
	recorder      string
	keys          string
}

func newRunDirs(root string) runDirs {
	return runDirs{
		root:          root,
		home:          filepath.Join(root, "home"),
		scanHome:      filepath.Join(root, "scan-home"),
		xdgConfig:     filepath.Join(root, "xdg", "config"),
		xdgData:       filepath.Join(root, "xdg", "data"),
		xdgCache:      filepath.Join(root, "xdg", "cache"),
		xdgState:      filepath.Join(root, "xdg", "state"),
		xdgRuntime:    filepath.Join(root, "xdg", "runtime"),
		xdgConfigDirs: filepath.Join(root, "xdg", "config-dirs"),
		xdgDataDirs:   filepath.Join(root, "xdg", "data-dirs"),
		tmp:           filepath.Join(root, "tmp"),
		cwd:           filepath.Join(root, "cwd"),
		rules:         filepath.Join(root, "rules"),
		recorder:      filepath.Join(root, "recorder"),
		keys:          filepath.Join(root, "keys"),
	}
}

// create makes the run directory and every pinned directory. The root must not
// exist yet: a reused directory could carry state from an earlier run.
func (d runDirs) create() error {
	if err := os.Mkdir(d.root, 0o750); err != nil {
		return err
	}
	for _, dir := range []string{d.home, d.scanHome, d.xdgConfig, d.xdgData, d.xdgCache, d.xdgState, d.xdgConfigDirs, d.xdgDataDirs, d.tmp, d.cwd, d.rules} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	return os.MkdirAll(d.xdgRuntime, 0o700)
}

// pinned returns the environment variables the harness sets itself.
func (d runDirs) pinned() map[string]string {
	return map[string]string{
		"HOME":            d.home,
		"XDG_CONFIG_HOME": d.xdgConfig,
		"XDG_DATA_HOME":   d.xdgData,
		"XDG_CACHE_HOME":  d.xdgCache,
		"XDG_STATE_HOME":  d.xdgState,
		"XDG_RUNTIME_DIR": d.xdgRuntime,
		"XDG_CONFIG_DIRS": d.xdgConfigDirs,
		"XDG_DATA_DIRS":   d.xdgDataDirs,
		"TMPDIR":          d.tmp,
	}
}

// envReport records how the child environment was built.
type envReport struct {
	Allowlist    []string          `json:"allowlist"`
	Passed       map[string]string `json:"passed"`
	Pinned       map[string]string `json:"pinned"`
	DroppedCount int               `json:"dropped_count"`
}

// buildChildEnv returns the scrubbed environment for the proxy child: the
// allowlisted host variables plus the pinned run-directory variables.
func buildChildEnv(host []string, dirs runDirs) ([]string, envReport) {
	allowed := make(map[string]bool, len(passthroughEnv))
	for _, name := range passthroughEnv {
		allowed[name] = true
	}
	pinned := dirs.pinned()
	rep := envReport{Allowlist: append([]string(nil), passthroughEnv...), Passed: map[string]string{}, Pinned: map[string]string{}}
	var env []string
	for _, kv := range host {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if _, isPinned := pinned[name]; isPinned || !allowed[name] {
			rep.DroppedCount++
			continue
		}
		env = append(env, kv)
		rep.Passed[name] = recordedEnvValue(name, value)
	}
	names := make([]string, 0, len(pinned))
	for name := range pinned {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, name+"="+pinned[name])
		rel, err := filepath.Rel(dirs.root, pinned[name])
		if err != nil {
			rel = pinned[name]
		}
		rep.Pinned[name] = rel
	}
	return env, rep
}

// recordedEnvValue is what a passed-through variable looks like in the result.
// Scheduling and zone values are plain. PATH exposes the home directory layout
// and a proxy URL can embed credentials or internal hostnames, so those are
// recorded as a digest: enough to tell two runs apart, not enough to leak.
func recordedEnvValue(name, value string) string {
	switch name {
	case "TZ", "GOMAXPROCS":
		return value
	}
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:8])
}

type fileDigest struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// rulesReport is the pinned rule-bundle input. Mode "empty" loads nothing;
// mode "dir" loads a copy of a named directory whose every file is hashed.
type rulesReport struct {
	Mode   string       `json:"mode"`
	Source string       `json:"source,omitempty"`
	Dir    string       `json:"dir"`
	Files  []fileDigest `json:"files"`
	// ProxyLogLines are the proxy's own startup lines about rule bundles. The
	// directory and the environment are pinned, but this is the proxy's word
	// for what it actually loaded, so under mode "empty" any line here is a
	// leak and fails integrity.
	ProxyLogLines []string `json:"proxy_log_bundle_lines"`
}

var bundleLogPattern = regexp.MustCompile(`(?i)rule bundle|rule_bundle_|\bbundle "[^"]+"|bundle\(s\)`)

const maxBundleLogLines = 20

// bundleLogLines returns the lines of a proxy log that talk about rule
// bundles, bounded so a noisy log cannot bloat the result.
func bundleLogLines(logPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Clean(logPath))
	if err != nil {
		return nil, err
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if bundleLogPattern.MatchString(line) && len(lines) < maxBundleLogLines {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines, nil
}

const rulesEmpty = "empty"

// prepareRules pins rules_dir. The effective directory always lives inside the
// run directory: empty for rulesEmpty, otherwise a verified copy of source so
// the loader's freshness state and lock never touch the original.
func prepareRules(spec string, dirs runDirs) (rulesReport, error) {
	rep := rulesReport{Mode: rulesEmpty, Dir: "rules", Files: []fileDigest{}, ProxyLogLines: []string{}}
	if spec == "" || spec == rulesEmpty {
		return rep, nil
	}
	rep.Mode = "dir"
	abs, err := filepath.Abs(spec)
	if err != nil {
		return rep, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return rep, fmt.Errorf("--rules: %w", err)
	}
	if !info.IsDir() {
		return rep, fmt.Errorf("--rules %q is not a directory", spec)
	}
	rep.Source = abs
	files, err := copyTreeHashed(abs, dirs.rules)
	if err != nil {
		return rep, fmt.Errorf("--rules: %w", err)
	}
	rep.Files = files
	return rep, nil
}

// copyTreeHashed copies the regular files and directories under src into dst,
// hashing each file as it is read and again after the copy. Symlinks and other
// special files are refused: they could point outside the pinned input.
func copyTreeHashed(src, dst string) ([]fileDigest, error) {
	var files []fileDigest
	root, err := os.OpenRoot(src)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	err = filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		target := filepath.Join(dst, rel)
		switch {
		case entry.IsDir():
			return os.MkdirAll(target, 0o750)
		case !entry.Type().IsRegular():
			return fmt.Errorf("%s is not a regular file or directory", rel)
		}
		digest, copyErr := copyHashed(root, rel, target)
		if copyErr != nil {
			return copyErr
		}
		digest.Path = filepath.ToSlash(rel)
		files = append(files, digest)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func copyHashed(root *os.Root, rel, target string) (fileDigest, error) {
	in, err := root.Open(rel)
	if err != nil {
		return fileDigest{}, err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(filepath.Clean(target), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fileDigest{}, err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, h), in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fileDigest{}, err
	}
	copied, err := sha256File(target)
	if err != nil {
		return fileDigest{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if copied != sum {
		return fileDigest{}, fmt.Errorf("%s changed while it was copied", rel)
	}
	return fileDigest{Size: size, SHA256: sum}, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// configParams are the settings the harness forces on the generated config.
type configParams struct {
	mode   string
	chains int
	dirs   runDirs
}

// configReport is the effective config the child ran with. SHA256 hashes the
// exact bytes; CanonicalSHA256 hashes them with the run directory replaced by
// a placeholder so two runs on different paths or machines compare equal when
// their settings are equal.
type configReport struct {
	Path            string   `json:"path"`
	SHA256          string   `json:"sha256"`
	CanonicalSHA256 string   `json:"canonical_sha256"`
	ExternalPaths   []string `json:"external_paths"`
	YAML            string   `json:"yaml"`
}

// applyConfig forces the load-test settings onto a generated config and
// returns the serialized effective config.
func applyConfig(base []byte, p configParams) ([]byte, error) {
	var cfg map[string]any
	if err := yaml.Unmarshal(base, &cfg); err != nil {
		return nil, err
	}
	monitoring, err := configSection(cfg, "fetch_proxy", "monitoring")
	if err != nil {
		return nil, err
	}
	monitoring["max_requests_per_minute"] = 10000000
	forward, err := configSection(cfg, "forward_proxy")
	if err != nil {
		return nil, err
	}
	forward["enabled"] = true
	ssrf, err := configSection(cfg, "ssrf")
	if err != nil {
		return nil, err
	}
	ssrf["ip_allowlist"] = []string{"127.0.0.1/32"}
	fr, err := configSection(cfg, "flight_recorder")
	if err != nil {
		return nil, err
	}
	fr["enabled"] = p.mode != modeOff
	fr["require_receipts"] = p.mode == modeRequired
	fr["receipt_chains"] = p.chains
	rules, err := configSection(cfg, "rules")
	if err != nil {
		rules = map[string]any{}
		cfg["rules"] = rules
	}
	rules["rules_dir"] = p.dirs.rules
	pinHostPaths(cfg, p.dirs)
	return yaml.Marshal(cfg)
}

// pinHostPaths points every defaulted host-wide directory at the run
// directory. Today that is the quarantine directory, which defaults to a
// shared location under the system temp directory.
func pinHostPaths(node any, dirs runDirs) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "quarantine_dir" {
				v[key] = filepath.Join(dirs.tmp, "quarantine")
				continue
			}
			pinHostPaths(child, dirs)
		}
	case []any:
		for _, child := range v {
			pinHostPaths(child, dirs)
		}
	}
}

// describeConfig hashes the effective config and lists every directory or file
// setting that points outside the run directory.
func describeConfig(path string, data []byte, root string) (configReport, error) {
	sum := sha256.Sum256(data)
	canonical := sha256.Sum256([]byte(strings.ReplaceAll(string(data), root, "<RUN_DIR>")))
	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return configReport{}, err
	}
	external := []string{}
	collectExternalPaths(cfg, "", root, &external)
	sort.Strings(external)
	return configReport{
		Path:            filepath.Base(path),
		SHA256:          hex.EncodeToString(sum[:]),
		CanonicalSHA256: hex.EncodeToString(canonical[:]),
		ExternalPaths:   external,
		YAML:            strings.ReplaceAll(string(data), root, "<RUN_DIR>"),
	}, nil
}

func isPathKey(key string) bool {
	for _, suffix := range []string{"_dir", "_dirs", "_path", "_file", "_home"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return key == "dir" || key == "path" || key == "file" || key == "home"
}

func collectExternalPaths(node any, trail, root string, out *[]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, child := range v {
			collectExternalPaths(child, joinTrail(trail, key), root, out)
		}
	case []any:
		for i, child := range v {
			collectExternalPaths(child, trail+"["+strconv.Itoa(i)+"]", root, out)
		}
	case string:
		key := trail[strings.LastIndexByte(trail, '.')+1:]
		if isPathKey(key) && filepath.IsAbs(v) && !strings.HasPrefix(v, root+string(filepath.Separator)) && v != root {
			*out = append(*out, trail+"="+v)
		}
	}
}

func joinTrail(trail, key string) string {
	if trail == "" {
		return key
	}
	return trail + "." + key
}

// configSection walks nested YAML mappings and reports a clear error when the
// generated config no longer has the expected shape.
func configSection(cfg map[string]any, keys ...string) (map[string]any, error) {
	current := cfg
	for _, key := range keys {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("generated config has no %q mapping", strings.Join(keys, "."))
		}
		current = next
	}
	return current, nil
}

// hostReport records the facts about the machine that move throughput.
type hostReport struct {
	GOOS              string `json:"goos"`
	GOARCH            string `json:"goarch"`
	NumCPU            int    `json:"num_cpu"`
	HarnessGOMAXPROCS int    `json:"harness_gomaxprocs"`
	ChildGOMAXPROCS   string `json:"child_gomaxprocs_env"`
	CgroupCPUQuota    string `json:"cgroup_cpu_quota"`
	OutputFSType      string `json:"output_filesystem_type"`
}

func describeHost(env []string, out string) hostReport {
	child := "unset"
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "GOMAXPROCS="); ok {
			child = v
		}
	}
	return hostReport{
		GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(),
		HarnessGOMAXPROCS: runtime.GOMAXPROCS(0),
		ChildGOMAXPROCS:   child,
		CgroupCPUQuota:    cgroupCPUQuota(),
		OutputFSType:      filesystemType(out),
	}
}

// cgroupCPUQuota reports the tightest visible cgroup v2 cpu.max limit above
// this process. Ancestor limits apply even when a child has a larger quota.
func cgroupCPUQuota() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "unavailable: no /proc/self/cgroup"
	}
	var rel string
	for _, line := range strings.Split(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			rel = path
		}
	}
	if rel == "" {
		return "unavailable: not a cgroup v2 process"
	}
	return cgroupCPUQuotaFrom("/sys/fs/cgroup", rel)
}

func cgroupCPUQuotaFrom(root, rel string) string {
	var tightest *big.Rat
	quota := "none visible"
	for dir := filepath.Join(root, rel); dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)); dir = filepath.Dir(dir) {
		raw, readErr := os.ReadFile(filepath.Join(filepath.Clean(dir), "cpu.max"))
		if readErr != nil {
			// The unified root has no cpu.max interface.
			if dir != root || !errors.Is(readErr, os.ErrNotExist) {
				return "unavailable: cannot read quota hierarchy"
			}
		} else {
			fields := strings.Fields(string(raw))
			if len(fields) != 2 {
				return "unavailable: malformed quota hierarchy"
			}
			period, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil || period <= 0 {
				return "unavailable: invalid quota period"
			}
			if fields[0] != "max" {
				q, p, ok := parseCPUQuotaRatio(fields[0], fields[1])
				if !ok {
					return "unavailable: invalid quota hierarchy"
				}
				ratio := big.NewRat(q, p)
				if tightest == nil || ratio.Cmp(tightest) < 0 {
					tightest = ratio
					quota = fmt.Sprintf("%s/%s us (%s)", fields[0], fields[1], strings.TrimPrefix(dir, root))
				}
			}
		}
		if dir == root {
			break
		}
	}
	return quota
}

func parseCPUQuotaRatio(numerator, denominator string) (int64, int64, bool) {
	q, qErr := strconv.ParseInt(numerator, 10, 64)
	p, pErr := strconv.ParseInt(denominator, 10, 64)
	return q, p, qErr == nil && pErr == nil && q > 0 && p > 0
}

// binaryReport identifies the exact proxy under test.
type binaryReport struct {
	SHA256  string `json:"sha256"`
	Version string `json:"version_output"`
}

type harnessReport struct {
	ContractVersion string `json:"contract_version"`
	SourceSHA256    string `json:"source_sha256"`
	GoVersion       string `json:"go_version"`
}

var errNotExecutable = errors.New("not an executable regular file")
