// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"os"
	"path/filepath"
	"strings"
)

type containPlatform struct {
	id                 string
	idLike             []string
	family             string
	systemCABundlePath string
	bashPath           string
	nologinPath        string
	nftPath            string
	curlPath           string
}

const (
	platformFamilyDebian  = "debian"
	platformFamilyRHEL    = "rhel"
	platformFamilyArch    = "arch"
	platformFamilySUSE    = "suse"
	platformFamilyGeneric = "generic"
)

func detectContainPlatform(
	readFile func(string) ([]byte, error),
	stat func(string) (os.FileInfo, error),
	lookPath func(string) (string, error),
) containPlatform {
	id, likes := readOSRelease(readFile)
	family := platformFamilyFor(id, likes)
	return containPlatform{
		id:                 id,
		idLike:             likes,
		family:             family,
		systemCABundlePath: firstExistingPath(stat, systemCABundleCandidates(family)),
		bashPath:           resolveExecutablePath(stat, lookPath, "bash", []string{"/usr/bin/bash", "/bin/bash"}),
		nologinPath:        resolveExecutablePath(stat, lookPath, "nologin", []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}),
		nftPath:            resolveExecutablePathCandidatesFirst(stat, lookPath, "nft", []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"}),
		curlPath:           resolveExecutablePath(stat, lookPath, "curl", []string{"/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"}),
	}
}

func readOSRelease(readFile func(string) ([]byte, error)) (string, []string) {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := readFile(path)
		if err != nil {
			continue
		}
		fields := parseOSRelease(data)
		id := fields["ID"]
		if id == "" {
			id = "linux"
		}
		return id, strings.Fields(fields["ID_LIKE"])
	}
	return "linux", nil
}

func parseOSRelease(data []byte) map[string]string {
	out := map[string]string{}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			quote := value[0]
			if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
				value = value[1 : len(value)-1]
			}
		}
		out[key] = value
	}
	return out
}

func platformFamilyFor(id string, likes []string) string {
	for _, candidate := range append([]string{id}, likes...) {
		switch candidate {
		case "debian", "ubuntu":
			return platformFamilyDebian
		case "fedora", "rhel", "centos", "rocky", "almalinux", "ol", "amzn":
			return platformFamilyRHEL
		case "arch", "archlinux":
			return platformFamilyArch
		case "suse", "opensuse", "opensuse-tumbleweed", "opensuse-leap", "sles":
			return platformFamilySUSE
		}
	}
	return platformFamilyGeneric
}

func systemCABundleCandidates(family string) []string {
	switch family {
	case platformFamilyDebian:
		return []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/ssl/certs/ca-bundle.crt",
		}
	case platformFamilyRHEL:
		return []string{
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/certs/ca-bundle.crt",
			"/etc/ssl/certs/ca-certificates.crt",
		}
	case platformFamilyArch:
		return []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/ssl/certs/ca-bundle.crt",
		}
	case platformFamilySUSE:
		return []string{
			"/etc/ssl/ca-bundle.pem",
			"/var/lib/ca-certificates/ca-bundle.pem",
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/ssl/certs/ca-bundle.crt",
		}
	default:
		return []string{
			"/etc/ssl/certs/ca-certificates.crt",
			"/etc/ssl/certs/ca-bundle.crt",
			"/etc/pki/tls/certs/ca-bundle.crt",
			"/etc/ssl/ca-bundle.pem",
			"/var/lib/ca-certificates/ca-bundle.pem",
		}
	}
}

func firstExistingPath(stat func(string) (os.FileInfo, error), paths []string) string {
	for _, path := range paths {
		clean := filepath.Clean(path)
		info, err := stat(clean)
		if err == nil && !info.IsDir() {
			return clean
		}
	}
	if len(paths) == 0 {
		return defaultSystemCABundle
	}
	return filepath.Clean(paths[0])
}

func resolveExecutablePath(
	stat func(string) (os.FileInfo, error),
	lookPath func(string) (string, error),
	name string,
	candidates []string,
) string {
	if lookPath != nil {
		if path, err := lookPath(name); err == nil && path != "" {
			return filepath.Clean(path)
		}
	}
	for _, path := range candidates {
		clean := filepath.Clean(path)
		info, err := stat(clean)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return clean
		}
	}
	if len(candidates) == 0 {
		return name
	}
	return filepath.Clean(candidates[0])
}

func resolveExecutablePathCandidatesFirst(
	stat func(string) (os.FileInfo, error),
	lookPath func(string) (string, error),
	name string,
	candidates []string,
) string {
	for _, path := range candidates {
		clean := filepath.Clean(path)
		info, err := stat(clean)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0o111 != 0 {
			return clean
		}
	}
	if lookPath != nil {
		if path, err := lookPath(name); err == nil && path != "" {
			return filepath.Clean(path)
		}
	}
	if len(candidates) == 0 {
		return name
	}
	return filepath.Clean(candidates[0])
}
