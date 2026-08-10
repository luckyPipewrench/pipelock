// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// pipelock-release-images writes the exact container image digests that belong
// to one Pipelock release. It runs in the release workflow after all three
// published images resolve to immutable manifest digests.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const schema = "pipelock-release-images-v1"

var (
	tagRE    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

var expectedImages = map[string]string{
	"pipelock":                 "ghcr.io/luckypipewrench/pipelock",
	"pipelock-init":            "ghcr.io/luckypipewrench/pipelock-init",
	"pipelock-license-service": "ghcr.io/luckypipewrench/pipelock-license-service",
}

type imageFlag []string

func (f *imageFlag) String() string { return strings.Join(*f, ",") }

func (f *imageFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type releaseImages struct {
	Schema string         `json:"schema"`
	Tag    string         `json:"tag"`
	Commit string         `json:"commit"`
	Images []releaseImage `json:"images"`
}

type releaseImage struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "pipelock-release-images: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pipelock-release-images", flag.ContinueOnError)
	fs.SetOutput(stderr)
	tag := fs.String("tag", "", "release tag, e.g. v3.4.0")
	commit := fs.String("commit", "", "release commit SHA")
	out := fs.String("out", "", "output path for release-images.json")
	var images imageFlag
	fs.Var(&images, "image", "required image as name=repository@sha256:<64 lowercase hex chars>; repeat for every release image")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	manifest, err := buildManifest(*tag, *commit, images)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal release image bundle: %w", err)
	}
	data = append(data, '\n')
	if *out == "" {
		if _, err := stdout.Write(data); err != nil {
			return fmt.Errorf("write release image bundle: %w", err)
		}
		return nil
	}
	if err := os.WriteFile(filepath.Clean(*out), data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}
	return nil
}

func buildManifest(tag, commit string, values []string) (releaseImages, error) {
	tag = strings.TrimSpace(tag)
	if !tagRE.MatchString(tag) {
		return releaseImages{}, errors.New("--tag must be a release tag such as v3.4.0")
	}
	commit = strings.TrimSpace(commit)
	if !commitRE.MatchString(commit) {
		return releaseImages{}, errors.New("--commit must be a 40-character lowercase Git SHA")
	}
	if len(values) > len(expectedImages) {
		return releaseImages{}, fmt.Errorf("exactly %d --image flags are required", len(expectedImages))
	}

	seen := make(map[string]struct{}, len(values))
	images := make([]releaseImage, 0, len(values))
	for _, value := range values {
		image, err := parseImage(value)
		if err != nil {
			return releaseImages{}, err
		}
		if _, ok := seen[image.Name]; ok {
			return releaseImages{}, fmt.Errorf("duplicate --image %q", image.Name)
		}
		seen[image.Name] = struct{}{}
		wantRepository, ok := expectedImages[image.Name]
		if !ok {
			return releaseImages{}, fmt.Errorf("unknown --image name %q", image.Name)
		}
		if image.Repository != wantRepository {
			return releaseImages{}, fmt.Errorf("--image %q repository = %q, want %q", image.Name, image.Repository, wantRepository)
		}
		images = append(images, image)
	}
	for name := range expectedImages {
		if _, ok := seen[name]; !ok {
			return releaseImages{}, fmt.Errorf("missing required --image %q", name)
		}
	}
	sort.Slice(images, func(i, j int) bool { return images[i].Name < images[j].Name })
	return releaseImages{Schema: schema, Tag: tag, Commit: commit, Images: images}, nil
}

func parseImage(value string) (releaseImage, error) {
	name, reference, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || name == "" || reference == "" {
		return releaseImage{}, fmt.Errorf("--image %q must use name=repository@sha256:<64 lowercase hex chars>", value)
	}
	repository, digest, ok := strings.Cut(reference, "@")
	if !ok {
		return releaseImage{}, fmt.Errorf("--image %q must use a lowercase sha256 manifest digest", value)
	}
	if repository == "" {
		return releaseImage{}, fmt.Errorf("--image %q must name a repository before @", value)
	}
	if strings.Contains(digest, "@") {
		return releaseImage{}, fmt.Errorf("--image %q has more than one @ separator", value)
	}
	if !digestRE.MatchString(digest) {
		return releaseImage{}, fmt.Errorf("--image %q must use a lowercase sha256 manifest digest", value)
	}
	return releaseImage{Name: name, Repository: repository, Digest: digest}, nil
}
