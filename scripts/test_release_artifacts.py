# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Fail-closed structural checks for the tag-release artifact contract.

These run in the tag preflight job, before GoReleaser can upload a release. The
checks intentionally inspect the workflow source rather than relying on a
successful prior run: a future edit that drops one architecture, swaps a tool
for a floating version, or stops publishing an image SBOM must block the tag
that introduced the drift.
"""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yaml"

GORELEASER_VERSION = "v2.17.1"
GORELEASER_LINUX_AMD64_SHA256 = "a99bbc7ae0d8d897b07c4c497a9b62f222558804715ef219d1af05a7e417bc80"
SYFT_VERSION = "v1.50.0"
SYFT_LINUX_AMD64_SHA256 = "bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788"

PLATFORM_ARTIFACTS = {
    "pipelock": "ghcr.io/luckypipewrench/pipelock",
    "pipelock_init": "ghcr.io/luckypipewrench/pipelock-init",
    "license_service": "ghcr.io/luckypipewrench/pipelock-license-service",
}
ATTESTATION_NAMES = {
    "pipelock": "pipelock",
    "pipelock_init": "pipelock-init",
    "license_service": "license-service",
}
BUNDLE_NAMES = {
    "pipelock": "pipelock",
    "pipelock_init": "pipelock-init",
    "license_service": "pipelock-license-service",
}


class TestReleaseArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_goreleaser_is_exactly_pinned_and_self_reports(self) -> None:
        self.assertIn(f"GORELEASER_VERSION: {GORELEASER_VERSION}", self.workflow)
        self.assertIn(
            f"GORELEASER_LINUX_AMD64_SHA256: {GORELEASER_LINUX_AMD64_SHA256}",
            self.workflow,
        )
        self.assertIn('gh release download "$GORELEASER_VERSION"', self.workflow)
        self.assertIn("--repo goreleaser/goreleaser", self.workflow)
        self.assertIn("sha256sum --check", self.workflow)
        self.assertIn('got="$($tool_dir/goreleaser --version', self.workflow)
        self.assertIn('test "$got" = "$expected"', self.workflow)
        self.assertIn("run: goreleaser release --clean --draft", self.workflow)
        self.assertNotIn("version: '~> v2'", self.workflow)

    def test_every_platform_is_resolved_from_the_published_index(self) -> None:
        self.assertIn("Resolve release image platform digests", self.workflow)
        self.assertIn('for arch in amd64 arm64; do', self.workflow)
        self.assertIn('crane manifest "${repository}:${TAG#v}"', self.workflow)
        self.assertIn('crane digest "${repository}:${TAG#v}-${arch}"', self.workflow)
        self.assertIn('is not the index child', self.workflow)
        for name, repository in PLATFORM_ARTIFACTS.items():
            self.assertIn(f"resolve_image {name} {repository}", self.workflow)
            for arch in ("amd64", "arm64"):
                self.assertIn(f"{name}_{arch}", self.workflow)

    def test_every_platform_image_gets_a_published_sbom(self) -> None:
        self.assertIn(f"SYFT_VERSION: {SYFT_VERSION}", self.workflow)
        self.assertIn(f"SYFT_LINUX_AMD64_SHA256: {SYFT_LINUX_AMD64_SHA256}", self.workflow)
        self.assertIn('gh release download "$SYFT_VERSION"', self.workflow)
        self.assertIn("--repo anchore/syft", self.workflow)
        self.assertIn('got="$($tool_dir/syft version', self.workflow)
        self.assertIn('test "$got" = "$expected"', self.workflow)
        self.assertIn('"$tool_dir/syft" "${image}@${digest}"', self.workflow)
        self.assertIn('gh release upload "$GITHUB_REF_NAME" "$output" --clobber', self.workflow)

        for name, repository in PLATFORM_ARTIFACTS.items():
            stem = repository.rsplit("/", maxsplit=1)[-1]
            for arch in ("amd64", "arm64"):
                digest_var = f"{name.upper()}_{arch.upper()}_DIGEST"
                self.assertIn(
                    f"{digest_var}: ${{{{ steps.platform-digests.outputs.{name}_{arch} }}}}",
                    self.workflow,
                )
                output = f"sbom-{stem}-linux-{arch}.cdx.json"
                self.assertIn(
                    f"publish_sbom {repository} \"${digest_var}\" {output}",
                    self.workflow,
                )

    def test_every_platform_child_has_provenance_and_is_fail_closed(self) -> None:
        for name, repository in PLATFORM_ARTIFACTS.items():
            for arch in ("amd64", "arm64"):
                attestation_id = f"attest-{ATTESTATION_NAMES[name]}-{arch}"
                self.assertIn(f"id: {attestation_id}", self.workflow)
                self.assertIn(
                    f"subject-digest: ${{{{ steps.platform-digests.outputs.{name}_{arch} }}}}",
                    self.workflow,
                )
                self.assertIn(
                    f"steps.{attestation_id}.outcome != 'success'",
                    self.workflow,
                )

    def test_github_release_promotion_follows_proof_bundle_and_chart(self) -> None:
        goreleaser = self.workflow.index("- name: Run GoReleaser")
        proof_gate = self.workflow.index("- name: Verify attestation")
        bundle = self.workflow.index("- name: Build Kubernetes image digest bundle")
        upload = self.workflow.index("- name: Upload Kubernetes image digest bundle")
        chart = self.workflow.index("- name: Package and publish Helm chart")
        promotion = self.workflow.index("- name: Publish GitHub release")
        self.assertIn('gh release edit "$GITHUB_REF_NAME" --draft=false', self.workflow)

        self.assertLess(goreleaser, proof_gate)
        self.assertLess(proof_gate, bundle)
        self.assertLess(bundle, upload)
        self.assertLess(upload, chart)
        self.assertLess(chart, promotion)

        for name, repository in PLATFORM_ARTIFACTS.items():
            self.assertIn(
                f'-image "{BUNDLE_NAMES[name]}={repository}@${{{{ steps.platform-digests.outputs.{name}_index }}}}"',
                self.workflow,
            )
        self.assertIn("dist/release-images.json", self.workflow)


if __name__ == "__main__":
    unittest.main()
