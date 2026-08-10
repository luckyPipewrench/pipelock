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
GORELEASER = ROOT / ".goreleaser.yaml"

GORELEASER_VERSION = "v2.17.1"
GORELEASER_LINUX_AMD64_SHA256 = "a99bbc7ae0d8d897b07c4c497a9b62f222558804715ef219d1af05a7e417bc80"
SYFT_VERSION = "v1.50.0"
SYFT_LINUX_AMD64_SHA256 = "bf7b29ff57f06da30918266a0e1c2885a8f99784798d1bdb1628886aa015d788"
COSIGN_VERSION = "v2.6.5"
COSIGN_LINUX_AMD64_SHA256 = "c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"
CYCLONEDX_GOMOD_VERSION = "v1.10.0"
CYCLONEDX_GOMOD_LINUX_AMD64_SHA256 = "5cce8ae99a5181be6a610ea5ed9ca9d596937cc04dc1a8f6f6b5e462d8c9900e"
CRANE_VERSION = "v0.21.9"
CRANE_LINUX_AMD64_SHA256 = "5c16d8ddb971cb1d5e6ed8b1e743da8224414eeba2c2762d8f1a61b2f095699e"

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
INDEX_ATTESTATION_IDS = (
    "attest-pipelock-container",
    "attest-pipelock-init-container",
    "attest-license-service-container",
)
ARCHIVE_ATTESTATION_IDS = ("attest-binaries", "attest-checksums", "attest-sbom")
IMAGE_SBOM_ATTESTATION_IDS = (
    "attest-pipelock-amd64-sbom",
    "attest-pipelock-arm64-sbom",
    "attest-pipelock-init-amd64-sbom",
    "attest-pipelock-init-arm64-sbom",
    "attest-license-service-amd64-sbom",
    "attest-license-service-arm64-sbom",
)


class TestReleaseArtifacts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.goreleaser = GORELEASER.read_text(encoding="utf-8")

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

        for repository in PLATFORM_ARTIFACTS.values():
            self.assertIn(f'"{repository}:{{{{ .Version }}}}-staging-amd64"', self.goreleaser)
            self.assertIn(f'"{repository}:{{{{ .Version }}}}-staging-arm64"', self.goreleaser)
            self.assertIn(f'name_template: "{repository}:{{{{ .Version }}}}-staging"', self.goreleaser)
            self.assertNotIn(f'name_template: "{repository}:{{{{ .Version }}}}"', self.goreleaser)
            self.assertNotIn(f'name_template: "{repository}:latest"', self.goreleaser)

    def test_other_release_tools_are_exactly_pinned_and_verified(self) -> None:
        expected_tools = (
            (
                "COSIGN",
                COSIGN_VERSION,
                COSIGN_LINUX_AMD64_SHA256,
                "sigstore/cosign",
                "cosign-linux-amd64",
                'got="$($tool_dir/cosign version',
            ),
            (
                "CYCLONEDX_GOMOD",
                CYCLONEDX_GOMOD_VERSION,
                CYCLONEDX_GOMOD_LINUX_AMD64_SHA256,
                "CycloneDX/cyclonedx-gomod",
                "cyclonedx-gomod_",
                'got="$($tool_dir/cyclonedx-gomod version',
            ),
            (
                "CRANE",
                CRANE_VERSION,
                CRANE_LINUX_AMD64_SHA256,
                "google/go-containerregistry",
                "go-containerregistry_Linux_x86_64.tar.gz",
                'got="$($tool_dir/crane version)',
            ),
        )
        for prefix, version, digest, repository, asset, version_check in expected_tools:
            start = self.workflow.index(f"{prefix}_VERSION: {version}")
            end = self.workflow.find("\n      - name:", start)
            block = self.workflow[start : end if end != -1 else len(self.workflow)]
            self.assertIn(f"{prefix}_LINUX_AMD64_SHA256: {digest}", block)
            self.assertIn(f"--repo {repository}", block)
            self.assertIn(asset, block)
            self.assertIn("sha256sum --check", block)
            self.assertIn(version_check, block)

        self.assertNotIn("go install github.com/CycloneDX", self.workflow)
        self.assertNotIn("go install github.com/google/go-containerregistry", self.workflow)

    def test_every_platform_is_resolved_from_the_staging_index(self) -> None:
        self.assertIn("Resolve release image platform digests", self.workflow)
        self.assertIn('for arch in amd64 arm64; do', self.workflow)
        self.assertIn('staging_tag="${TAG#v}-staging"', self.workflow)
        self.assertIn('"$tool_dir/crane" manifest "${repository}:${staging_tag}"', self.workflow)
        self.assertIn('"$tool_dir/crane" digest "${repository}:${staging_tag}-${arch}"', self.workflow)
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
        self.assertIn('archive="syft_${SYFT_VERSION#v}_linux_amd64.tar.gz"', self.workflow)
        self.assertIn('got="$($tool_dir/syft version', self.workflow)
        self.assertIn('test "$got" = "$expected"', self.workflow)
        self.assertIn('"$tool_dir/syft" "registry:${image}@${digest}"', self.workflow)
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

    def test_every_attestation_dependency_is_fail_closed(self) -> None:
        proof_gate = self.workflow.index("- name: Verify attestation")
        attestation_ids = [*ARCHIVE_ATTESTATION_IDS, *INDEX_ATTESTATION_IDS]
        for attestation_id in attestation_ids:
            self.assertIn(f"id: {attestation_id}", self.workflow)
            self.assertIn(f"steps.{attestation_id}.outcome != 'success'", self.workflow)
            self.assertLess(self.workflow.index(f"id: {attestation_id}"), proof_gate)

        for name, repository in PLATFORM_ARTIFACTS.items():
            for arch in ("amd64", "arm64"):
                attestation_id = f"attest-{ATTESTATION_NAMES[name]}-{arch}"
                attestation_ids.append(attestation_id)
                self.assertIn(f"id: {attestation_id}", self.workflow)
                self.assertIn(
                    f"subject-digest: ${{{{ steps.platform-digests.outputs.{name}_{arch} }}}}",
                    self.workflow,
                )
                self.assertIn(
                    f"steps.{attestation_id}.outcome != 'success'",
                    self.workflow,
                )
                self.assertLess(self.workflow.index(f"id: {attestation_id}"), proof_gate)
                sbom_attestation_id = f"{attestation_id}-sbom"
                self.assertIn(f"id: {sbom_attestation_id}", self.workflow)
                self.assertLess(self.workflow.index(f"id: {sbom_attestation_id}"), proof_gate)
                self.assertIn(
                    f"sbom-{repository.rsplit('/', maxsplit=1)[-1]}-linux-{arch}.cdx.json",
                    self.workflow,
                )

        attestation_ids.extend(IMAGE_SBOM_ATTESTATION_IDS)

        gate_end = self.workflow.index("run: |", proof_gate)
        normalized_gate = " ".join(self.workflow[proof_gate:gate_end].split())
        expected_condition = "always() && ( " + " || ".join(
            f"steps.{attestation_id}.outcome != 'success'"
            for attestation_id in attestation_ids
        ) + " )"
        self.assertIn(expected_condition, normalized_gate)
        self.assertNotIn("== 'failure'", normalized_gate)

    def test_verified_staging_indexes_promote_after_the_proof_gate(self) -> None:
        resolution = self.workflow.index("- name: Resolve release image platform digests")
        proof_gate = self.workflow.index("- name: Verify attestation")
        chart_preflight = self.workflow.index("- name: Package and verify Helm chart version")
        promotion = self.workflow.index("- name: Promote verified image manifests")
        bundle = self.workflow.index("- name: Build Kubernetes image digest bundle")
        self.assertLess(resolution, proof_gate)
        self.assertLess(proof_gate, chart_preflight)
        self.assertLess(chart_preflight, promotion)
        self.assertLess(proof_gate, promotion)
        self.assertLess(promotion, bundle)
        self.assertIn('crane copy --no-clobber "${repository}@${index_digest}"', self.workflow)
        self.assertIn('crane copy --no-clobber "${repository}@${digest}" "$target"', self.workflow)
        self.assertIn('"${repository}:latest"', self.workflow)
        self.assertIn('if [[ "$version" != *-* ]]; then', self.workflow)
        self.assertIn("grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+$'", self.workflow)
        self.assertIn('if [[ "$newest_stable" = "$version" ]]; then', self.workflow)
        self.assertIn('if [[ "$latest_digest" != "$index_digest" ]]; then', self.workflow)
        self.assertIn("grep -E '^v2\\.[0-9]+\\.[0-9]+$'", self.workflow)
        self.assertIn('if [[ "$TAG_NAME" != "$latest_stable_tag" ]]; then', self.workflow)

        digest_vars = {
            "pipelock": "PIPELOCK_INDEX_DIGEST",
            "pipelock_init": "PIPELOCK_INIT_INDEX_DIGEST",
            "license_service": "LICENSE_SERVICE_INDEX_DIGEST",
        }
        for name, repository in PLATFORM_ARTIFACTS.items():
            self.assertIn(
                f'promote_image {repository} "${digest_vars[name]}"',
                self.workflow,
            )
            for arch in ("amd64", "arm64"):
                self.assertIn(
                    f'promote_platform_image {repository} "${name.upper()}_{arch.upper()}_DIGEST" {arch}',
                    self.workflow,
                )

    def test_github_release_promotion_follows_proof_bundle_and_chart(self) -> None:
        goreleaser = self.workflow.index("- name: Run GoReleaser")
        proof_gate = self.workflow.index("- name: Verify attestation")
        bundle = self.workflow.index("- name: Build Kubernetes image digest bundle")
        bundle_attestation = self.workflow.index("- name: Attest Kubernetes image digest bundle")
        bundle_gate = self.workflow.index("- name: Verify Kubernetes image digest bundle attestation")
        upload = self.workflow.index("- name: Upload Kubernetes image digest bundle")
        chart = self.workflow.index("- name: Publish Helm chart")
        promotion = self.workflow.index("- name: Publish GitHub release")
        self.assertIn('gh release edit "$GITHUB_REF_NAME" --draft=false', self.workflow)

        self.assertLess(goreleaser, proof_gate)
        self.assertLess(proof_gate, bundle)
        self.assertLess(bundle, bundle_attestation)
        self.assertLess(bundle_attestation, bundle_gate)
        self.assertLess(bundle_gate, upload)
        self.assertLess(upload, chart)
        self.assertLess(chart, promotion)

        self.assertIn('release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{}")"', self.workflow)
        self.assertNotIn('-commit "$GITHUB_SHA"', self.workflow)
        self.assertIn('steps.attest-release-images.outcome != \'success\'', self.workflow)
        self.assertIn('if [[ "$CHART_ALREADY_PUBLISHED" != true ]]; then', self.workflow)
        self.assertIn('diff -ru "$candidate_dir/pipelock" "$existing_dir/pipelock"', self.workflow)
        self.assertIn('echo "CHART_VERSION=$chart_version" >> "$GITHUB_ENV"', self.workflow)
        self.assertIn('chart_version="$CHART_VERSION"', self.workflow)
        digest_vars = {
            "pipelock": "PIPELOCK_INDEX_DIGEST",
            "pipelock_init": "PIPELOCK_INIT_INDEX_DIGEST",
            "license_service": "LICENSE_SERVICE_INDEX_DIGEST",
        }
        for name, repository in PLATFORM_ARTIFACTS.items():
            self.assertIn(
                f'-image "{BUNDLE_NAMES[name]}={repository}@${{{digest_vars[name]}}}"',
                self.workflow,
            )
        self.assertIn("dist/release-images.json", self.workflow)


if __name__ == "__main__":
    unittest.main()
