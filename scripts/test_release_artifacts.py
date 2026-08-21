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

import yaml

from scripts.chart_changes_version import changes_appversion


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
GORELEASER = ROOT / ".goreleaser.yaml"
CHART = ROOT / "charts/pipelock/Chart.yaml"
MANUAL_CHART_WORKFLOW = ROOT / ".github/workflows/publish-chart.yaml"
WORKFLOWS_DIR = ROOT / ".github/workflows"

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


def workflow_events(document: object) -> set[str]:
    """Return a workflow's trigger names from any of the three accepted forms."""
    triggers = document.get("on") if isinstance(document, dict) else None
    if isinstance(triggers, dict):
        return set(triggers)
    if isinstance(triggers, list):
        return {str(entry) for entry in triggers}
    if isinstance(triggers, str):
        return {triggers}
    return set()


def grants_package_write(block: object) -> bool:
    """Report whether a permissions block hands the run registry write access."""
    if isinstance(block, str):
        return block == "write-all"
    if isinstance(block, dict):
        return block.get("packages") == "write"
    return False


def load_workflow(path: Path) -> object:
    # BaseLoader for the same reason the reviewer tests use it, and it must stay
    # BaseLoader. Every other loader reads GitHub's `on:` key as the YAML 1.1
    # boolean true, so the trigger set this check exists to read would arrive
    # under a key named True, every workflow would look trigger-less, and the
    # check would pass on all of them while testing nothing.
    #
    # This is not the unsafe load. BaseLoader constructs only strings, lists and
    # dicts, so it cannot instantiate arbitrary Python; it is strictly narrower
    # than safe_load, which additionally resolves the bool that breaks this.
    return yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


class TestReleaseArtifacts(unittest.TestCase):
    def test_chart_has_no_branch_selectable_manual_publisher(self) -> None:
        self.assertFalse(
            MANUAL_CHART_WORKFLOW.exists(),
            "chart publication must stay in the tag release path; a manual workflow can run branch-selected code",
        )

    def test_no_workflow_pairs_a_manual_trigger_with_package_write(self) -> None:
        """The class behind the deleted chart publisher, not just that one file.

        A manual dispatch lets the person starting the run choose the branch,
        and the branch then supplies the code that spends whatever authority the
        run holds. Naming one file cannot say anything about the next workflow
        that reaches for `packages: write`, so this reads the pairing itself.

        It is deliberately narrow, and the filename check above is not redundant
        with it: this sees only authority granted through GITHUB_TOKEN
        permissions. A manual publisher authenticating with a stored registry
        token declares no permissions at all and would pass here.
        """
        offenders = []
        for path in sorted(WORKFLOWS_DIR.glob("*.y*ml")):
            document = load_workflow(path)
            if not isinstance(document, dict):
                continue
            if "workflow_dispatch" not in workflow_events(document):
                continue
            blocks = [document.get("permissions")]
            jobs = document.get("jobs")
            if isinstance(jobs, dict):
                blocks.extend(job.get("permissions") for job in jobs.values() if isinstance(job, dict))
            if any(grants_package_write(block) for block in blocks):
                offenders.append(path.name)
        self.assertEqual(
            offenders,
            [],
            "a manually dispatched workflow must not hold packages: write; "
            "publish from the tag release path instead",
        )

    def test_chart_changes_version_is_scoped_to_annotation(self) -> None:
        chart = """description: Pipelock appVersion 9.9.9. Decoy.\nannotations:\n  artifacthub.io/changes: |\n    - kind: fixed\n      note: description: Pipelock appVersion 8.8.8. Nested decoy.\n      description: Pipelock appVersion 3.4.0. Real notes.\n  artifacthub.io/containsSecurityUpdates: \"true\"\n"""
        self.assertEqual(changes_appversion(chart), "3.4.0")

    def test_chart_changes_version_rejects_match_outside_annotation(self) -> None:
        chart = """description: Pipelock appVersion 9.9.9. Decoy.\nannotations:\n  artifacthub.io/changes: |\n    - kind: fixed\n      description: Notes without a version marker.\n  artifacthub.io/containsSecurityUpdates: \"true\"\n"""
        self.assertEqual(changes_appversion(chart), "")

    def test_chart_changes_version_matches_real_chart_appversion(self) -> None:
        chart_text = CHART.read_text(encoding="utf-8")
        chart = yaml.safe_load(chart_text)
        self.assertEqual(changes_appversion(chart_text), str(chart["appVersion"]))

    def test_chart_changes_version_accepts_prerelease(self) -> None:
        chart = """annotations:
  artifacthub.io/changes: |
    - kind: fixed
      description: Pipelock appVersion 3.5.0-preview.1. Candidate notes.
"""
        self.assertEqual(changes_appversion(chart), "3.5.0-preview.1")

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

    def test_homebrew_formula_is_generated_without_build_time_publication(self) -> None:
        config = yaml.safe_load(self.goreleaser)
        brews = config.get("brews", [])
        self.assertEqual(len(brews), 1)
        self.assertTrue(brews[0].get("skip_upload") is True)
        self.assertEqual(brews[0].get("directory"), "Formula")

    def test_tap_token_reaches_only_the_protected_publish_step(self) -> None:
        """The tap credential is what makes "generates but does not publish" real.

        `skip_upload` is a GoReleaser setting, so on its own it is a promise in a
        config file. Withholding the tap token from the build job is the part
        that cannot be undone by a config edit, and it is worth asserting
        separately because a token quietly restored to the GoReleaser step would
        make the separation cosmetic while every other check here still passed.
        """
        parsed = yaml.safe_load(WORKFLOW.read_text())
        holders = []
        for job_name, job in parsed["jobs"].items():
            for step in job.get("steps", []):
                blocks = (step.get("env") or {}, step.get("with") or {})
                if any(
                    "HOMEBREW_TAP_TOKEN" in str(value)
                    for block in blocks
                    for value in block.values()
                ):
                    holders.append((job_name, step.get("name", "")))
        self.assertEqual(holders, [("release-promote", "Publish Homebrew formula")])

    def test_release_waits_for_customer_verifier_install_gate(self) -> None:
        gate = self.workflow.index("  release-verifier-install:")
        release_build = self.workflow.index("\n  release-build:\n", gate)
        gate_block = self.workflow[gate:release_build]

        self.assertIn("needs: [release-tests]", gate_block)
        self.assertIn("fetch-depth: 0", gate_block)
        self.assertIn(
            'scripts/release-verifier-install-gate.sh --tag "$GITHUB_REF_NAME"',
            gate_block,
        )
        self.assertIn(
            "needs: [release-tests, release-verifier-install]",
            self.workflow[release_build:],
        )

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

    def test_verified_staging_indexes_promote_only_in_protected_job(self) -> None:
        resolution = self.workflow.index("- name: Resolve release image platform digests")
        proof_gate = self.workflow.index("- name: Verify attestation")
        chart_preflight = self.workflow.index("- name: Package Helm chart")
        bundle = self.workflow.index("- name: Build Kubernetes image digest bundle")
        promotion = self.workflow.index("- name: Promote verified image manifests")
        self.assertLess(resolution, proof_gate)
        self.assertLess(proof_gate, chart_preflight)
        self.assertLess(chart_preflight, bundle)
        self.assertLess(bundle, promotion)
        self.assertIn('crane copy --no-clobber "${repository}@${index_digest}"', self.workflow)
        self.assertIn('crane copy --no-clobber "${repository}@${digest}" "$target"', self.workflow)
        self.assertIn('"${repository}:latest"', self.workflow)
        self.assertIn('if [[ "$version" != *-* ]]; then', self.workflow)
        self.assertIn("grep -E '^[0-9]+\\.[0-9]+\\.[0-9]+$'", self.workflow)
        self.assertIn('if [[ "$newest_stable" = "$version" ]]; then', self.workflow)
        self.assertIn('if [[ "$latest_digest" != "$index_digest" ]]; then', self.workflow)
        runs = self._job_runs("release-promote")
        image_promotion = dict(runs)["Promote verified image manifests"]
        self.assertIn("git ls-remote --tags --refs origin 'refs/tags/v*'", image_promotion)
        self.assertNotIn("printf '%s\\n%s\\n' \"$tags\" \"$version\"", image_promotion)
        floating_steps = [script for name, script in runs if name == "Update floating major tag for GitHub Action"]
        self.assertEqual(len(floating_steps), 1, "expected exactly one floating-tag step")
        floating_lines = self._executable_lines(floating_steps[0])
        self.assertTrue(any("git ls-remote --tags --refs origin" in line for line in floating_lines))
        self.assertFalse(any("git tag --list" in line for line in floating_lines))
        self.assertTrue(
            any(
                "sed -nE 's/^v([0-9]+)\\.[0-9]+\\.[0-9]+$/\\1/p'" in line
                for line in floating_lines
            )
        )
        self.assertTrue(any('grep -E "^v${major}\\.[0-9]+\\.[0-9]+$"' in line for line in floating_lines))
        self.assertTrue(
            any('if [[ "$TAG_NAME" != "$latest_stable_tag" ]]; then' in line for line in floating_lines)
        )
        self.assertTrue(
            any(
                line.startswith("remote_oid=")
                and 'git ls-remote --refs origin "$floating_ref" | awk' in line
                for line in floating_lines
            )
        )
        push_lines = [line for line in floating_lines if line.startswith("git push ")]
        self.assertEqual(
            push_lines,
            ['git push origin "$floating_ref" --force-with-lease="${floating_ref}:${remote_oid}"'],
        )

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

    def _job_runs(self, job_name: str) -> list[tuple[str, str]]:
        """Return (step name, run script) for every step of one workflow job.

        Reading the parsed workflow rather than its text is the point. A string
        search is satisfied by a comment or an echo that merely mentions a
        command, and it cannot tell which step a command belongs to.
        """
        parsed = yaml.safe_load(WORKFLOW.read_text())
        steps = parsed["jobs"][job_name]["steps"]
        return [
            (step.get("name", ""), step["run"])
            for step in steps
            if isinstance(step, dict) and isinstance(step.get("run"), str)
        ]

    @staticmethod
    def _executable_lines(script: str) -> list[str]:
        """Return the lines of a run script that actually execute.

        Comments do not run, so a check that accepts them proves nothing about
        what the step does.
        """
        lines = []
        for raw in script.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
        return lines

    def test_promotion_is_separate_protected_and_signature_gated(self) -> None:  # noqa: PLR0915
        parsed = yaml.safe_load(WORKFLOW.read_text())
        build = parsed["jobs"]["release-build"]
        promote = parsed["jobs"]["release-promote"]
        self.assertEqual(promote["needs"], ["release-build"])
        self.assertEqual(promote["environment"], "release-promotion")
        self.assertEqual(promote["permissions"], {"contents": "write", "packages": "write"})

        build_runs = self._job_runs("release-build")
        promote_runs = self._job_runs("release-promote")
        build_script = "\n".join(script for _, script in build_runs)
        for forbidden in (
            "helm push ",
            "gh release edit ",
            "git push origin ",
            "repos/luckyPipewrench/homebrew-tap/contents/",
            '"${repository}:${version}"',
            '"${repository}:latest"',
        ):
            self.assertNotIn(forbidden, build_script)

        names = [name for name, _ in promote_runs]
        verify = names.index("Verify release manifest signature before promotion")
        inputs_verified = names.index("Verify promotion image inputs")
        for public_write in (
            "Promote verified image manifests",
            "Publish Helm chart",
            "Publish Homebrew formula",
            "Reverify the release manifest signature and publish",
            "Update floating major tag for GitHub Action",
        ):
            self.assertLess(verify, names.index(public_write))
            self.assertLess(inputs_verified, names.index(public_write))

        self.assertIn("actions/upload-artifact@043fb46d", self.workflow)
        self.assertIn("actions/download-artifact@3e5f45b", self.workflow)

        # These two were positional (`build["steps"][-1]`, `promote["steps"][3]`).
        # A positional index starts passing for the wrong reason the moment a
        # step is inserted ahead of it, and it never expressed the property that
        # matters. Look the steps up by name and assert the ordering instead.
        build_step_names = [step.get("name", "") for step in build["steps"]]
        save = build["steps"][build_step_names.index("Save promotion inputs")]
        self.assertEqual(save["with"]["retention-days"], 7)
        self.assertEqual(save["with"]["if-no-files-found"], "error")
        self.assertTrue(save["with"]["overwrite"] is True)
        self.assertEqual(
            [line.strip() for line in save["with"]["path"].split("\n") if line.strip()],
            [
                "dist/homebrew/Formula/pipelock.rb",
                "dist-chart/pipelock-*.tgz",
                "dist/release-images.json",
            ],
        )
        self.assertLess(
            build_step_names.index("Verify promotion inputs are complete"),
            build_step_names.index("Save promotion inputs"),
        )
        completeness = dict(build_runs)["Verify promotion inputs are complete"]
        for required in (
            "dist/release-images.json",
            "dist-chart -maxdepth 1 -name 'pipelock-*.tgz'",
            "dist/homebrew/Formula/pipelock.rb",
        ):
            self.assertIn(required, completeness)

        promote_step_names = [step.get("name", "") for step in promote["steps"]]
        login = promote_step_names.index("Login to GHCR for promotion")
        self.assertLess(login, promote_step_names.index("Promote verified image manifests"))
        login_step = promote["steps"][login]
        self.assertEqual(
            login_step["uses"],
            "docker/login-action@dbcb813823bdd20940b903addbd779551569679f",
        )
        self.assertEqual(login_step["with"]["registry"], "ghcr.io")
        download = promote_step_names.index("Download promotion inputs")
        for consumer in (
            "Verify release manifest signature before promotion",
            "Verify promotion image inputs",
            "Promote verified image manifests",
            "Publish Helm chart",
            "Publish Homebrew formula",
        ):
            self.assertLess(download, promote_step_names.index(consumer))

        self.assertIn(
            'test "$("$tool_dir/crane" version)" = "${CRANE_VERSION#v}"',
            self.workflow,
        )
        input_checks = dict(promote_runs)["Verify promotion image inputs"]
        self.assertIn("pipelock-release-images-v1", input_checks)
        self.assertIn('git rev-parse "${GITHUB_REF_NAME}^{}"', input_checks)
        self.assertIn("expected 4 Homebrew archive checksums", input_checks)
        self.assertIn("does not match signed release.json", input_checks)

        # Every promotion input is proven present before the first public write,
        # not when the step that consumes it finally runs. A presence check that
        # lives in the consuming step fails with images already promoted.
        self.assertIn("dist/homebrew/Formula/pipelock.rb", input_checks)
        self.assertIn("dist-chart -maxdepth 1 -name 'pipelock-*.tgz'", input_checks)
        self.assertLess(
            promote_step_names.index("Verify promotion image inputs"),
            promote_step_names.index("Promote verified image manifests"),
        )
        expected_outputs = {
            "pipelock_index": "pipelock_index",
            "pipelock_init_index": "pipelock_init_index",
            "license_service_index": "license_service_index",
            "pipelock_amd64": "pipelock_amd64",
            "pipelock_arm64": "pipelock_arm64",
            "pipelock_init_amd64": "pipelock_init_amd64",
            "pipelock_init_arm64": "pipelock_init_arm64",
            "license_service_amd64": "license_service_amd64",
            "license_service_arm64": "license_service_arm64",
        }
        self.assertEqual(
            build["outputs"],
            {
                output: f"${{{{ steps.platform-digests.outputs.{step_output} }}}}"
                for output, step_output in expected_outputs.items()
            },
        )
        for output in expected_outputs:
            self.assertIn(f"needs.release-build.outputs.{output}", self.workflow)
        for digest_name in (
            "PIPELOCK_AMD64_DIGEST",
            "PIPELOCK_ARM64_DIGEST",
            "PIPELOCK_INIT_AMD64_DIGEST",
            "PIPELOCK_INIT_ARM64_DIGEST",
            "LICENSE_SERVICE_AMD64_DIGEST",
            "LICENSE_SERVICE_ARM64_DIGEST",
        ):
            self.assertIn(digest_name, input_checks)
        self.assertIn("^sha256:[a-f0-9]{64}$", input_checks)

        undraft_cmd = 'gh release edit "$GITHUB_REF_NAME" --draft=false'
        verify_cmd = "go run ./cmd/pipelock-release-manifest --verify --manifest"
        promotion_steps = [
            script
            for name, script in promote_runs
            if name == "Reverify the release manifest signature and publish"
        ]
        self.assertEqual(len(promotion_steps), 1, "expected exactly one promotion step")
        promotion_lines = self._executable_lines(promotion_steps[0])

        # The release must leave draft in exactly one place. An undraft anywhere
        # else could publish before verification while a check scoped to this
        # step still passed.
        undrafting_steps = [
            name for name, script in promote_runs
            if any(undraft_cmd in line for line in self._executable_lines(script))
        ]
        self.assertEqual(
            undrafting_steps,
            ["Reverify the release manifest signature and publish"],
            f"draft removal must happen only in the promotion step, found {undrafting_steps}",
        )

        # Both commands must EXECUTE here, not merely appear, and the verifier
        # must be able to stop the publish. `... --verify --manifest x || true`
        # starts with the verifier and permits an invalid signature through, so
        # the line is required to be the canonical command exactly: no shell
        # operator, no error suppression, no redirection appended to it.
        canonical_verify = f'{verify_cmd} "$verify_dir/release.json"'
        verify_at = [i for i, line in enumerate(promotion_lines) if canonical_verify in line]
        undraft_at = [i for i, line in enumerate(promotion_lines) if undraft_cmd in line]
        self.assertEqual(len(verify_at), 1, "promotion step must run the verifier exactly once")
        self.assertEqual(len(undraft_at), 1, "promotion step must undraft exactly once")
        for i in verify_at + undraft_at:
            self.assertNotRegex(
                promotion_lines[i],
                r"(\|\||&&|;|\||>|<|\btrue\b)",
                f"release-gating command must fail closed, found: {promotion_lines[i]}",
            )
        self.assertEqual(promotion_lines[verify_at[0]], canonical_verify)
        self.assertEqual(promotion_lines[undraft_at[0]], undraft_cmd)
        self.assertLess(verify_at[0], undraft_at[0])
        self.assertNotIn("- name: Publish GitHub release", self.workflow)

        # The same fail-closed treatment for the PRE-promotion gate. Only the
        # publish step was checked this way, so `--verify ... || true` in the
        # first gate would have passed every assertion in this file while
        # letting an unverifiable manifest reach the image promotion below it.
        prepromotion_steps = [
            script
            for name, script in promote_runs
            if name == "Verify release manifest signature before promotion"
        ]
        self.assertEqual(len(prepromotion_steps), 1, "expected one pre-promotion gate")
        prepromotion_lines = self._executable_lines(prepromotion_steps[0])
        pre_verify_at = [
            i for i, line in enumerate(prepromotion_lines) if canonical_verify in line
        ]
        self.assertEqual(
            len(pre_verify_at), 1, "pre-promotion gate must run the verifier exactly once"
        )
        self.assertEqual(prepromotion_lines[pre_verify_at[0]], canonical_verify)

        # A good signature over the WRONG release still verifies: the verifier
        # checks the signature and the keyring, never which release the manifest
        # describes. Signing is offline and manual, so both gates must bind the
        # verified manifest to the tag and commit being promoted.
        tag_bind = 'test "$manifest_tag" = "$GITHUB_REF_NAME" || {'
        commit_bind = (
            'test "$manifest_commit" = "$(git rev-parse "${GITHUB_REF_NAME}^{}")" || {'
        )
        for gate in (
            "Verify release manifest signature before promotion",
            "Reverify the release manifest signature and publish",
        ):
            lines = self._executable_lines(dict(promote_runs)[gate])
            self.assertIn('manifest_tag="$(jq -r .tag "$verify_dir/release.json")"', lines)
            self.assertIn(
                'manifest_commit="$(jq -r .commit "$verify_dir/release.json")"', lines
            )
            self.assertIn(tag_bind, lines)
            self.assertIn(commit_bind, lines)

        # In the publish step the binding has to sit between the verification and
        # the undraft, or the release goes public before anything checked that
        # the signed manifest belongs to this tag.
        tag_bind_at = [i for i, line in enumerate(promotion_lines) if line == tag_bind]
        self.assertEqual(len(tag_bind_at), 1)
        self.assertLess(verify_at[0], tag_bind_at[0])
        self.assertLess(tag_bind_at[0], undraft_at[0])

        self.assertIn('release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{}")"', self.workflow)
        self.assertNotIn('-commit "$GITHUB_SHA"', self.workflow)
        self.assertIn('steps.attest-release-images.outcome != \'success\'', self.workflow)
        self.assertIn('diff -ru "$candidate_dir/pipelock" "$existing_dir/pipelock"', self.workflow)
        self.assertIn(
            'cmp -s "$chart_archive" "$existing_dir/pipelock-${chart_version}.tgz"',
            self.workflow,
        )
        self.assertIn('test "$chart_app_version" = "$app_version"', self.workflow)
        homebrew = dict(promote_runs)["Publish Homebrew formula"]
        self.assertIn("git ls-remote --tags --refs origin 'refs/tags/v*'", homebrew)
        self.assertIn('if [[ "$version" != "$newest_stable" ]]; then', homebrew)
        self.assertLess(
            homebrew.index('if [[ "$version" != "$newest_stable" ]]; then'),
            homebrew.index("gh api --method PUT"),
        )
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
