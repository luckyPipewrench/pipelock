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

import copy
import re
import unittest
from pathlib import Path

import yaml

from scripts.chart_changes_version import changes_appversion


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/release.yaml"
GORELEASER = ROOT / ".goreleaser.yaml"
RUNTIME_DOCKERFILES = (ROOT / "Dockerfile", ROOT / "Dockerfile.goreleaser")
CHART = ROOT / "charts/pipelock/Chart.yaml"
MANUAL_CHART_WORKFLOW = ROOT / ".github/workflows/publish-chart.yaml"
WORKFLOWS_DIR = ROOT / ".github/workflows"

GORELEASER_VERSION = "v2.15.4"
GORELEASER_LINUX_AMD64_SHA256 = "aae00c71a4a6d55e08cce9273a1516bdce33c1e07cffb7e502fa6fec4377dede"
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
    def test_scratch_images_use_a_non_go_init(self) -> None:
        """Keep the published binary out of PID 1 in a new PID namespace."""
        expected_tini_copies = {
            "Dockerfile": "COPY --from=builder /sbin/tini-static /sbin/tini-static",
            "Dockerfile.goreleaser": "COPY --from=certs /sbin/tini-static /sbin/tini-static",
        }
        for dockerfile in RUNTIME_DOCKERFILES:
            with self.subTest(dockerfile=dockerfile.name):
                source = dockerfile.read_text(encoding="utf-8")
                self.assertIn("tini-static=0.19.0-r3", source)
                self.assertIn(expected_tini_copies[dockerfile.name], source)
                self.assertIn("/sbin/tini-static", source)
                self.assertIn(
                    'ENTRYPOINT ["/sbin/tini-static", "--", "/pipelock"]', source
                )

    def test_chart_has_no_branch_selectable_manual_publisher(self) -> None:
        self.assertFalse(
            MANUAL_CHART_WORKFLOW.exists(),
            "chart publication must stay in the tag release path; a manual workflow can run branch-selected code",
        )

    def test_tap_preflight_is_not_manually_dispatched(self) -> None:
        document = load_workflow(WORKFLOWS_DIR / "homebrew-tap-preflight.yaml")
        events = workflow_events(document)
        self.assertIn("schedule", events)
        self.assertNotIn(
            "workflow_dispatch",
            events,
            "a manual run would let the selected branch receive the tap credential",
        )
        self.assertNotIn(
            "pull_request",
            events,
            "a pull request would let the head branch receive the tap credential",
        )
        self.assertNotIn(
            "pull_request_target",
            events,
            "a pull request would let the head branch receive the tap credential",
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
                texts = [
                    str(value)
                    for block in (step.get("env") or {}, step.get("with") or {})
                    for value in block.values()
                ]
                run = step.get("run")
                if run is not None:
                    texts.append(str(run))
                if any("HOMEBREW_TAP_TOKEN" in text for text in texts):
                    holders.append((job_name, step.get("name", "")))
        self.assertEqual(
            holders,
            [
                ("release-publish", "Preflight Homebrew tap credential"),
                ("release-publish", "Publish Homebrew formula"),
            ],
        )

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

    def _assert_attestation_contract(self, parsed: dict) -> None:
        """Discover producers; the next named boundary owns their completion."""
        boundaries = {
            "release-build": [
                "Verify attestation",
                "Verify Kubernetes image digest bundle attestation",
            ],
            "release-attest-chart": ["Verify Helm chart attestation"],
        }
        required = {
            "Verify attestation": {
                *ARCHIVE_ATTESTATION_IDS, *INDEX_ATTESTATION_IDS, *IMAGE_SBOM_ATTESTATION_IDS,
                *(f"attest-{name}-{arch}" for name in ATTESTATION_NAMES.values()
                  for arch in ("amd64", "arm64")),
            },
            "Verify Kubernetes image digest bundle attestation": {"attest-release-images"},
            "Verify Helm chart attestation": {"attest-helm-chart"},
        }
        for job_name in boundaries:
            self.assertIn(job_name, parsed["jobs"])
        for job_name, job in parsed["jobs"].items():
            steps = job.get("steps", [])
            ids = [step["id"] for step in steps if "id" in step]
            self.assertTrue(all(isinstance(value, str) and re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_-]*", value) for value in ids), "invalid step ID")
            self.assertEqual(len(ids), len(set(ids)), "duplicate step ID")
            producers = [i for i, step in enumerate(steps)
                         if str(step.get("uses", "")).split("@", 1)[0].lower().startswith("actions/attest")]
            if job_name not in boundaries:
                self.assertFalse(producers, "attestation producer in an unguarded job")
                continue
            self.assertIs(job.get("continue-on-error", False), False)
            previous = -1
            covered = set()
            for name in boundaries[job_name]:
                positions = [i for i, step in enumerate(steps) if step.get("name") == name]
                self.assertEqual(len(positions), 1, f"expected one {name} boundary")
                position = positions[0]
                self.assertGreater(position, previous, "reordered completion boundaries")
                group = [i for i in producers if previous < i < position]
                self.assertTrue(group, "empty completion boundary")
                expected = []
                for i in group:
                    producer = steps[i]
                    self.assertIn("id", producer, "producer needs an ID")
                    self.assertIs(producer.get("continue-on-error"), True)
                    action = str(producer["uses"]).partition("@")[0].lower()
                    self._assert_action_pin(producer, action)
                    expected.append(producer["id"])
                self.assertTrue(required[name].issubset(expected),
                                "required subject moved or removed from its boundary")
                gate = steps[position]
                self.assertIs(gate.get("continue-on-error", False), False)
                # Step settings override job defaults, which override workflow
                # defaults. A custom shell can ignore even a failing run body.
                workflow_shell = parsed.get("defaults", {}).get("run", {}).get("shell")
                job_shell = job.get("defaults", {}).get("run", {}).get("shell", workflow_shell)
                shell = gate.get("shell", job_shell)
                if shell is None:
                    self.assertRegex(str(job.get("runs-on", "")), r"^ubuntu-(latest|[0-9]+\.[0-9]+)(-arm)?$",
                                     "implicit gate shell requires an Ubuntu runner")
                else:
                    self.assertIn(shell, ("bash", "sh"), "completion gate must use bash or sh")
                # Environment settings use the same most-specific precedence.
                # Startup hooks must not replace the gate's executable body.
                environment = {
                    **parsed.get("env", {}), **job.get("env", {}), **gate.get("env", {}),
                }
                for variable in ("BASH_ENV", "ENV"):
                    self.assertEqual(environment.get(variable, ""), "",
                                     "completion gate must not configure shell startup hooks")
                condition = " ".join(gate.get("if", "").split())
                if condition.startswith("${{") and condition.endswith("}}"):
                    condition = condition[3:-2].strip()
                # Accept only this small grammar, never evaluate GitHub expressions.
                match = re.fullmatch(r"\s*always\(\s*\)\s*&&\s*(.*?)\s*", condition)
                self.assertIsNotNone(match, "completion gate must always run")
                terms = match.group(1)
                if terms.startswith("(") and terms.endswith(")"):
                    terms = terms[1:-1]
                elif "||" in terms:
                    self.fail("OR outcomes must be grouped after always()")
                found = []
                for term in terms.split("||"):
                    outcome = re.fullmatch(
                        r"\s*steps\.([A-Za-z_][A-Za-z0-9_-]*)\.outcome\s*!=\s*'success'\s*", term)
                    self.assertIsNotNone(outcome, "only non-success outcomes may select the gate")
                    found.append(outcome.group(1))
                self.assertCountEqual(found, expected, "gate must cover exactly its producers")
                self._assert_attestation_gate_body(gate)
                covered.update(group)
                previous = position
            self.assertEqual(covered, set(producers), "producer after final completion gate")
        self._assert_required_attestation_subjects(parsed)

    def _assert_required_attestation_subjects(self, parsed: dict) -> None:
        # Independent expected subjects prevent discovery shrinking on deletion.
        expected = {
            "attest-binaries": {"subject-path": "dist/pipelock_*.tar.gz"},
            "attest-checksums": {"subject-path": "dist/checksums.txt"},
            "attest-sbom": {"subject-path": "dist/pipelock_*.tar.gz", "sbom-path": "sbom.cdx.json"},
            "attest-release-images": {"subject-path": "dist/release-images.json"},
            "attest-helm-chart": {
                "subject-name": "ghcr.io/luckypipewrench/charts/pipelock",
                "subject-digest": "${{ needs.release-promote.outputs.chart_digest }}",
            },
        }
        for name, repository in PLATFORM_ARTIFACTS.items():
            for suffix, output in [("container", "index"), ("amd64", "amd64"), ("arm64", "arm64")]:
                identifier = f"attest-{ATTESTATION_NAMES[name]}-{suffix}"
                inputs = {
                    "subject-name": repository,
                    "subject-digest": "${{ steps.platform-digests.outputs." + f"{name}_{output}" + " }}",
                    "push-to-registry": True,
                }
                expected[identifier] = inputs
                if suffix != "container":
                    expected[identifier + "-sbom"] = {
                        **inputs,
                        "sbom-path": f"sbom-{repository.rsplit('/', 1)[-1]}-linux-{suffix}.cdx.json",
                    }
        for identifier, inputs in expected.items():
            # GitHub's steps context belongs to one job; another job may reuse
            # an ID without replacing this producer or its outcome.
            job_name = "release-attest-chart" if identifier == "attest-helm-chart" else "release-build"
            steps = {step["id"]: step for step in parsed["jobs"][job_name]["steps"] if "id" in step}
            self.assertIn(identifier, steps, "required attestation subject removed")
            step = steps[identifier]
            # The action identity and SHA pinning are fixed; the pinned commit
            # is not, so a routine dependency bump of the action stays green.
            action = "actions/attest-sbom" if "sbom-path" in inputs else "actions/attest-build-provenance"
            self._assert_action_pin(step, action)
            self.assertEqual(step.get("with"), inputs)

    def _assert_action_pin(self, step: dict, action: str) -> None:
        name, _, ref = str(step.get("uses", "")).partition("@")
        self.assertEqual(name.lower(), action)
        self.assertRegex(ref, r"^[0-9a-fA-F]{40}$", "action must be pinned to a commit SHA")

    def test_every_attestation_dependency_is_fail_closed(self) -> None:
        self._assert_attestation_contract(yaml.safe_load(self.workflow))

    def _assert_attestation_gate_body(self, gate: dict) -> None:
        # The condition alone proves nothing if the step it guards succeeds:
        # the gate's executable body must end the job with a nonzero exit.
        gate_lines = self._executable_lines(gate["run"])
        self.assertEqual(gate_lines[-1], "exit 1")
        # No path through the gate may leave successfully. Every `exit`
        # anywhere in a line (after `&&`, `;`, inside `if ... fi`) must carry
        # a literal nonzero status: `exit 0`, a bare `exit` and a computed
        # status such as `exit "$?"` can all return success. Quotes and
        # backslashes are dropped first so `'exit' 0` or `\exit 0` is still
        # seen, and the status must be 1-255 because the shell takes it
        # modulo 256 (`exit 256` succeeds). Backslash-continued lines are
        # joined first, as the shell does, so `exi\` + `t 0` is one command.
        # This guards against an accidental edit to the gate, not a
        # determined attempt to hide a successful exit from a regex.
        exit_command = re.compile(r"(?:^|[;&|({\s])exit\b\s*([^\s;&|)}#]*)")
        commands = re.sub(r"\\\n", "", gate["run"]).splitlines()
        not_failing = [
            line for line in self._executable_lines("\n".join(commands))
            for status in exit_command.findall(re.sub(r"['\"\\]", "", line))
            if not (re.fullmatch(r"[1-9][0-9]{0,2}", status) and int(status) <= 255)
        ]
        self.assertFalse(not_failing)

    def test_attestation_contract_rejects_mutations(self) -> None:
        original = yaml.safe_load(self.workflow)
        # Mutate actual workflow structure, not a second model of the checker.
        for label in (
            "uncovered producer", "dropped producer", "missing ID", "blank ID",
            "duplicate producer ID", "nonproducer ID collision", "after gate",
            "wrong job", "missing term", "failure only", "missing always",
            "ungrouped OR", "bypass OR", "duplicate term", "gate suppression",
            "job suppression", "producer suppression", "successful body",
            "early successful exit", "subject miswire", "digest miswire", "SBOM miswire",
            "bundle successful body", "chart successful body", "reordered gates",
            "removed action", "dropped producer and term", "bundle missing always",
            "chart job suppression", "chart gate suppression",
            "subject moved with coverage", "mixed-case uncovered producer",
            "wrong action", "unpinned action", "wrapped failure only",
            "wrapped bypass OR", "malformed wrapper",
        ):
            with self.subTest(mutation=label):
                parsed = copy.deepcopy(original)
                job = parsed["jobs"]["release-build"]
                steps = job["steps"]
                producer = next(step for step in steps if step.get("id") == "attest-binaries")
                gate = next(step for step in steps if step.get("name") == "Verify attestation")
                bundle = next(step for step in steps if step.get("name") ==
                              "Verify Kubernetes image digest bundle attestation")
                chart_job = parsed["jobs"]["release-attest-chart"]
                chart_gate = chart_job["steps"][-1]
                extra = {**copy.deepcopy(producer), "id": "attest-extra"}
                if label == "uncovered producer":
                    steps.insert(steps.index(gate), extra)
                elif label in ("dropped producer", "dropped producer and term"):
                    steps.remove(producer)
                    if label.endswith("and term"):
                        gate["if"] = gate["if"].replace("steps.attest-binaries.outcome != 'success' ||", "")
                elif label == "missing ID":
                    del producer["id"]
                elif label == "blank ID":
                    producer["id"] = ""
                elif label == "duplicate producer ID":
                    steps.insert(steps.index(gate), copy.deepcopy(producer))
                elif label == "nonproducer ID collision":
                    steps.insert(0, {"id": producer["id"], "run": "echo duplicate"})
                elif label == "after gate":
                    steps.append(extra)
                elif label == "wrong job":
                    parsed["jobs"]["release-publish"]["steps"].append(extra)
                elif label == "missing term":
                    gate["if"] = gate["if"].replace("steps.attest-binaries.outcome != 'success' ||", "")
                elif label == "failure only":
                    gate["if"] = gate["if"].replace("!= 'success'", "== 'failure'")
                elif label == "missing always":
                    gate["if"] = gate["if"].replace("always() &&", "")
                elif label == "ungrouped OR":
                    gate["if"] = gate["if"].replace("&& (", "&& ").rstrip().removesuffix(")")
                elif label == "bypass OR":
                    gate["if"] += " || true"
                elif label == "duplicate term":
                    gate["if"] = gate["if"].replace("&& (", "&& (steps.attest-binaries.outcome != 'success' ||")
                elif label == "gate suppression":
                    gate["continue-on-error"] = True
                elif label == "job suppression":
                    job["continue-on-error"] = True
                elif label == "producer suppression":
                    producer["continue-on-error"] = False
                elif label == "successful body":
                    gate["run"] = "echo failure\nexit 0"
                elif label == "early successful exit":
                    gate["run"] = "exit 0\nexit 1"
                elif label == "subject miswire":
                    producer["with"]["subject-path"] = "dist/wrong.txt"
                elif label == "digest miswire":
                    next(step for step in steps if step.get("id") == "attest-pipelock-amd64")["with"]["subject-digest"] = "wrong"
                elif label == "SBOM miswire":
                    next(step for step in steps if step.get("id") == "attest-sbom")["with"]["sbom-path"] = "wrong"
                elif label == "bundle successful body":
                    bundle["run"] = "exit 0"
                elif label == "chart successful body":
                    chart_gate["run"] = "exit 0"
                elif label == "reordered gates":
                    steps.remove(bundle)
                    steps.insert(steps.index(gate), bundle)
                elif label == "removed action":
                    producer["uses"] = "actions/checkout@different"
                elif label == "bundle missing always":
                    bundle["if"] = "steps.attest-release-images.outcome != 'success'"
                elif label == "chart job suppression":
                    chart_job["continue-on-error"] = True
                elif label == "subject moved with coverage":
                    steps.remove(producer)
                    steps.insert(steps.index(bundle), producer)
                    gate["if"] = gate["if"].replace("steps.attest-binaries.outcome != 'success' ||", "")
                    bundle["if"] = "always() && (steps.attest-release-images.outcome != 'success' || steps.attest-binaries.outcome != 'success')"
                elif label == "chart gate suppression":
                    chart_gate["continue-on-error"] = True
                elif label == "mixed-case uncovered producer":
                    extra["uses"] = extra["uses"].replace("actions/attest", "Actions/Attest")
                    steps.insert(steps.index(gate), extra)
                elif label == "wrong action":
                    producer["uses"] = next(
                        step for step in steps if step.get("id") == "attest-sbom")["uses"]
                elif label == "unpinned action":
                    producer["uses"] = "actions/attest-build-provenance@v4"
                elif label == "wrapped failure only":
                    gate["if"] = "${{ " + gate["if"].replace("!= 'success'", "== 'failure'") + " }}"
                elif label == "wrapped bypass OR":
                    gate["if"] = "${{ " + gate["if"] + " || true }}"
                elif label == "malformed wrapper":
                    gate["if"] = "${{ " + gate["if"] + " }"
                with self.assertRaises(AssertionError):
                    self._assert_attestation_contract(parsed)

    def test_attestation_contract_accepts_ids_reused_by_another_job(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        parsed["jobs"]["release-publish"]["steps"].append({
            "id": "attest-binaries", "run": "echo unrelated step",
        })
        self._assert_attestation_contract(parsed)

    def test_attestation_contract_checks_effective_gate_shell(self) -> None:
        original = yaml.safe_load(self.workflow)
        for job_name, gate_name in (
            ("release-build", "Verify attestation"),
            ("release-build", "Verify Kubernetes image digest bundle attestation"),
            ("release-attest-chart", "Verify Helm chart attestation"),
        ):
            for scope in ("step", "job", "workflow"):
                for shell in ("bash", "sh", "true {0}"):
                    with self.subTest(boundary=gate_name, scope=scope, shell=shell):
                        parsed = copy.deepcopy(original)
                        job = parsed["jobs"][job_name]
                        gate = next(step for step in job["steps"] if step.get("name") == gate_name)
                        if scope == "step":
                            gate["shell"] = shell
                        else:
                            owner = job if scope == "job" else parsed
                            owner["defaults"] = {"run": {"shell": shell}}
                        if shell == "true {0}":
                            with self.assertRaisesRegex(AssertionError, "must use bash or sh"):
                                self._assert_attestation_contract(parsed)
                        else:
                            self._assert_attestation_contract(parsed)
        parsed = copy.deepcopy(original)
        parsed["jobs"]["release-build"]["runs-on"] = "windows-latest"
        with self.assertRaisesRegex(AssertionError, "implicit gate shell"):
            self._assert_attestation_contract(parsed)

    def test_attestation_gate_shell_overrides_follow_workflow_precedence(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        parsed["defaults"] = {"run": {"shell": "true {0}"}}
        for job in parsed["jobs"].values():
            job["defaults"] = {"run": {"shell": "bash"}}
        self._assert_attestation_contract(parsed)
        for job in parsed["jobs"].values():
            job["defaults"] = {"run": {"shell": "true {0}"}}
            for step in job.get("steps", []):
                if step.get("name", "").startswith("Verify"):
                    step["shell"] = "sh"
        self._assert_attestation_contract(parsed)

    def test_attestation_contract_checks_effective_gate_environment(self) -> None:
        original = yaml.safe_load(self.workflow)
        for job_name, gate_name in (
            ("release-build", "Verify attestation"),
            ("release-build", "Verify Kubernetes image digest bundle attestation"),
            ("release-attest-chart", "Verify Helm chart attestation"),
        ):
            for scope in ("step", "job", "workflow"):
                for variable in ("BASH_ENV", "ENV"):
                    for value in ("startup.sh", "${{ github.workspace }}/startup.sh", ""):
                        with self.subTest(boundary=gate_name, scope=scope,
                                          variable=variable, value=value):
                            parsed = copy.deepcopy(original)
                            job = parsed["jobs"][job_name]
                            gate = next(step for step in job["steps"] if step.get("name") == gate_name)
                            owner = gate if scope == "step" else job if scope == "job" else parsed
                            owner.setdefault("env", {})[variable] = value
                            if value:
                                with self.assertRaisesRegex(AssertionError, "shell startup hooks"):
                                    self._assert_attestation_contract(parsed)
                            else:
                                self._assert_attestation_contract(parsed)

    def test_attestation_gate_environment_overrides_follow_workflow_precedence(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        parsed.setdefault("env", {}).update({"BASH_ENV": "startup.sh", "ENV": "startup.sh"})
        for job in parsed["jobs"].values():
            job.setdefault("env", {}).update({"BASH_ENV": "", "ENV": ""})
        self._assert_attestation_contract(parsed)
        for job in parsed["jobs"].values():
            job["env"].update({"BASH_ENV": "startup.sh", "ENV": "startup.sh"})
            for step in job.get("steps", []):
                if step.get("name", "").startswith("Verify"):
                    step.setdefault("env", {}).update({"BASH_ENV": "", "ENV": ""})
        self._assert_attestation_contract(parsed)
        parsed = yaml.safe_load(self.workflow)
        parsed.setdefault("env", {})["RELEASE_LABEL"] = "v1.2.3"
        self._assert_attestation_contract(parsed)

    def test_attestation_contract_accepts_action_pin_bumps(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        for job in parsed["jobs"].values():
            for step in job.get("steps", []):
                action, _, _ = str(step.get("uses", "")).partition("@")
                if action.startswith("actions/attest"):
                    step["uses"] = f"{action}@{'0' * 40}"
        self._assert_attestation_contract(parsed)

    def test_attestation_contract_accepts_expression_wrappers_and_action_case(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        for job in parsed["jobs"].values():
            for step in job.get("steps", []):
                if str(step.get("uses", "")).startswith("actions/attest"):
                    step["uses"] = step["uses"].upper()
                if step.get("name", "").startswith("Verify") and "always() &&" in step.get("if", ""):
                    step["if"] = "${{ " + step["if"].strip() + " }}"
        self._assert_attestation_contract(parsed)

    def test_action_pins_accept_updates_and_reject_floating_or_wrong_actions(self) -> None:
        for action in ("actions/attest-build-provenance", "actions/attest-sbom", "docker/login-action"):
            with self.subTest(action=action):
                self._assert_action_pin({"uses": f"{action}@{'a' * 40}"}, action)
                for uses in (f"{action}@v4", f"{action}@{'a' * 39}", f"actions/checkout@{'a' * 40}"):
                    with self.subTest(uses=uses), self.assertRaises(AssertionError):
                        self._assert_action_pin({"uses": uses}, action)

    def test_attestation_contract_accepts_added_covered_producers(self) -> None:
        original = yaml.safe_load(self.workflow)
        for job_name, gate_name in (
            ("release-build", "Verify attestation"),
            ("release-build", "Verify Kubernetes image digest bundle attestation"),
            ("release-attest-chart", "Verify Helm chart attestation"),
        ):
            with self.subTest(boundary=gate_name):
                parsed = copy.deepcopy(original)
                steps = parsed["jobs"][job_name]["steps"]
                gate = next(step for step in steps if step.get("name") == gate_name)
                producer = {
                    "id": "attest-extra", "uses": f"actions/attest-build-provenance@{'b' * 40}",
                    "continue-on-error": True, "with": {"subject-path": "dist/extra.txt"},
                }
                steps.insert(steps.index(gate), producer)
                outcomes = gate["if"].split("&&", 1)[1].strip().strip("()")
                gate["if"] = "always() && (" + outcomes + " || steps.attest-extra.outcome != 'success')"
                self._assert_attestation_contract(parsed)
                for ref in ("v4", "future", "b" * 39, ""):
                    with self.subTest(unpinned_ref=ref):
                        producer["uses"] = "actions/attest-build-provenance" + (f"@{ref}" if ref else "")
                        with self.assertRaisesRegex(AssertionError, "pinned to a commit SHA"):
                            self._assert_attestation_contract(parsed)

    def test_attestation_contract_accepts_whitespace_and_term_reordering(self) -> None:
        parsed = yaml.safe_load(self.workflow)
        for job in parsed["jobs"].values():
            for gate in job.get("steps", []):
                if gate.get("name", "").startswith("Verify") and "always() &&" in gate.get("if", ""):
                    outcomes = gate["if"].split("&&", 1)[1].strip().strip("()")
                    terms = outcomes.split("||")
                    gate["if"] = "  always( )  && (\n" + " ||\n".join(reversed(terms)) + "\n) "
        self._assert_attestation_contract(parsed)

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
        publish_job_runs = self._job_runs("release-publish")
        self.assertIn("git ls-remote --tags --refs origin 'refs/tags/v*'", image_promotion)
        self.assertNotIn("printf '%s\\n%s\\n' \"$tags\" \"$version\"", image_promotion)
        floating_steps = [
            script
            for name, script in publish_job_runs
            if name == "Update floating major tag for GitHub Action"
        ]
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
        publish = parsed["jobs"]["release-publish"]
        publish_runs = self._job_runs("release-publish")
        # Consumer-facing publishes wait for promotion, attestation, and the
        # digest-verified chart publication; any failure leaves a draft.
        self.assertEqual(publish["needs"], ["release-promote", "release-attest-chart", "release-publish-chart"])
        self.assertNotIn("if", publish, "publish must require both successful dependencies")
        self.assertEqual(publish["permissions"], {"contents": "write"})
        self.assertNotIn("environment", publish)
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
        ):
            self.assertLess(verify, names.index(public_write))
            self.assertLess(inputs_verified, names.index(public_write))
        publish_names = [name for name, _ in publish_runs]
        self.assertEqual(
            publish_names,
            [
                "Verify Go version",
                "Preflight Homebrew tap credential",
                "Publish Homebrew formula",
                "Reverify the release manifest signature and publish",
                "Update floating major tag for GitHub Action",
            ],
        )
        for consumer_write in (
            "Publish Homebrew formula",
            "Reverify the release manifest signature and publish",
            "Update floating major tag for GitHub Action",
        ):
            self.assertNotIn(consumer_write, names)

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
        self._assert_action_pin(login_step, "docker/login-action")
        self.assertEqual(login_step["with"]["registry"], "ghcr.io")
        download = promote_step_names.index("Download promotion inputs")
        for consumer in (
            "Verify release manifest signature before promotion",
            "Verify promotion image inputs",
            "Promote verified image manifests",
            "Stage Helm chart locally",
        ):
            self.assertLess(download, promote_step_names.index(consumer))
        publish_step_names = [step.get("name", "") for step in publish["steps"]]
        self.assertLess(
            publish_step_names.index("Download promotion inputs"),
            publish_step_names.index("Publish Homebrew formula"),
        )

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
            for name, script in publish_runs
            if name == "Reverify the release manifest signature and publish"
        ]
        self.assertEqual(len(promotion_steps), 1, "expected exactly one promotion step")
        promotion_lines = self._executable_lines(promotion_steps[0])

        # The release must leave draft in exactly one place. An undraft anywhere
        # else could publish before verification while a check scoped to this
        # step still passed.
        undrafting_steps = [
            (job_name, name)
            for job_name in parsed["jobs"]
            for name, script in self._job_runs(job_name)
            if any(undraft_cmd in line for line in self._executable_lines(script))
        ]
        self.assertEqual(
            undrafting_steps,
            [("release-publish", "Reverify the release manifest signature and publish")],
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
        for job_runs, gate in (
            (promote_runs, "Verify release manifest signature before promotion"),
            (publish_runs, "Reverify the release manifest signature and publish"),
        ):
            gate_steps = [script for name, script in job_runs if name == gate]
            self.assertEqual(len(gate_steps), 1, f"expected one {gate} step")
            lines = self._executable_lines(gate_steps[0])
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
        self._assert_attestation_contract(parsed)
        self.assertIn('diff -ru "$candidate_dir/pipelock" "$existing_dir/pipelock"', self.workflow)
        self.assertIn(
            'cmp -s "$chart_archive" "$existing_dir/pipelock-${chart_version}.tgz"',
            self.workflow,
        )
        self.assertIn('test "$chart_app_version" = "$app_version"', self.workflow)
        homebrew = dict(publish_runs)["Publish Homebrew formula"]
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

    def test_helm_chart_attestation_is_confined_and_fail_closed(self) -> None:
        """The chart is attested by digest in a job that holds the signing
        permissions only for GitHub's first-party attestation action."""
        parsed = yaml.safe_load(WORKFLOW.read_text())
        promote = parsed["jobs"]["release-promote"]
        self.assertNotIn("id-token", promote["permissions"])
        self.assertNotIn("attestations", promote["permissions"])
        self.assertEqual(
            promote["outputs"]["chart_digest"],
            "${{ steps.stage-helm-chart.outputs.chart_digest }}",
        )
        stage = next(step for step in promote["steps"] if step.get("id") == "stage-helm-chart")
        self.assertIn("crane registry serve", stage["run"])
        self.assertIn("crane pull --insecure --format=oci", stage["run"])
        self.assertIn('helm push "$chart_archive" oci://127.0.0.1:5000/charts --plain-http', stage["run"])
        self.assertNotIn('helm push "$chart_archive" oci://ghcr.io', stage["run"])
        self.assertNotIn("crane push", stage["run"])
        # The staged digest comes from Helm; a rerun may reuse an existing
        # public digest only after comparing the published archive.
        extract = """awk '$1 == "Digest:" { print $2 }'"""
        self.assertIn(f'printf \'%s\\n\' "$stage_output" | {extract}', stage["run"])
        self.assertIn(f'printf \'%s\\n\' "$chart_lookup_output" | {extract}', stage["run"])
        self.assertIn('cmp -s "$chart_archive" "$existing_dir/pipelock-${chart_version}.tgz"', stage["run"])
        self.assertIn('echo "chart_digest=${chart_digest}" >>"$GITHUB_OUTPUT"', stage["run"])
        saved = next(step for step in promote["steps"] if step.get("name") == "Save staged Helm chart OCI layout")
        self.assertEqual(saved["with"]["name"], "staged-helm-chart-oci")

        attest_job = parsed["jobs"]["release-attest-chart"]
        self.assertEqual(attest_job["needs"], ["release-promote"])
        self.assertEqual(
            attest_job["permissions"],
            {"contents": "read", "id-token": "write", "attestations": "write"},
        )
        self.assertNotIn("continue-on-error", attest_job)
        uses = [step["uses"] for step in attest_job["steps"] if "uses" in step]
        self.assertTrue(uses)
        for action in uses:
            self.assertTrue(
                action.startswith("actions/attest-build-provenance@"),
                f"{action} runs in the job that holds id-token: write",
            )
        attest = next(step for step in attest_job["steps"] if step.get("id") == "attest-helm-chart")
        self.assertEqual(
            attest["with"]["subject-digest"],
            "${{ needs.release-promote.outputs.chart_digest }}",
        )
        self.assertNotIn("push-to-registry", attest["with"])
        self._assert_attestation_contract(parsed)

        chart_publish = parsed["jobs"]["release-publish-chart"]
        self.assertEqual(chart_publish["needs"], ["release-promote", "release-attest-chart"])
        self.assertEqual(chart_publish["permissions"], {"contents": "read", "packages": "write", "attestations": "read"})
        self.assertNotIn("continue-on-error", chart_publish)
        self.assertNotIn("if", chart_publish)
        publish_step = next(step for step in chart_publish["steps"] if step.get("name") == "Publish and verify attested Helm chart")
        self.assertIn('crane push dist-chart-oci "$target"', publish_step["run"])
        self.assertIn('test "$(crane digest "$target")" = "$CHART_DIGEST"', publish_step["run"])
        self.assertIn('gh attestation verify "oci://${target}"', publish_step["run"])
        self.assertIn('helm registry login ghcr.io', publish_step["run"])
        missing_tag = re.search(r"elif grep -qiE '([^']+)'", publish_step["run"])
        self.assertIsNotNone(missing_tag)
        matcher = re.compile(missing_tag.group(1), re.IGNORECASE)
        for error in (
            "GET manifest: MANIFEST_UNKNOWN",
            "GET package: NAME_UNKNOWN",
        ):
            self.assertRegex(error, matcher)
        self.assertNotRegex("HEAD request: unexpected status code 404 Not Found", matcher)
        self.assertNotRegex("DENIED: access to package denied", matcher)
        self.assertEqual(
            publish_step["env"]["CHART_DIGEST"],
            "${{ needs.release-promote.outputs.chart_digest }}",
        )

        # Nothing a consumer reads may move before the attestation succeeds.
        publish_job = parsed["jobs"]["release-publish"]
        self.assertIn("release-attest-chart", publish_job["needs"])
        self.assertIn("release-publish-chart", publish_job["needs"])
        self.assertNotIn("id-token", publish_job["permissions"])
        self.assertNotIn("attestations", publish_job["permissions"])
        for job_name in ("release-promote", "release-attest-chart", "release-publish-chart"):
            script = "\n".join(run for _, run in self._job_runs(job_name))
            for consumer_write in (
                'gh release edit "$GITHUB_REF_NAME" --draft=false',
                "repos/luckyPipewrench/homebrew-tap/contents/",
                'git push origin "$floating_ref"',
            ):
                self.assertNotIn(consumer_write, script, f"{consumer_write} runs in {job_name}")

if __name__ == "__main__":
    unittest.main()
