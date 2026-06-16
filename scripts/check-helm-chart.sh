#!/usr/bin/env bash
set -euo pipefail

chart="charts/pipelock"
render_dir="$(mktemp -d)"
trap 'rm -rf "$render_dir"' EXIT

helm lint "$chart"

helm template pipelock "$chart" >"$render_dir/default.yaml"

for values in "$chart"/examples/*.yaml; do
  name="$(basename "$values" .yaml)"
  helm lint "$chart" -f "$values"
  helm template pipelock "$chart" -f "$values" >"$render_dir/$name.yaml"
done

expect_template_error() {
  local want="$1"
  shift
  local out="$render_dir/negative.out"
  if helm template pipelock "$chart" "$@" >"$out" 2>&1; then
    echo "helm template unexpectedly succeeded for negative case: $want" >&2
    exit 1
  fi
  if ! grep -q "$want" "$out"; then
    echo "helm template negative case did not include expected error: $want" >&2
    cat "$out" >&2
    exit 1
  fi
}

expect_template_error "/image/tag" \
  --set image.tag="@sha256:e8e249d2dd1b579f995f0f5a75cfab13fb8505a8ffc33c2cec7a6418290d9098"

expect_template_error "/image/tag" \
  --set image.tag="sha256:e8e249d2dd1b579f995f0f5a75cfab13fb8505a8ffc33c2cec7a6418290d9098"

expect_template_error "/image/digest" \
  --set image.digest="not-a-digest"

expect_template_error "/image/digest" \
  --set image.digest="sha256:e8e249d2dd1b579f995f0f5a75cfab13fb8505a8ffc33c2cec7a6418290d909Z"

expect_template_error "conductorFollower.conductorURL is required" \
  --set conductorFollower.enabled=true

expect_template_error "enterprise modes require explicit networkPolicy.ingress and networkPolicy.egress rules" \
  --set mode=conductor \
  --set networkPolicy.enabled=true \
  --set networkPolicy.ingress=null \
  --set networkPolicy.egress=null

expect_template_error "conductor.replicaCount must be 1 when conductor.persistence.accessModes includes ReadWriteOnce" \
  -f "$chart/examples/values-enterprise-conductor.yaml" \
  --set conductor.replicaCount=2

expect_template_error "fleetSink.replicaCount must be 1 when fleetSink.persistence.accessModes includes ReadWriteOnce" \
  -f "$chart/examples/values-enterprise-devfleet.yaml" \
  --set fleetSink.replicaCount=2

grep -q -- "- run" "$render_dir/default.yaml"
grep -q -- "conductor:" "$render_dir/values-enterprise-follower.yaml"
grep -q -- "pipelock-follower-bundles" "$render_dir/values-enterprise-follower.yaml"
grep -q -- "pipelock-follower-audit-queue" "$render_dir/values-enterprise-follower.yaml"

grep -q -- "- conductor" "$render_dir/values-enterprise-conductor.yaml"
grep -q -- "- serve" "$render_dir/values-enterprise-conductor.yaml"
grep -q -- "--probe-listen" "$render_dir/values-enterprise-conductor.yaml"
grep -q -- "--publisher-token-file" "$render_dir/values-enterprise-conductor.yaml"
grep -q -- "pipelock-conductor-probes" "$render_dir/values-enterprise-conductor.yaml"

grep -q -- "- fleet-sink" "$render_dir/values-enterprise-devfleet.yaml"
grep -q -- "--probe-listen" "$render_dir/values-enterprise-devfleet.yaml"
grep -q -- "--reader-token-file" "$render_dir/values-enterprise-devfleet.yaml"
grep -q -- "pipelock-fleet-sink-probes" "$render_dir/values-enterprise-devfleet.yaml"
grep -q -- "pipelock-fleet-sink-storage" "$render_dir/values-enterprise-devfleet.yaml"

if grep -R "publisher.token:" "$render_dir" >/dev/null; then
  echo "rendered manifests must not contain inline publisher token values" >&2
  exit 1
fi

# Every rendered image reference must be either repo:tag or repo@sha256:...,
# never a malformed combination. This guards UX-001 (a digest concatenated as a
# tag produced ":@sha256:") and the related empty-tag / double-separator shapes.
image_refs="$(grep -RhE '^[[:space:]]*image:[[:space:]]' "$render_dir" | grep -vE '^[[:space:]]*imagePull(Secrets|Policy):' || true)"
if [ -z "$image_refs" ]; then
  echo "no image references found in rendered manifests" >&2
  exit 1
fi
if printf '%s\n' "$image_refs" | grep -E ':@sha256:|@@|: *"[^"]*:" *$|:" *$' >/dev/null; then
  echo "rendered manifests contain a malformed image reference:" >&2
  printf '%s\n' "$image_refs" | grep -E ':@sha256:|@@|: *"[^"]*:" *$|:" *$' >&2
  exit 1
fi

# Digest-pinned examples must render repository@sha256:..., not a tag.
for name in values-enterprise-conductor values-enterprise-follower; do
  if ! grep -q -- 'image: "ghcr.io/luckypipewrench/pipelock@sha256:' "$render_dir/$name.yaml"; then
    echo "$name should render a digest-pinned image (repository@sha256:...)" >&2
    grep -- 'image:' "$render_dir/$name.yaml" >&2
    exit 1
  fi
done

echo "helm chart checks passed"
