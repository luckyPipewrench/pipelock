# Kubernetes image upgrades

Every Pipelock release publishes `release-images.json`. It lists the immutable
manifest digest for each image built from that release commit:

| Bundle entry | Use it for |
| --- | --- |
| `pipelock` | The proxy, Conductor, and `pipelock dashboard serve` workloads |
| `pipelock-init` | Init containers that copy the Pipelock binary into a shared volume |
| `pipelock-license-service` | The separately deployed license service |

The bundle is an upgrade input, not a signature. Verify the release's image
provenance before applying it, then keep the exact file with the change that
updates your cluster.

## Get the exact image set

This downloads the immutable image set for v3.5.0 into the current directory.
Replace the version only after selecting a released version.

```bash
mkdir -p pipelock-v3.5.0
gh release download v3.5.0 --repo luckyPipewrench/pipelock --pattern release-images.json --dir pipelock-v3.5.0
cat pipelock-v3.5.0/release-images.json
```

Verify the bundle before you use an image from it. This checks the selected
release tag against the remote repository, verifies the bundle attestation, and
then verifies the main Pipelock image named in the bundle. It requires a current
GitHub CLI login and registry access when the image is not public:

```bash
PIPELOCK_RELEASE=v3.5.0
PIPELOCK_BUNDLE="pipelock-${PIPELOCK_RELEASE}/release-images.json"
PIPELOCK_COMMIT="$(git ls-remote https://github.com/luckyPipewrench/pipelock.git \
  "refs/tags/${PIPELOCK_RELEASE}" "refs/tags/${PIPELOCK_RELEASE}^{}" \
  | awk '$2 ~ /\^\{\}$/ { peeled = $1 } $2 !~ /\^\{\}$/ { direct = $1 } END { print peeled ? peeled : direct }')"
test -n "$PIPELOCK_COMMIT"

gh attestation verify "$PIPELOCK_BUNDLE" \
  --repo luckyPipewrench/pipelock \
  --signer-workflow luckyPipewrench/pipelock/.github/workflows/release.yaml \
  --source-ref "refs/tags/${PIPELOCK_RELEASE}" \
  --source-digest "$PIPELOCK_COMMIT" \
  --deny-self-hosted-runners

jq -e --arg tag "$PIPELOCK_RELEASE" --arg commit "$PIPELOCK_COMMIT" \
  '.schema == "pipelock-release-images-v1" and .tag == $tag and .commit == $commit' \
  "$PIPELOCK_BUNDLE" >/dev/null

PIPELOCK_IMAGE="$(jq -er '.images[] | select(.name == "pipelock") | "\(.repository)@\(.digest)"' "$PIPELOCK_BUNDLE")"
gh attestation verify "oci://${PIPELOCK_IMAGE}" \
  --repo luckyPipewrench/pipelock \
  --signer-workflow luckyPipewrench/pipelock/.github/workflows/release.yaml \
  --source-ref "refs/tags/${PIPELOCK_RELEASE}" \
  --source-digest "$PIPELOCK_COMMIT" \
  --deny-self-hosted-runners
```

Run the same command for `pipelock-init` and `pipelock-license-service` when
your upgrade uses those images.

The file has this shape:

```json
{
  "schema": "pipelock-release-images-v1",
  "tag": "v3.5.0",
  "commit": "the release commit",
  "images": [
    {
      "name": "pipelock",
      "repository": "ghcr.io/luckypipewrench/pipelock",
      "digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Use a `repository@digest` reference. A tag such as `:3.5.0` can be moved; a
manifest digest cannot.

## Helm chart

The Pipelock chart accepts a digest directly. Put the `pipelock` repository and
digest from `release-images.json` in a values file. Leave `tag` empty. The same
value applies to proxy and Conductor chart modes because both run the Pipelock
image.

```yaml
image:
  repository: ghcr.io/luckypipewrench/pipelock
  tag: ""
  digest: "sha256:73e5d240f2ae02392c7de9c8858e9dee164396382c13e0ea95b4a497b2567965"
```

That is the v3.5.0 digest. For another release, replace it with the `pipelock`
digest from that release's verified bundle.

Render the exact values before applying them:

```bash
helm lint charts/pipelock -f values-pipelock-v3.5.0.yaml
helm template pipelock charts/pipelock -f values-pipelock-v3.5.0.yaml > rendered-pipelock-v3.5.0.yaml
grep 'image:' rendered-pipelock-v3.5.0.yaml
```

The output must contain `ghcr.io/luckypipewrench/pipelock@sha256:`. It must not
contain a tag beside the digest.

## Other Kubernetes workloads

Use the same `pipelock` digest for a standalone dashboard deployment. For an
init-copy container, use `pipelock-init` from the bundle. For the license
service, use `pipelock-license-service` from the bundle. Those two images are
separate on purpose and are not configured by the Pipelock Helm chart.

```yaml
initContainers:
  - name: pipelock-init
    image: ghcr.io/luckypipewrench/pipelock-init@sha256:0d54825d0ddf820edd9627cc08253ed838aebd43f7a62938505f6eae7955d714
    args: ["cp", "/pipelock", "/shared-bin/pipelock"]

containers:
  - name: license-service
    image: ghcr.io/luckypipewrench/pipelock-license-service@sha256:68553cea16b32bdaa4251b65531c2e2ad9502ad9b4a9e4fa8e616ed69deaf5e0
```

Those are the v3.5.0 digests. For another release, replace each with its
matching entry from that release's verified bundle.

## Prove the cluster changed

Run these commands against the namespace and workload you changed. They check
four different things: the desired pod template, a completed rollout, ready
pods, and the digest the node reported after pulling the image.

```bash
kubectl -n pipelock get deployment pipelock -o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
kubectl -n pipelock rollout status deployment/pipelock --timeout=5m
PIPELOCK_SELECTOR="$(kubectl -n pipelock get deployment pipelock -o json | jq -er '
  [
    (.spec.selector.matchLabels // {} | to_entries[] | "\(.key)=\(.value)"),
    (.spec.selector.matchExpressions // [] | .[] |
      if .operator == "In" then "\(.key) in (\(.values | join(",")))"
      elif .operator == "NotIn" then "\(.key) notin (\(.values | join(",")))"
      elif .operator == "Exists" then .key
      elif .operator == "DoesNotExist" then "!\(.key)"
      else error("unsupported workload selector operator: \(.operator)")
      end)
  ] | join(",")
')"
test -n "$PIPELOCK_SELECTOR"
kubectl -n pipelock wait --for=condition=Ready pod -l "$PIPELOCK_SELECTOR" --timeout=5m
kubectl -n pipelock get pods -l "$PIPELOCK_SELECTOR" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .status.initContainerStatuses[*]}{.name}{"\t"}{.imageID}{"\n"}{end}{range .status.containerStatuses[*]}{.name}{"\t"}{.imageID}{"\n"}{end}{end}'
```

Compare every desired `image:` reference and every reported `imageID` to the
matching digest in `release-images.json`. `imageID` often starts with
`containerd://`; the digest after that prefix is the part that must match.

Repeat the same check for each standalone dashboard, init-copy workload, and
license-service Deployment or StatefulSet. A green rollout only proves a pod
started. It does not prove the node pulled the image you meant to deploy.

## Drift and rollback

Keep the previous release's `release-images.json` beside the new one. Compare
the desired pod templates and live image IDs after every GitOps reconciliation
or manual Helm upgrade. A mismatch means the cluster is running a different
image from the release you approved.

For a normal rollback, change the same values or GitOps image references back
to the previous bundle, apply through the same path, then repeat the four
checks above. `kubectl rollout undo` is an emergency tool for a Deployment;
it does not roll back separate StatefulSets, Helm values, or GitOps state, so
use it only to stop a bad rollout while you restore the declared configuration.
