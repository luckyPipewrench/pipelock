# Deployment Recipes

Pipelock blocks bad traffic, but only if traffic actually goes through it. Setting `HTTPS_PROXY` is a convenience, not a security boundary: any agent that can make raw socket calls can bypass it. These recipes lock your agent's egress at the network level so nothing bypasses the proxy.

The pattern is always the same: agent can only reach pipelock, pipelock can reach the internet.

## Enforcement Tiers

Pipelock supports three enforcement tiers. Pick the one that matches your threat model, then follow the recipe that implements it.

| Tier | Name | What enforces it | Bypass surface | Recommended when |
|------|------|------------------|----------------|------------------|
| 1 | **Soft** (`HTTPS_PROXY`, K8s sidecar) | Agent cooperation | Raw sockets, tools that ignore proxy env vars, any container sharing the pod network namespace | Local dev, trusted agents, quick start |
| 2 | **Enforced** (kernel network boundary) | Container runtime network namespace or kernel per-UID packet filter | Container escape or kernel-level bypass | Most production workloads on a single host |
| 3 | **Transparent** (separate proxy pod + NetworkPolicy egress lock) | Cluster CNI enforces that the agent pod can only reach the pipelock Service IP | CNI misconfiguration or a CNI vulnerability | Zero-trust deployments, untrusted agents, fleet scale |

Each tier is strictly stronger than the previous one. Tier 1 assumes the agent cooperates with `HTTPS_PROXY`. Tier 2 makes cooperation irrelevant because a kernel-enforced boundary drops direct egress from the agent. Tier 3 moves pipelock to its own pod so the agent's container has no network path except the pipelock Service endpoint — even a compromised agent binary can't bypass it without escaping the CNI.

**Picking a tier:**

- **Tier 1 (Soft):** `HTTPS_PROXY` env var, or [Kubernetes sidecar](#sidecar-deployment) where pipelock runs in the same pod as the agent. Fast to set up, no isolation guarantees — the agent must cooperate. The K8s sidecar is in this tier because the agent container shares the pod's network namespace with pipelock and can reach the internet directly without going through pipelock; NetworkPolicy filters the pod's egress, not the container-to-container traffic within the pod. Good for local development, CI where the agent is trusted, and K8s quickstart.
- **Tier 2 (Enforced):** [Docker Compose with `internal: true` network](#docker-compose-recommended-for-local-development) on a single host (Docker creates an isolated network namespace with no gateway, so pipelock is the agent's only route out), [Linux host firewall rules](#iptables--nftables-linux) (iptables/nftables `--uid-owner` filtering drops packets from the agent user unless destined for pipelock), or [macOS PF per-user filtering](#macos-pf) (PF drops packets from the agent user unless destined for pipelock). In all three, a kernel-enforced boundary drops direct agent egress; raw sockets don't help because the kernel drops the packets before they leave the host.
- **Tier 3 (Transparent):** [Kubernetes separate-pod pattern with NetworkPolicy](#kubernetes-with-networkpolicy) restricting the agent pod's egress to only the pipelock Service IP. Pipelock runs as its own Deployment, not as a sidecar. The agent pod has no route to the internet; it can only reach the pipelock Service endpoint. This is the strongest tier pipelock supports today with zero agent cooperation required.

> **Future work: kernel-level transparent interception.** TPROXY / `IP_TRANSPARENT`-based interception that redirects packets at the kernel before they leave the host would let pipelock transparently capture agent traffic without any agent cooperation or per-UID filtering. Pipelock does not currently set `IP_TRANSPARENT` on its listen socket, so a TPROXY recipe requires pipelock code changes, not just documentation. This is on the roadmap.

## Docker Compose (Recommended for Local Development)

The quickest way to get full network isolation. Pipelock generates this for you:

```bash
pipelock generate docker-compose --agent claude-code -o docker-compose.yaml
docker compose up
```

Or build it yourself:

```yaml
version: "3.8"

networks:
  agent-internal:
    internal: true    # No internet access
  proxy-external:
    # Normal network, internet access

services:
  pipelock:
    image: ghcr.io/luckypipewrench/pipelock:latest
    command: run --config /config/pipelock.yaml --listen 0.0.0.0:8888
    volumes:
      - ./pipelock.yaml:/config/pipelock.yaml:ro
    networks:
      - agent-internal   # Agent can reach pipelock
      - proxy-external   # Pipelock can reach internet
    ports:
      - "8888:8888"      # Optional: expose for debugging

  agent:
    image: your-agent-image
    environment:
      - HTTPS_PROXY=http://pipelock:8888
      - HTTP_PROXY=http://pipelock:8888
      - NO_PROXY=localhost,127.0.0.1
    networks:
      - agent-internal   # Agent can ONLY reach pipelock
    depends_on:
      - pipelock
```

The `internal: true` flag on `agent-internal` is what makes this work. Docker won't create a gateway for that network, so the agent container has no route to the internet. Its only option is pipelock on port 8888.

> **Docker version note:** Docker < 25.0.5 has a DNS leak on internal networks ([CVE-2024-29018](https://github.com/moby/moby/security/advisories/GHSA-mq39-4gv4-mvpx)). Containers on `internal: true` networks could resolve external hostnames via the embedded DNS server, bypassing the `internal` flag. Upgrade to Docker >= 25.0.5 or add `enable_ipv6: false` to your internal network definition as a partial mitigation.

For a complete working example with verification tests, see [`examples/quickstart/`](../../examples/quickstart/).

### Adding MCP Servers

If your agent uses MCP servers, wrap them through pipelock too:

```yaml
services:
  pipelock:
    command: >
      run --config /config/pipelock.yaml
      --listen 0.0.0.0:8888
      --mcp-listen 0.0.0.0:8889
      --mcp-upstream http://mcp-server:3000/mcp
    # ...

  mcp-server:
    image: your-mcp-server
    networks:
      - agent-internal
```

### Kill Switch API on a Separate Port

For operator access to the kill switch without exposing it to the agent:

```yaml
services:
  pipelock:
    # ... (same as above)
    ports:
      - "127.0.0.1:9090:9090"    # Kill switch API, host-only

  # pipelock.yaml should have:
  # kill_switch:
  #   api_listen: "0.0.0.0:9090"
  #   api_token: "your-token-here"
```

Port publishing controls host access, not inter-container access. The agent on `agent-internal` can still reach `pipelock:9090` via the service name. The token requirement is what prevents unauthorized activation. Binding to `127.0.0.1` on the host side keeps the API off external interfaces.

## Kubernetes with NetworkPolicy

For K8s deployments, pipelock runs as a sidecar in the agent pod. The agent container talks to pipelock on localhost, and pipelock talks to the internet.

**Important caveat:** K8s NetworkPolicy is pod-scoped, not container-scoped. Since pipelock and the agent share a pod, any egress you allow for pipelock also applies to the agent container. NetworkPolicy alone cannot prevent the agent from bypassing the proxy. You need one of:

1. **Separate proxy pod** (recommended): run pipelock as its own Deployment and use NetworkPolicy to restrict the agent pod's egress to only the pipelock Service IP. Generate the full bundle with [`pipelock init sidecar`](../cli/init-sidecar.md) (see below).
2. **CNI-level enforcement**: Cilium or Calico Enterprise support container-level network policies.
3. **Application-level controls**: configure the agent runtime to only use `HTTPS_PROXY` and block raw socket access.

The sidecar pattern below is convenient for getting started, but understand the limitation: it relies on the agent honoring `HTTPS_PROXY`, not on network-level enforcement.

### Generated companion-proxy deployment (recommended)

`pipelock init sidecar` generates the Tier 3 (Transparent) deployment automatically from a workload manifest. The command emits a companion pipelock Deployment, a ClusterIP Service, a PodDisruptionBudget, a pipelock ConfigMap, and a NetworkPolicy that locks the agent pod's egress to the pipelock Service. The agent container keeps its original spec plus the `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` envs pointing at the companion.

```bash
pipelock init sidecar --inject-spec my-agent-deployment.yaml --output enforced.yaml
kubectl apply -f enforced.yaml
```

Three output formats are supported:

| Flag | Output | Use |
|------|--------|-----|
| (default) | Strategic-merge patch + additional manifests | `kubectl apply` directly |
| `--emit kustomize` | Kustomize overlay with `kustomization.yaml` | GitOps (Flux, Argo CD) |
| `--emit helm-values` | `values.yaml` fragment for the pipelock Helm chart | Helm-based pipelines |

The generated companion config sets `bind_default_agent_identity: true` so caller-supplied `X-Pipelock-Agent` headers and `?agent=` query parameters are ignored — identity is bound to the workload. This is the recommended mode for single-workload topologies. Shared-proxy multi-agent identity remains a deferred item on the roadmap (requires mTLS or workload-authenticated listener binding). Full reference: [`pipelock init sidecar`](../cli/init-sidecar.md).

**Rollout order:** deploy the pipelock Deployment and wait for ready endpoints before patching the agent workload to route through it. The Helm output documents that order explicitly. Rolling the agent workload first creates a fail-closed brownout until the companion is up.

**Airlock recovery:** when a session escalates into the hard or drain tier under adaptive enforcement, use the [`pipelock session`](../cli/session.md) operator CLI to inspect, explain, and (if needed) release the session. The CLI talks to the companion's admin API over the port configured by `kill_switch.api_listen`.

### Sidecar Deployment

Pipelock runs as a sidecar container in the same pod as your agent. They share `localhost`, so the agent sets `HTTPS_PROXY=http://127.0.0.1:8888`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-agent
  namespace: agents
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-agent
  template:
    metadata:
      labels:
        app: my-agent
    spec:
      # Init container: copy pipelock binary for MCP stdio wrapping
      initContainers:
        - name: pipelock-init
          image: ghcr.io/luckypipewrench/pipelock-init:latest
          command: ["cp", "/pipelock", "/shared-bin/pipelock"]
          volumeMounts:
            - name: shared-bin
              mountPath: /shared-bin

      containers:
        # Pipelock sidecar
        - name: pipelock
          image: ghcr.io/luckypipewrench/pipelock:latest
          args:
            - run
            - --config
            - /etc/pipelock/pipelock.yaml
          ports:
            - containerPort: 8888
              name: proxy
            - containerPort: 9090
              name: killswitch
          env:
            - name: PIPELOCK_KILLSWITCH_API_TOKEN
              valueFrom:
                secretKeyRef:
                  name: pipelock-secrets
                  key: killswitch-api-token
          volumeMounts:
            - name: pipelock-config
              mountPath: /etc/pipelock/pipelock.yaml
              subPath: pipelock.yaml
          livenessProbe:
            httpGet:
              path: /health
              port: 8888
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 8888
            periodSeconds: 10
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              cpu: 200m
              memory: 128Mi

        # Your agent
        - name: agent
          image: your-agent-image
          env:
            - name: HTTPS_PROXY
              value: "http://127.0.0.1:8888"
            - name: HTTP_PROXY
              value: "http://127.0.0.1:8888"
            - name: NO_PROXY
              value: "localhost,127.0.0.1"
          volumeMounts:
            - name: shared-bin
              mountPath: /usr/local/bin/pipelock
              subPath: pipelock
            - name: pipelock-config
              mountPath: /etc/pipelock/pipelock.yaml
              subPath: pipelock.yaml

      volumes:
        - name: pipelock-config
          configMap:
            name: pipelock-config
        - name: shared-bin
          emptyDir: {}
```

### NetworkPolicy (Required)

A NetworkPolicy restricts pod-level egress. In the sidecar pattern, this limits what the entire pod (both containers) can reach, but does not prevent the agent container from making direct connections that bypass pipelock. For true network-level enforcement, use a separate proxy pod (see note above).

This policy restricts the pod's egress to DNS and HTTPS:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-egress
  namespace: agents
spec:
  podSelector:
    matchLabels:
      app: my-agent
  policyTypes:
    - Egress
    - Ingress
  egress:
    # DNS (required for any network access)
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53

    # Pipelock sidecar talks to the internet
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
        - protocol: TCP
          port: 80

    # Intra-pod communication (agent <-> pipelock on localhost)
    # Note: K8s NetworkPolicy doesn't filter localhost traffic within a pod.
    # The sidecar pattern works because they share the same network namespace.

  ingress:
    # Allow monitoring (Prometheus scrape)
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: monitoring
      ports:
        - protocol: TCP
          port: 8888
```

**Important:** K8s NetworkPolicy controls traffic between pods, not between containers within a pod. In the sidecar pattern, the agent container shares the pod's network namespace and can reach the internet directly (same egress rules as pipelock). The `HTTPS_PROXY` env var tells the agent to route through pipelock, but nothing at the network level enforces it. For enforced isolation, run pipelock as a separate pod and restrict the agent pod's egress to only the pipelock Service.

### PodMonitor (Prometheus Scraping)

If you use the Prometheus Operator, add a PodMonitor to scrape pipelock metrics:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: pipelock
  namespace: agents
  labels:
    release: kube-prometheus-stack
spec:
  selector:
    matchLabels:
      app: my-agent
  podMetricsEndpoints:
    - port: proxy
      path: /metrics
      interval: 30s
      metricRelabelings:
        - sourceLabels: [__name__]
          regex: 'pipelock_.*'
          action: keep
```

## iptables / nftables (Linux)

For bare-metal or VM deployments where Docker/K8s isn't an option, use iptables to force agent traffic through pipelock.

This assumes pipelock runs as its own user (`pipelock`) and the agent runs as a different user (`agent`).

```bash
# Create a dedicated user for pipelock
sudo useradd -r -s /bin/false pipelock

# Run pipelock as the pipelock user
sudo -u pipelock pipelock run --config /etc/pipelock/pipelock.yaml &

# Block all outbound HTTP/HTTPS from the agent user EXCEPT to pipelock
sudo iptables -A OUTPUT -m owner --uid-owner agent -p tcp --dport 443 -j DROP
sudo iptables -A OUTPUT -m owner --uid-owner agent -p tcp --dport 80 -j DROP
sudo iptables -A OUTPUT -m owner --uid-owner agent -d 127.0.0.1 -p tcp --dport 8888 -j ACCEPT

# Allow pipelock user to reach the internet
sudo iptables -A OUTPUT -m owner --uid-owner pipelock -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner pipelock -p tcp --dport 80 -j ACCEPT
```

The key is `--uid-owner`: it matches packets by the UID of the process that created the socket. The agent user can only reach localhost:8888 (pipelock). Pipelock's user can reach the internet.

**To persist across reboots:**

```bash
# Save rules
sudo iptables-save > /etc/iptables/rules.v4

# Or use iptables-persistent (Debian/Ubuntu)
sudo apt install iptables-persistent
sudo netfilter-persistent save
```

### nftables (modern alternative)

```nft
table inet agent_firewall {
    chain output {
        type filter hook output priority 0; policy accept;

        # Agent user: block direct internet, allow pipelock
        meta skuid "agent" tcp dport { 80, 443 } drop
        meta skuid "agent" ip daddr 127.0.0.1 tcp dport 8888 accept

        # Pipelock user: allow internet
        meta skuid "pipelock" tcp dport { 80, 443 } accept
    }
}
```

## ufw (Ubuntu/Debian)

ufw doesn't support per-user filtering directly. Use it alongside the iptables rules above, or use ufw for the basics and add user-specific rules manually:

```bash
# Default deny outgoing (careful: this affects everything)
sudo ufw default deny outgoing
sudo ufw default deny incoming

# Allow pipelock to reach the internet
sudo ufw allow out on any proto tcp to any port 443
sudo ufw allow out on any proto tcp to any port 80

# Allow DNS
sudo ufw allow out on any proto udp to any port 53

# Then add iptables rules for per-user filtering (see above)
```

For most setups, Docker Compose or K8s NetworkPolicy is simpler and more portable than host-level firewall rules.

## macOS (PF)

macOS uses PF (Packet Filter). The approach is similar to iptables: block the agent's outbound traffic except to pipelock.

```bash
# /etc/pf.anchors/pipelock
# Block agent user from reaching internet directly
block out quick on en0 proto tcp from any to any port {80, 443} user agent
# Allow agent to reach pipelock on localhost
pass out quick on lo0 proto tcp from any to any port 8888 user agent
# Allow pipelock to reach internet
pass out quick on en0 proto tcp from any to any port {80, 443} user pipelock
```

Load the rules:

```bash
# Add anchor to /etc/pf.conf
echo 'anchor "pipelock"' | sudo tee -a /etc/pf.conf
echo 'load anchor "pipelock" from "/etc/pf.anchors/pipelock"' | sudo tee -a /etc/pf.conf

# Reload PF
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

**Note:** macOS PF rules don't survive reboots by default. Create a LaunchDaemon to load them at boot.

## TLS Interception (CA Distribution)

When TLS interception is enabled, the agent must trust pipelock's CA certificate. The distribution method depends on your deployment pattern. Generate the CA first with `pipelock tls init` (see the [TLS Interception Guide](tls-interception.md) for full setup).

### Docker Compose

Mount the CA certificate into the agent container and set the appropriate environment variable:

```yaml
services:
  pipelock:
    image: ghcr.io/luckypipewrench/pipelock:latest
    command: run --config /config/pipelock.yaml --listen 0.0.0.0:8888
    volumes:
      - ./pipelock.yaml:/config/pipelock.yaml:ro
      - ./ca.pem:/etc/pipelock/ca.pem:ro
      - ./ca-key.pem:/etc/pipelock/ca-key.pem:ro
    networks:
      - agent-internal
      - proxy-external

  agent:
    image: your-agent-image
    environment:
      - HTTPS_PROXY=http://pipelock:8888
      - HTTP_PROXY=http://pipelock:8888
      - NO_PROXY=localhost,127.0.0.1
      # Trust pipelock's CA (pick the one matching your runtime)
      - SSL_CERT_FILE=/etc/pipelock/ca.pem          # Python, Go
      - REQUESTS_CA_BUNDLE=/etc/pipelock/ca.pem      # Python requests/httpx
      - NODE_EXTRA_CA_CERTS=/etc/pipelock/ca.pem     # Node.js
    volumes:
      - ./ca.pem:/etc/pipelock/ca.pem:ro
    networks:
      - agent-internal
```

The pipelock config should reference the mounted paths:

```yaml
tls_interception:
  enabled: true
  ca_cert: /etc/pipelock/ca.pem
  ca_key: /etc/pipelock/ca-key.pem
```

### Kubernetes (ConfigMap + Secret)

Store the CA certificate in a ConfigMap and the private key in a Secret:

```bash
kubectl create configmap pipelock-ca --from-file=ca.pem=~/.pipelock/ca.pem -n agents
kubectl create secret generic pipelock-ca-key --from-file=ca-key.pem=~/.pipelock/ca-key.pem -n agents
```

Mount both into the pipelock sidecar, and the CA (not the key) into the agent container:

```yaml
containers:
  - name: pipelock
    image: ghcr.io/luckypipewrench/pipelock:latest
    args: ["run", "--config", "/etc/pipelock/pipelock.yaml"]
    volumeMounts:
      - name: pipelock-config
        mountPath: /etc/pipelock/pipelock.yaml
        subPath: pipelock.yaml
      - name: pipelock-ca
        mountPath: /etc/pipelock/ca.pem
        subPath: ca.pem
      - name: pipelock-ca-key
        mountPath: /etc/pipelock/ca-key.pem
        subPath: ca-key.pem

  - name: agent
    image: your-agent-image
    env:
      - name: HTTPS_PROXY
        value: "http://127.0.0.1:8888"
      - name: SSL_CERT_FILE
        value: "/etc/pipelock/ca.pem"
      - name: NODE_EXTRA_CA_CERTS
        value: "/etc/pipelock/ca.pem"
    volumeMounts:
      - name: pipelock-ca
        mountPath: /etc/pipelock/ca.pem
        subPath: ca.pem

volumes:
  - name: pipelock-ca
    configMap:
      name: pipelock-ca
  - name: pipelock-ca-key
    secret:
      secretName: pipelock-ca-key
```

### Bare-Metal / iptables

Install the CA into the system trust store so all applications trust it:

```bash
# Debian/Ubuntu
sudo cp ~/.pipelock/ca.pem /usr/local/share/ca-certificates/pipelock-ca.crt
sudo update-ca-certificates

# RHEL/Fedora
sudo cp ~/.pipelock/ca.pem /etc/pki/ca-trust/source/anchors/pipelock-ca.crt
sudo update-ca-trust extract
```

Some runtimes ignore the system store. Set the environment variable for the agent user:

```bash
# In the agent user's shell profile
export SSL_CERT_FILE=~/.pipelock/ca.pem
export NODE_EXTRA_CA_CERTS=~/.pipelock/ca.pem
```

### macOS

Add the CA to the system keychain:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.pipelock/ca.pem
```

For Node.js and Python, also set environment variables (they may not use the system keychain):

```bash
export NODE_EXTRA_CA_CERTS=~/.pipelock/ca.pem
export SSL_CERT_FILE=~/.pipelock/ca.pem
```

## Verifying Isolation

After setting up any of these recipes, verify the agent can't bypass pipelock:

```bash
# From the agent's context (container, user, etc.):

# This should FAIL (direct internet access blocked)
curl -s https://example.com
# Expected: connection refused or timeout

# This should SUCCEED (through pipelock)
curl -s "http://localhost:8888/fetch?url=https://example.com"
# Expected: page content

# This should be BLOCKED by pipelock (DLP catches the fake key)
curl -s "http://localhost:8888/fetch?url=https://example.com/?key=sk-ant-api03-fake1234567890"
# Expected: blocked response
```

For Docker Compose deployments, the [`examples/quickstart/`](../../examples/quickstart/) includes an automated verification suite that tests network isolation, DLP blocking, response injection detection, and MCP tool poisoning in one command:

```bash
cd examples/quickstart
docker compose --profile verify up --abort-on-container-exit --exit-code-from verify
```

## Which Recipe to Use

| Scenario | Recipe | Why |
|----------|--------|-----|
| Local development | Docker Compose | Simplest setup, one `docker compose up` |
| Kubernetes cluster | Separate proxy pod + NetworkPolicy | Enforced isolation at the network level |
| Kubernetes (quick start) | Sidecar + HTTPS_PROXY | Convenient, but relies on agent honoring proxy |
| Bare-metal Linux | iptables/nftables | No container runtime needed |
| macOS development | PF or Docker Compose | PF for native, Docker for portability |
| CI/CD pipeline | GitHub Action | Use the [reusable workflow](../../.github/workflows/reusable-scan.yml) |
