# Deployment Recipes

Pipelock blocks bad traffic, but only if traffic actually goes through it. These recipes lock your agent's egress so nothing bypasses the proxy.

The pattern is always the same: agent can only reach pipelock, pipelock can reach the internet.

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
      - "9090:9090"    # Kill switch API, host-only

  # pipelock.yaml should have:
  # kill_switch:
  #   api_listen: "0.0.0.0:9090"
  #   api_token: "your-token-here"
```

The agent on `agent-internal` cannot reach port 9090. Only the host (or another container on `proxy-external`) can.

## Kubernetes with NetworkPolicy

For K8s deployments, pipelock runs as a sidecar in the agent pod. The agent container talks to pipelock on localhost, and pipelock talks to the internet.

**Important caveat:** K8s NetworkPolicy is pod-scoped, not container-scoped. Since pipelock and the agent share a pod, any egress you allow for pipelock also applies to the agent container. NetworkPolicy alone cannot prevent the agent from bypassing the proxy. You need one of:

1. **Separate proxy pod** (recommended): run pipelock as its own Deployment and use NetworkPolicy to restrict the agent pod's egress to only the pipelock Service IP.
2. **CNI-level enforcement**: Cilium or Calico Enterprise support container-level network policies.
3. **Application-level controls**: configure the agent runtime to only use `HTTPS_PROXY` and block raw socket access.

The sidecar pattern below is convenient for getting started, but understand the limitation: it relies on the agent honoring `HTTPS_PROXY`, not on network-level enforcement.

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
      # Init container: download pipelock binary for MCP wrapping
      initContainers:
        - name: pipelock-init
          image: alpine:3.19
          command:
            - sh
            - -c
            - |
              VERSION=0.3.0  # pin to a specific release
              ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
              wget -qO- "https://github.com/luckyPipewrench/pipelock/releases/download/v${VERSION}/pipelock_${VERSION}_linux_${ARCH}.tar.gz" \
                | tar xz -C /shared-bin pipelock
              chmod +x /shared-bin/pipelock
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

## Which Recipe to Use

| Scenario | Recipe | Why |
|----------|--------|-----|
| Local development | Docker Compose | Simplest setup, one `docker compose up` |
| Kubernetes cluster | Separate proxy pod + NetworkPolicy | Enforced isolation at the network level |
| Kubernetes (quick start) | Sidecar + HTTPS_PROXY | Convenient, but relies on agent honoring proxy |
| Bare-metal Linux | iptables/nftables | No container runtime needed |
| macOS development | PF or Docker Compose | PF for native, Docker for portability |
| CI/CD pipeline | GitHub Action | Use the [reusable workflow](../../.github/workflows/reusable-scan.yml) |
