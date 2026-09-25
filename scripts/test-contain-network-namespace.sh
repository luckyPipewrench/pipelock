#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0

set -u -o pipefail

namespace_unit=pipelock-agent-netns.service
proxy_socket=pipelock-agent-proxy.socket
namespace_forwarder=pipelock-agent-netns-forward.service
agent_user=pipelock-agent
proxy_port="${1:-8888}"
run_id="$$"
inside_listener_unit="pipelock-netns-proof-inside-${run_id}.service"
host_listener_unit="pipelock-netns-proof-host-${run_id}.service"
runtime_dir="$(mktemp -d /run/pipelock-netns-proof.XXXXXX)"
inside_port_file="${runtime_dir}/inside.port"
host_port_file="${runtime_dir}/host.port"
failures=0

cleanup() {
    systemctl stop "${inside_listener_unit}" "${host_listener_unit}" >/dev/null 2>&1 || true
    systemctl reset-failed "${inside_listener_unit}" "${host_listener_unit}" >/dev/null 2>&1 || true
    rm -f "${inside_port_file}" "${host_port_file}"
    rmdir "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

pass() {
    printf 'PASS: %s\n' "$1"
}

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    failures=$((failures + 1))
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command is unavailable: $1"
        return 1
    fi
}

namespace_curl() {
    systemd-run \
        --quiet \
        --wait \
        --collect \
        --pipe \
        --service-type=oneshot \
        --property=PrivateNetwork=true \
        --property="JoinsNamespaceOf=${namespace_unit}" \
        --uid="${agent_user}" \
        -- \
        curl --noproxy '*' --silent --show-error --fail \
        --connect-timeout 1 --max-time 2 "$1" >/dev/null 2>&1
}

wait_for() {
    local deadline=$((SECONDS + 10))
    until "$@"; do
        if (( SECONDS >= deadline )); then
            return 1
        fi
        sleep 0.1
    done
}

if [[ "${EUID}" -ne 0 ]]; then
    printf 'FAIL: run this script as root\n' >&2
    exit 1
fi

for command in systemctl systemd-run curl python3; do
    require_command "${command}" || true
done
if (( failures > 0 )); then
    exit 1
fi
if ! getent passwd "${agent_user}" >/dev/null; then
    fail "contained agent user ${agent_user} does not exist"
    exit 1
fi
if [[ ! "${proxy_port}" =~ ^[0-9]+$ ]] || (( proxy_port < 1 || proxy_port > 65535 )); then
    fail "proxy port must be an integer from 1 to 65535"
    exit 1
fi

touch "${inside_port_file}" "${host_port_file}"
chown "${agent_user}" "${inside_port_file}"
chmod 0600 "${inside_port_file}" "${host_port_file}"
# mktemp -d leaves the directory 0700 root, so the listener running as the
# contained user cannot traverse into it to publish its port, and the failure
# reads as "did not publish its kernel-assigned port" rather than a permission
# problem. Grant traverse only; the files keep their own modes.
chmod 0711 "${runtime_dir}"

# The host doorway is a pathname unix socket in the HOST namespace, because
# systemd.socket(5) allocates every .socket listener there regardless of
# PrivateNetwork=. The in-namespace listener is a separate service that joins
# the namespace and dials that socket.
if ! systemctl start "${proxy_socket}"; then
    fail "start host doorway socket ${proxy_socket}"
    exit 1
fi
if ! systemctl start "${namespace_forwarder}"; then
    fail "start in-namespace proxy listener ${namespace_forwarder}"
    exit 1
fi
if ! systemctl is-active --quiet "${namespace_unit}"; then
    fail "private network namespace anchor ${namespace_unit} is active"
    exit 1
fi
if ! systemctl is-active --quiet "${namespace_forwarder}"; then
    fail "in-namespace proxy listener ${namespace_forwarder} is active"
    exit 1
fi

if ! systemd-run \
    --quiet \
    --unit="${inside_listener_unit}" \
    --service-type=exec \
    --property=PrivateNetwork=true \
    --property="JoinsNamespaceOf=${namespace_unit}" \
    --uid="${agent_user}" \
    -- \
    python3 -c 'import http.server, pathlib, sys
class FixedHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixedHandler)
pathlib.Path(sys.argv[1]).write_text(str(server.server_port))
server.serve_forever()' "${inside_port_file}" >/dev/null; then
    fail "start listener inside the private namespace"
else
    if ! wait_for test -s "${inside_port_file}"; then
        fail "inside listener did not publish its kernel-assigned port"
        inside_port=""
    else
        inside_port="$(<"${inside_port_file}")"
    fi
    if [[ -n "${inside_port}" ]]; then
        if wait_for namespace_curl "http://127.0.0.1:${inside_port}/"; then
            pass "a process inside the namespace can reach its own loopback listener"
        else
            fail "a process inside the namespace can reach its own loopback listener"
        fi
        if curl --noproxy '*' --silent --show-error --fail \
            --connect-timeout 1 --max-time 2 "http://127.0.0.1:${inside_port}/" >/dev/null 2>&1; then
            fail "a host process cannot reach the namespace loopback listener"
        else
            pass "a host process cannot reach the namespace loopback listener"
        fi
    fi
fi

if ! systemd-run \
    --quiet \
    --unit="${host_listener_unit}" \
    --service-type=exec \
    -- \
    python3 -c 'import http.server, pathlib, sys
class FixedHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixedHandler)
pathlib.Path(sys.argv[1]).write_text(str(server.server_port))
server.serve_forever()' "${host_port_file}" >/dev/null; then
    fail "start host-loopback listener"
else
    if ! wait_for test -s "${host_port_file}"; then
        fail "host listener did not publish its kernel-assigned port"
        host_port=""
    else
        host_port="$(<"${host_port_file}")"
    fi
    if [[ -z "${host_port}" ]] || ! wait_for curl --noproxy '*' --silent --show-error --fail \
        --connect-timeout 1 --max-time 2 --output /dev/null "http://127.0.0.1:${host_port}/"; then
        fail "host-loopback control listener is reachable from the host"
    elif namespace_curl "http://127.0.0.1:${host_port}/"; then
        fail "a contained process cannot reach a host-loopback listener"
    else
        pass "a contained process cannot reach a host-loopback listener"
    fi
fi

if namespace_curl "http://127.0.0.1:${proxy_port}/health"; then
    pass "a contained process can reach the socket-forwarded Pipelock proxy"
else
    fail "a contained process can reach the socket-forwarded Pipelock proxy"
fi

if (( failures > 0 )); then
    printf 'FAIL: %d assertion(s) failed\n' "${failures}" >&2
    exit 1
fi
printf 'PASS: all network namespace boundary assertions passed\n'
