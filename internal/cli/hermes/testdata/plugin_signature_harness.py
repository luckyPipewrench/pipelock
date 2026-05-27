#!/usr/bin/env python3
"""Signature regression harness for the pipelock Hermes plugin.

Drives every hook the plugin registers exactly the way Hermes' real dispatcher
does -- ``cb(**kwargs)`` (hermes_cli/plugins.py invoke_hook) -- using the kwarg
set verified against the real Hermes call sites in hermes_agent 0.13.0 and
0.14.0 (identical between the two):

  pre_tool_call          hermes_cli/plugins.py  get_pre_tool_call_block_message()
  transform_tool_result  model_tools.py         tool-dispatch seam
  on_session_start       run_agent.py           run_conversation() new-session
  on_session_end         run_agent.py           run_conversation() teardown
  pre_gateway_dispatch   gateway/run.py          inbound dispatch guard

Why this matters: Hermes wraps each ``cb(**kwargs)`` in a bare ``except
Exception`` that only logs a warning. A hook whose signature rejects a kwarg
Hermes passes raises TypeError, Hermes swallows it, and the scan silently never
runs -- the agent proceeds UNSCANNED (fail-open). This harness turns that
silent runtime failure into a loud CI failure.

Usage: python3 plugin_signature_harness.py <installed-plugin-dir>
Exit 0 = every hook accepts the contract. Non-zero = drift; the message names
the offending hook.
"""

import importlib.util
import os
import sys


class _Event:
    """Minimal stand-in for Hermes' MessageEvent (pre_gateway_dispatch reads
    .text and .sender via getattr)."""

    text = "hello from the gateway"
    sender = "user-123"


# The verified kwarg set Hermes passes to each hook. Keep in sync with the
# Hermes call sites cited in the module docstring; the live-Hermes e2e test
# (Step B) is the durable guard against upstream renames this harness can't see.
HERMES_KWARGS = {
    "pre_tool_call": dict(
        tool_name="terminal",
        args={"command": "echo hi"},
        task_id="task-1",
        session_id="sess-1",
        tool_call_id="call-1",
    ),
    "transform_tool_result": dict(
        tool_name="terminal",
        args={"command": "echo hi"},
        result='{"output": "hi"}',
        task_id="task-1",
        session_id="sess-1",
        tool_call_id="call-1",
        duration_ms=42,
    ),
    "on_session_start": dict(session_id="sess-1", model="gpt-4", platform="cli"),
    "on_session_end": dict(
        session_id="sess-1",
        completed=True,
        interrupted=False,
        model="gpt-4",
        platform="cli",
    ),
    "pre_gateway_dispatch": dict(event=_Event(), gateway=None, session_store=None),
}
EXPECTED_HOOKS = set(HERMES_KWARGS)


class _RecordingCtx:
    """Captures register_hook() calls the way Hermes' PluginContext would."""

    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, cb):
        self.hooks.setdefault(name, []).append(cb)


def _load_plugin(plugin_dir):
    path = os.path.join(plugin_dir, "plugin.py")
    spec = importlib.util.spec_from_file_location("pipelock_plugin_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    if len(sys.argv) != 2:
        print("usage: plugin_signature_harness.py <plugin-dir>", file=sys.stderr)
        return 2
    plugin_dir = sys.argv[1]

    # Point PIPELOCK_BIN at a path that is not a file so _resolve_pipelock()
    # returns None and the hooks never spawn a subprocess. We are testing the
    # signature boundary, not scan behavior, so this keeps the harness hermetic
    # and fast.
    os.environ["PIPELOCK_BIN"] = "/nonexistent/pipelock-signature-harness"

    mod = _load_plugin(plugin_dir)
    ctx = _RecordingCtx()
    mod.register(ctx)

    registered = set(ctx.hooks)
    if registered != EXPECTED_HOOKS:
        print(
            "FAIL: registered hooks {} != expected {}".format(
                sorted(registered), sorted(EXPECTED_HOOKS)
            ),
            file=sys.stderr,
        )
        return 1

    for name, kwargs in HERMES_KWARGS.items():
        for cb in ctx.hooks[name]:
            try:
                cb(**kwargs)
            except TypeError as exc:
                print(
                    "FAIL: hook {} rejected Hermes kwargs {}: {}".format(
                        name, sorted(kwargs), exc
                    ),
                    file=sys.stderr,
                )
                return 1
            except Exception as exc:  # noqa: BLE001 - any escape is a real bug
                print(
                    "FAIL: hook {} raised {}: {}".format(
                        name, type(exc).__name__, exc
                    ),
                    file=sys.stderr,
                )
                return 1

    print("OK: all hooks accept the Hermes kwarg contract")
    return 0


if __name__ == "__main__":
    sys.exit(main())
