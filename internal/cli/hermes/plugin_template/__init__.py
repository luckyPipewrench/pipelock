"""Pipelock security plugin for Hermes Agent.

Registers the hooks pipelock cares about (pre_tool_call, transform_tool_result,
pre_gateway_dispatch, on_session_start, on_session_end). Each hook subprocess-
exec's `pipelock hermes hook` over stdin/stdout JSON, matching Hermes' standard
shell-hook wire protocol.

This module is installed to ~/.hermes/plugins/pipelock/ by `pipelock hermes
install`. Do not hand-edit; re-run install to upgrade.
"""

from .plugin import register

__all__ = ["register"]
