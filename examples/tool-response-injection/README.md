# Tool Response Injection

## Scenario
An agent calls an MCP tool with an innocent name. The tool description looks harmless. The tool response is the attack.

In this example, `play_game` returns a prompt-injection payload that tells the agent to ignore prior instructions and insert a path-traversal bug into later code. A client-side audit log that records only the prompt, tool name, and final completion misses the payload entirely. The bad instruction lived in the tool response body, and the log never captured it.

We built this harness to show two things at once. Pipelock blocks the response before it reaches the agent. Pipelock also emits signed receipts that a third party can verify without trusting pipelock itself.

## Run It
Run the full harness from this directory:

```bash
python3 demo.py
```

Dependencies:
- Python 3
- `cryptography` (`pip install cryptography`)
- a `pipelock` binary on `PATH`

If you want to point the demo at a specific binary, set `PIPELOCK_BIN`:

```bash
PIPELOCK_BIN=/path/to/pipelock python3 demo.py
```

The harness writes a fresh Ed25519 signing key to `./signing.key`, resets `./evidence`, then runs three transport demos with the same signing key:
- MCP stdio
- MCP HTTP upstream
- HTTP fetch

## What The Demo Proves
- `MCP_STDIO` shows the baseline attack. The tool call is blocked and pipelock emits signed `allow` and `block` receipts for the call and the blocked response.
- `TAMPER TEST` flips one byte in a receipt signature. The inline verifier rejects it with `InvalidSignature`.
- `CHAIN-BREAK TEST` deletes a middle receipt from the JSONL file and shells out to `pipelock verify-receipt`. The Go verifier reports the exact sequence where the chain breaks.
- `MCP_HTTP_UPSTREAM` shows the same prompt-injection payload caught on the HTTP MCP surface.
- `FETCH` shows the same payload caught on the fetch proxy surface. The signed receipt records `layer=response_scan`.
- `ENCODED PAYLOAD VARIANTS` runs base64, gzip+base64, URL-encoded, Unicode-escaped, and Cyrillic homoglyph variants of the same payload. On the current branch, all five variants are caught.
- `demo_capability_separation.py` shows the same-user deployment limit. In this environment, the agent can delete `./evidence` or truncate `./evidence/*.jsonl`. Pipelock keeps blocking, but the on-disk evidence can be destroyed. Run pipelock as a different user than the agent if you want the evidence directory to survive an adversary with the agent's file permissions.

## What The Evidence Looks Like
This is an actual block receipt from one run of the harness. It came from the MCP stdio demo after `play_game` returned the injection payload:

```json
{
  "v": 1,
  "seq": 1,
  "ts": "2026-04-10T14:54:42.323260257Z",
  "session_id": "proxy",
  "type": "action_receipt",
  "transport": "mcp_stdio",
  "summary": "receipt: block unclassified mcp_stdio",
  "detail": {
    "version": 1,
    "action_record": {
      "version": 1,
      "action_id": "019d77e3-5c91-7ccb-ac8e-61fc4937340b",
      "action_type": "unclassified",
      "timestamp": "2026-04-10T14:54:42.323213838Z",
      "principal": "local",
      "actor": "pipelock",
      "target": "response:3",
      "side_effect_class": "none",
      "reversibility": "unknown",
      "policy_hash": "b28d3f9f54e2f6420b2d69989868c9ee08afac69c39ebd70ab555c01ea72a3cf",
      "verdict": "block",
      "transport": "mcp_stdio",
      "layer": "mcp_response_scan",
      "pattern": "Prompt Injection",
      "request_id": "3",
      "chain_prev_hash": "23f7168a500c8d8c2f50194b340082af16cb14955df3d31b9a14dc3ad64cb3b8",
      "chain_seq": 1
    },
    "signature": "ed25519:fed7f683db09bb576898c3dd44a9d392c95fe22f06987e78b1ae99dbebaede38d6cea0fef8ef5d9b2c91b64c08941d20efc609d6a5376119287e31b3b98b4902",
    "signer_key": "6b4f13acbab4498026e270a8d66e0ef87a8b20708089f173023234580f35de1c"
  }
}
```

The important fields are straightforward:
- `verdict` records what pipelock actually did.
- `layer` and `pattern` show why the response was blocked.
- `chain_prev_hash` and `chain_seq` link this receipt to the prior receipt in the session.
- `signature` and `signer_key` let anyone verify the record with the public key alone.

The receipt format is documented here: <https://pipelab.org/learn/action-receipt-spec/>

## Independent Verification
`demo.py` verifies every receipt inline with Python and the `cryptography` library. The chain-break subdemo also shells out to the Go CLI so the Python and Go verifiers agree on the same evidence file.

Two interchangeable verifiers are available.

The Go CLI ships with pipelock:

```bash
pipelock verify-receipt evidence/evidence-proxy-0.jsonl --key <public-key-hex>
```

The Python reference verifier is on PyPI as [`pipelock-verify`](https://pypi.org/project/pipelock-verify/) and mirrors the Go output byte-for-byte:

```bash
pip install pipelock-verify
python -m pipelock_verify evidence/evidence-proxy-0.jsonl --key <public-key-hex>
```

Both return exit 0 on success, 1 on failure. You can also inspect the public key that `demo.py` prints and verify the JSONL file yourself from any other implementation of the spec.

## Adapting The Demo For Your Own MCP Server
Swap `malicious_mcp_server.py` for your own server and keep the same `pipelock.yaml` shape.

For stdio mode, replace the subprocess command in `demo.py` with your server command. For HTTP mode, point `--upstream` at your real MCP endpoint. If you want to probe only one transport, comment out the others and keep the receipt verification code intact.

The harness is most useful when your server has an innocent tool description but a risky tool response body. That is the gap this example is meant to surface.

## Security Note
This example emits deliberate prompt-injection payloads for testing and demonstration. It is a detector harness, not a weapon.
