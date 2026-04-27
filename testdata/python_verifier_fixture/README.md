# Python verifier — cross-implementation conformance for v2.4 learn-and-lock

Independently verifies the Ed25519 signatures on Go-emitted golden vectors,
proving byte-identical JCS canonicalization between the Go and Python
implementations.

## Usage

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 verify.py ../../internal/contract/testdata/golden/
```

Output: `OK <fixture>` per fixture or `FAIL <fixture>: <reason>`.
Exits 0 on full success, 1 on any failure.

## CI integration

The Go-side shim test `internal/contract/python_roundtrip_test.go` runs this
verifier when `python3` is available and is skipped under `go test -short`.
