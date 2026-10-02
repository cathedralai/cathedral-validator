#!/usr/bin/env python3
"""Localnet stand-in for the pinned TDX quote verifier. NOT A VERIFIER.

The direct validator loads this file only when CATHEDRAL_LOCALNET=1, and only
if its SHA-256 equals LOCALNET_STUB_QVL_DIGEST in
cathedral_thin/independent_runtime/localnet.py. It runs with the production
verifier's argument and output contract:

    stub_tdx_verifier.py QUOTE_PATH EXPECTED_REPORT_DATA_HEX

It accepts exactly one input shape: a quote minted by cathedral-sandbox's
localnet stub collector (cathedral/attest/localnet_stub.py),

    STUB_QUOTE_MAGIC || REPORT_DATA (64 bytes) || platform (32 bytes)

A real Intel TDX quote, or any other bytes, exits 1 (FAIL). REPORT_DATA is
compared exactly, so the channel binding (nonce, hotkey, TLS SPKI) is still
enforced end to end. The platform identity is a digest of the stub's platform
bytes, never a hardware PPID.
"""

import hashlib
import json
import sys

STUB_QUOTE_MAGIC = b"CATHEDRAL-LOCALNET-STUB-TDX-QUOTE-V1\x00"
REPORT_DATA_BYTES = 64
PLATFORM_BYTES = 32
PLATFORM_DOMAIN = b"cathedral.localnet-stub-platform\x00"


def main(argv):
    if len(argv) != 3:
        print("usage: stub_tdx_verifier.py QUOTE_PATH EXPECTED_REPORT_DATA_HEX", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as handle:
        quote = handle.read(4096)
    try:
        expected = bytes.fromhex(argv[2])
    except ValueError:
        return 2
    size = len(STUB_QUOTE_MAGIC) + REPORT_DATA_BYTES + PLATFORM_BYTES
    if len(quote) != size or not quote.startswith(STUB_QUOTE_MAGIC):
        print(json.dumps({"localnet_stub": True, "intel_verified": False,
                          "error": "not a localnet stub quote"}))
        return 1
    body = quote[len(STUB_QUOTE_MAGIC):]
    report_data = body[:REPORT_DATA_BYTES]
    platform = body[REPORT_DATA_BYTES:]
    stable = "tdx-platform-sha256:" + hashlib.sha256(PLATFORM_DOMAIN + platform).hexdigest()
    print(json.dumps({
        "localnet_stub": True,
        "intel_verified": True,
        "report_data_match": report_data == expected,
        "platform_identity_kind": "stable",
        "platform_identity_verified": True,
        "claims_bound_to_quote": True,
        "stable_platform_id": stable,
        "platform_id": stable,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
