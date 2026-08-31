#!/usr/bin/env python3
"""Serve fixed corrupt bytes as github.com inside one disposable test VM."""

from __future__ import annotations

import argparse
import http.server
import ssl
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    body: bytes = b""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"TAMPERED_ORIGIN {self.address_string()} {format % args}", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--body", required=True, type=Path)
    args = parser.parse_args()
    Handler.body = args.body.read_bytes()
    if not Handler.body:
        raise SystemExit("tampered response body must not be empty")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
