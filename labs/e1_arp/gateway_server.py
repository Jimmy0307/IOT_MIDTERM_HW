"""E1 gateway / destination server: HTTP (plaintext) + HTTPS (TLS).

Serves a recognizable token so we can prove, from the attacker's PCAP, that the
token is visible over HTTP but NOT over correctly-validated HTTPS.

Runs inside the isolated e1_net only (scope section 0).
"""

from __future__ import annotations

import http.server
import socketserver
import ssl
import subprocess
import threading
from pathlib import Path

TOKEN = "SECRET_TELEMETRY_TOKEN_12345"  # DEMO marker, not a real secret
CERT = Path("/lab/server.crt")
KEY = Path("/lab/server.key")
GATEWAY_IP = "10.77.0.2"


def ensure_cert() -> None:
    """Generate a self-signed cert with SAN for the gateway IP + hostname."""
    if CERT.exists() and KEY.exists():
        return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(KEY), "-out", str(CERT), "-days", "7",
            "-subj", "/CN=gateway",
            "-addext", f"subjectAltName=DNS:gateway,IP:{GATEWAY_IP}",
        ],
        check=True,
    )


class Handler(http.server.BaseHTTPRequestHandler):
    def _respond(self, scheme: str) -> None:
        body = (
            f"scheme={scheme} path={self.path} token={TOKEN} "
            f"server=gateway\n"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._respond(self.server.scheme)  # type: ignore[attr-defined]

    def log_message(self, *args) -> None:  # silence
        return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    scheme = "http"


def serve_http() -> None:
    srv = Server(("0.0.0.0", 80), Handler)
    srv.scheme = "http"
    srv.serve_forever()


def serve_https() -> None:
    srv = Server(("0.0.0.0", 443), Handler)
    srv.scheme = "https"
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT), keyfile=str(KEY))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def main() -> None:
    ensure_cert()
    threading.Thread(target=serve_http, daemon=True).start()
    threading.Thread(target=serve_https, daemon=True).start()
    print("gateway serving http:80 and https:443", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
