"""Canonicalization rule - FROZEN (V2.2 spec sections 11 / 11.1).

The single most common HMAC implementation bug is the client and server
producing *different byte sequences* for the same logical request. The spec
therefore freezes the rule:

    canonical_body = RAW HTTP REQUEST BODY BYTES AS TRANSMITTED / RECEIVED

We never JSON-parse then re-serialize before signing. ``build_canonical``
accepts the ``bytes`` exactly as transmitted (client) or received (server).
"""

from __future__ import annotations

# Field separator inside the canonical byte string. A control byte that cannot
# appear in a method/path/timestamp/nonce keeps fields unambiguous.
_SEP = b"\x1e"  # ASCII record separator


def normalize_path(path: str) -> str:
    """Deterministic path normalization shared by client and server.

    - keep a single leading slash
    - strip a trailing slash except for root ``/``
    - query string is intentionally excluded (command APIs carry data in body)
    """
    path = path.split("?", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path


def build_canonical(
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    raw_body: bytes,
) -> bytes:
    """Build the canonical request bytes.

    ``raw_body`` MUST be the exact bytes transmitted (client) / received
    (server). ``timestamp`` and ``nonce`` use a fixed ASCII encoding and are
    covered by the signature (spec section 11.1).
    """
    if not isinstance(raw_body, (bytes, bytearray)):
        raise TypeError("raw_body must be bytes (the exact transmitted body)")
    parts = [
        method.upper().encode("ascii"),
        normalize_path(path).encode("utf-8"),
        timestamp.encode("ascii"),
        nonce.encode("ascii"),
        bytes(raw_body),
    ]
    return _SEP.join(parts)
