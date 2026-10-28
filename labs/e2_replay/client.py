"""E2 signing client - signs the EXACT raw bytes it transmits (spec section 11).

The client serializes the body once, keeps those bytes, signs *them*, and sends
*them* - guaranteeing the server verifies over identical bytes.
"""

from __future__ import annotations

import json
import secrets
import time

from .hmac_auth import sign_request


def make_nonce() -> str:
    return secrets.token_hex(16)


def build_signed_request(
    device_secret: bytes,
    path: str,
    body_obj: dict,
    device_id: str,
    timestamp: str | None = None,
    nonce: str | None = None,
) -> tuple[bytes, dict[str, str]]:
    """Return ``(raw_body_bytes, headers)`` for a signed POST.

    The returned ``raw_body_bytes`` are the exact bytes to transmit; the
    signature is computed over *those* bytes.
    """
    raw_body = json.dumps(body_obj, separators=(",", ":")).encode("utf-8")
    ts = timestamp if timestamp is not None else str(int(time.time()))
    nc = nonce if nonce is not None else make_nonce()
    sig = sign_request(device_secret, "POST", path, ts, nc, raw_body)
    headers = {
        "content-type": "application/json",
        "x-device-id": device_id,
        "x-timestamp": ts,
        "x-nonce": nc,
        "x-signature": sig,
    }
    return raw_body, headers
