"""HMAC signing / verification with constant-time comparison.

Spec sections 12 (HMAC), 13 (constant-time comparison), 18.1 (per-device key).
"""

from __future__ import annotations

import hashlib
import hmac

from .canonical import build_canonical


def sign(device_secret: bytes, canonical_request: bytes) -> str:
    """signature = HMAC-SHA256(device_secret, canonical_request) -> hex."""
    return hmac.new(device_secret, canonical_request, hashlib.sha256).hexdigest()


def sign_request(
    device_secret: bytes,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    raw_body: bytes,
) -> str:
    """Convenience: build canonical request from parts and sign it."""
    canonical = build_canonical(method, path, timestamp, nonce, raw_body)
    return sign(device_secret, canonical)


def verify(device_secret: bytes, canonical_request: bytes, provided_sig: str) -> bool:
    """Constant-time signature verification (spec section 13).

    Uses ``hmac.compare_digest`` - never ``received == expected`` - to reduce
    timing side-channels.
    """
    expected = sign(device_secret, canonical_request)
    return hmac.compare_digest(expected, provided_sig or "")
