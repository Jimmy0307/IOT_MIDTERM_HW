"""Replay protection: timestamp window + nonce cache (V2.2 spec sections 14-15, 19).

Both controls are required and must be used together:
  - timestamp window bounds how old an accepted request may be
  - nonce cache rejects re-use of a nonce still inside that window

The cache is intentionally in-memory for this lab; the restart residual risk is
documented and tested as E2_RESIDUAL_RISK (spec section 19).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class ReplayError(Exception):
    """Raised when a request fails a freshness / replay check."""


@dataclass
class ReplayGuard:
    """Timestamp-window + nonce-cache replay guard.

    ``accepted_window_s``: max age of an accepted request (spec: ~5 min).
    ``nonce_ttl_s``: how long a consumed nonce is remembered (spec: 5-10 min,
    must cover the full window so a nonce cannot be replayed while still valid).
    """

    accepted_window_s: int = 300
    nonce_ttl_s: int = 600
    _consumed: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.nonce_ttl_s < self.accepted_window_s:
            raise ValueError(
                "nonce_ttl_s must be >= accepted_window_s or a nonce could be "
                "replayed while still inside the timestamp window"
            )

    def _purge(self, now: float) -> None:
        expired = [n for n, exp in self._consumed.items() if exp <= now]
        for n in expired:
            del self._consumed[n]

    def check_timestamp(self, timestamp: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        try:
            ts = float(timestamp)
        except (TypeError, ValueError) as exc:
            raise ReplayError("invalid timestamp format") from exc
        age = now - ts
        if age > self.accepted_window_s:
            raise ReplayError(f"timestamp too old (age={age:.1f}s)")
        if age < -self.accepted_window_s:
            raise ReplayError(f"timestamp too far in future (age={age:.1f}s)")

    def check_nonce_unused(self, nonce: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._purge(now)
        if not nonce:
            raise ReplayError("missing nonce")
        if nonce in self._consumed:
            raise ReplayError("nonce already consumed (replay)")

    def consume(self, nonce: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._consumed[nonce] = now + self.nonce_ttl_s

    def active_nonce_count(self) -> int:
        self._purge(time.time())
        return len(self._consumed)
