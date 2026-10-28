"""Deterministic device action for the replay demo (V2.2 spec section 16).

We avoid the ambiguous ``OPEN`` state (already-open + OPEN again is
indistinguishable). Instead DISPENSE increments a counter so replay success is
unambiguous:

    first request        -> action_count = 1
    successful replay     -> action_count = 2
    blocked replay        -> action_count stays 1
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Device:
    """A lab IoT actuator with an observable, monotonically increasing counter."""

    device_id: str
    action_count: int = 0
    history: list[dict] = field(default_factory=list)

    def dispense(self, nonce: str, timestamp: str) -> dict:
        """Perform the business action and record it."""
        self.action_count += 1
        record = {
            "action": "DISPENSE",
            "action_count": self.action_count,
            "nonce": nonce,
            "timestamp": timestamp,
        }
        self.history.append(record)
        return record
