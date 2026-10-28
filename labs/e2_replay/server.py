"""E2 Replay lab FastAPI backend: vulnerable + protected command endpoints.

Trust boundary TB-B / TB-D (message authentication + freshness).

- ``/vulnerable/dispense``: no request authentication -> exact replay accepted.
- ``/protected/dispense``: HMAC over the *raw received body bytes* + timestamp
  window + nonce cache + constant-time comparison + audit log.

The server reads the exact raw body (``await request.body()``) and rebuilds the
canonical request from those bytes - it never JSON-parses then re-serializes
before verifying (spec section 11, FROZEN).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .canonical import build_canonical
from .device import Device
from .hmac_auth import verify
from .nonce_cache import ReplayGuard, ReplayError

# --- Per-device secrets (spec 18.1: per-device key, never a global shared one) ---
# DEMO / LOCAL ONLY lab credentials. Never a production secret.
_DEMO_SECRETS: dict[str, bytes] = {
    "dispenser-01": b"DEMO_LOCAL_ONLY_device_secret_dispenser_01",
    "dispenser-02": b"DEMO_LOCAL_ONLY_device_secret_dispenser_02",
}


def load_device_secrets() -> dict[str, bytes]:
    """Per-device secrets, overridable via env ``E2_SECRET_<DEVICE>`` for labs."""
    secrets = dict(_DEMO_SECRETS)
    for key, value in os.environ.items():
        if key.startswith("E2_SECRET_"):
            dev = key[len("E2_SECRET_"):].lower().replace("_", "-")
            secrets[dev] = value.encode("utf-8")
    return secrets


@dataclass
class ReplayLab:
    """Holds all in-memory lab state so tests and runners can inspect it."""

    secrets: dict[str, bytes] = field(default_factory=load_device_secrets)
    devices: dict[str, Device] = field(default_factory=dict)
    guard: ReplayGuard = field(default_factory=ReplayGuard)
    audit_log: list[dict] = field(default_factory=list)

    def device(self, device_id: str) -> Device:
        return self.devices.setdefault(device_id, Device(device_id=device_id))

    def audit(self, event: str, device_id: str, nonce: str, reason: str) -> None:
        self.audit_log.append(
            {"event": event, "device_id": device_id, "nonce": nonce, "reason": reason}
        )


def create_app(lab: ReplayLab | None = None) -> FastAPI:
    lab = lab or ReplayLab()
    app = FastAPI(title="E2 Replay Lab")
    app.state.lab = lab

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "lab": "e2_replay"}

    # --- Vulnerable: no authentication, no freshness. Exact replay succeeds. ---
    @app.post("/vulnerable/dispense")
    async def vulnerable_dispense(request: Request) -> JSONResponse:
        import json as _json

        raw = await request.body()
        try:
            payload = _json.loads(raw or b"{}")
        except ValueError:
            return JSONResponse({"error": "bad json"}, status_code=400)
        device_id = payload.get("device_id", "dispenser-01")
        rec = lab.device(device_id).dispense(nonce="(none)", timestamp="(none)")
        return JSONResponse({"status": "ACCEPT", "mode": "vulnerable", **rec})

    # --- Protected: HMAC(raw body) + timestamp window + nonce cache. ---
    @app.post("/protected/dispense")
    async def protected_dispense(request: Request) -> JSONResponse:
        raw = await request.body()  # EXACT received bytes - do not re-serialize
        ts = request.headers.get("x-timestamp", "")
        nonce = request.headers.get("x-nonce", "")
        sig = request.headers.get("x-signature", "")
        device_id = request.headers.get("x-device-id", "dispenser-01")

        secret = lab.secrets.get(device_id)
        if secret is None:
            lab.audit("REJECT", device_id, nonce, "unknown device")
            return JSONResponse(
                {"status": "REJECT", "reason": "unknown device"}, status_code=401
            )

        # 1. timestamp window, 2. nonce unused (spec section 14)
        try:
            lab.guard.check_timestamp(ts)
            lab.guard.check_nonce_unused(nonce)
        except ReplayError as exc:
            lab.audit("REJECT", device_id, nonce, str(exc))
            return JSONResponse(
                {"status": "REJECT", "reason": str(exc)}, status_code=401
            )

        # 3. rebuild canonical from RECEIVED bytes, 4. verify HMAC (constant-time)
        canonical = build_canonical("POST", request.url.path, ts, nonce, raw)
        if not verify(secret, canonical, sig):
            lab.audit("REJECT", device_id, nonce, "signature mismatch")
            return JSONResponse(
                {"status": "REJECT", "reason": "signature mismatch"}, status_code=401
            )

        # 5. execute, 6. mark nonce consumed, 7. audit
        rec = lab.device(device_id).dispense(nonce=nonce, timestamp=ts)
        lab.guard.consume(nonce)
        lab.audit("ACCEPT", device_id, nonce, "valid signed request")
        return JSONResponse({"status": "ACCEPT", "mode": "protected", **rec})

    return app
