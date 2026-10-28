"""E2 Replay acceptance + unit tests (V2.2 spec sections 20 / 22).

Exercises the ReplayLab via FastAPI TestClient using RAW body bytes (content=)
so the signed bytes are exactly the transmitted/received bytes.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from labs.e2_replay.canonical import build_canonical
from labs.e2_replay.client import build_signed_request, make_nonce
from labs.e2_replay.hmac_auth import sign, verify
from labs.e2_replay.nonce_cache import ReplayGuard, ReplayError
from labs.e2_replay.server import ReplayLab, create_app

DEVICE = "dispenser-01"
SECRET = b"DEMO_LOCAL_ONLY_device_secret_dispenser_01"
PATH = "/protected/dispense"


@pytest.fixture
def lab() -> ReplayLab:
    return ReplayLab()


@pytest.fixture
def client(lab: ReplayLab) -> TestClient:
    return TestClient(create_app(lab))


# --------------------------- unit: canonicalization ---------------------------

@pytest.mark.unit
def test_raw_body_bytes_not_reserialized():
    """Two JSON encodings with identical semantics but different bytes must
    produce different canonical requests (spec section 11, FROZEN)."""
    a = b'{"a":1,"b":2}'
    b = b'{\n  "b": 2,\n  "a": 1\n}'
    ca = build_canonical("POST", PATH, "100", "n1", a)
    cb = build_canonical("POST", PATH, "100", "n1", b)
    assert ca != cb
    assert sign(SECRET, ca) != sign(SECRET, cb)


@pytest.mark.unit
def test_constant_time_verify_true_and_false():
    canonical = build_canonical("POST", PATH, "100", "n1", b"{}")
    good = sign(SECRET, canonical)
    assert verify(SECRET, canonical, good) is True
    assert verify(SECRET, canonical, "deadbeef") is False
    assert verify(SECRET, canonical, "") is False


@pytest.mark.unit
def test_nonce_ttl_must_cover_window():
    with pytest.raises(ValueError):
        ReplayGuard(accepted_window_s=300, nonce_ttl_s=60)


@pytest.mark.unit
def test_timestamp_window_and_nonce_reuse():
    g = ReplayGuard(accepted_window_s=300, nonce_ttl_s=600)
    now = 1_000_000.0
    g.check_timestamp(str(int(now)), now=now)
    with pytest.raises(ReplayError):
        g.check_timestamp(str(int(now - 1000)), now=now)  # too old
    g.check_nonce_unused("x", now=now)
    g.consume("x", now=now)
    with pytest.raises(ReplayError):
        g.check_nonce_unused("x", now=now)  # replay


# --------------------------- vulnerable baseline ------------------------------

@pytest.mark.security
def test_vulnerable_exact_replay_accepted(client: TestClient, lab: ReplayLab):
    body = b'{"device_id":"dispenser-01"}'
    r1 = client.post("/vulnerable/dispense", content=body,
                     headers={"content-type": "application/json"})
    r2 = client.post("/vulnerable/dispense", content=body,
                     headers={"content-type": "application/json"})
    assert r1.json()["status"] == "ACCEPT" and r1.json()["action_count"] == 1
    assert r2.json()["status"] == "ACCEPT" and r2.json()["action_count"] == 2
    assert lab.device(DEVICE).action_count == 2  # VULNERABLE baseline


# --------------------------- protected acceptance gate ------------------------

@pytest.mark.acceptance
def test_protected_first_accept_then_exact_replay_rejected(client, lab):
    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    r1 = client.post(PATH, content=raw, headers=headers)
    assert r1.status_code == 200 and r1.json()["status"] == "ACCEPT"
    assert r1.json()["action_count"] == 1
    # EXACT replay: identical bytes + headers
    r2 = client.post(PATH, content=raw, headers=headers)
    assert r2.status_code == 401 and r2.json()["status"] == "REJECT"
    assert lab.device(DEVICE).action_count == 1  # ACTION_COUNT unchanged


@pytest.mark.acceptance
def test_modified_nonce_old_signature_rejected(client, lab):
    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    client.post(PATH, content=raw, headers=headers)
    tampered = dict(headers)
    tampered["x-nonce"] = make_nonce()  # new nonce, stale signature
    r = client.post(PATH, content=raw, headers=tampered)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature mismatch"
    assert lab.device(DEVICE).action_count == 1


@pytest.mark.acceptance
def test_modified_timestamp_old_signature_rejected(client, lab):
    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    client.post(PATH, content=raw, headers=headers)
    tampered = dict(headers)
    tampered["x-timestamp"] = str(int(time.time()) + 1)
    tampered["x-nonce"] = make_nonce()  # avoid nonce-reuse short-circuit
    r = client.post(PATH, content=raw, headers=tampered)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature mismatch"
    assert lab.device(DEVICE).action_count == 1


@pytest.mark.acceptance
def test_modified_body_old_signature_rejected(client, lab):
    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    client.post(PATH, content=raw, headers=headers)
    tampered_headers = dict(headers)
    tampered_headers["x-nonce"] = make_nonce()
    r = client.post(PATH, content=b'{"cmd":"DISPENSE","qty":999}',
                    headers=tampered_headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "signature mismatch"
    assert lab.device(DEVICE).action_count == 1


@pytest.mark.acceptance
def test_audit_log_created(client, lab):
    raw, headers = build_signed_request(SECRET, PATH, {"cmd": "DISPENSE"}, DEVICE)
    client.post(PATH, content=raw, headers=headers)
    client.post(PATH, content=raw, headers=headers)  # replay
    events = [e["event"] for e in lab.audit_log]
    assert "ACCEPT" in events and "REJECT" in events
