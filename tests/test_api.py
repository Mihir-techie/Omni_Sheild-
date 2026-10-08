import io

import numpy as np
import pytest
from fastapi.testclient import TestClient
from PIL import Image

from app.core.config import Settings
from app.main import create_app


def client(**overrides) -> TestClient:
    return TestClient(create_app(Settings(_env_file=None, **overrides)))


def test_health_and_ready():
    c = client()
    assert c.get("/healthz").json()["status"] == "ok"
    assert c.get("/readyz").status_code == 200


def test_scan_url_and_alias_return_same_shape():
    c = client()
    for path in ("/api/v1/scan-url", "/api/v1/phishing/scan"):
        r = c.post(path, json={"url": "http://192.168.1.5/verify"})
        assert r.status_code == 200
        body = r.json()
        assert body["module"] == "phishing" and body["risk_tier"] in {"Low", "Medium", "High"}
        assert body["findings"] and body["request_id"] and "X-Request-ID" in r.headers


def test_invalid_url_gives_422():
    assert client().post("/api/v1/scan-url", json={"url": "ftp://x.com"}).status_code == 422


def test_batch_limits_and_partial_errors():
    c = client()
    r = c.post("/api/v1/scan-batch", json={"urls": ["https://example.com", "ftp://bad"]})
    body = r.json()
    assert body["count"] == 2 and body["results"][1]["error"]
    assert c.post("/api/v1/scan-batch", json={"urls": []}).status_code == 422
    assert c.post("/api/v1/scan-batch", json={"urls": ["https://a.com"] * 51}).status_code == 422


def test_api_key_enforced_when_configured():
    c = client(api_key="s3cret")
    body = {"url": "https://example.com"}
    assert c.post("/api/v1/scan-url", json=body).status_code == 401
    assert c.post("/api/v1/scan-url", json=body, headers={"X-API-Key": "nope"}).status_code == 401
    assert c.post("/api/v1/scan-url", json=body, headers={"X-API-Key": "s3cret"}).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_ato_flow_via_api():
    c = client()
    base = {"username": "a@b.com", "ip_address": "203.0.113.5", "country": "IN", "device": "Chrome Windows"}
    assert c.post("/api/v1/ato/scan-log", json=base).json()["risk_score"] == 0
    r = c.post("/api/v1/ato/scan-log", json={**base, "failed_attempts": 30, "country": "RU"})
    body = r.json()
    assert body["decision"] == "block" and body["module"] == "ato"
    assert "a@b.com" not in r.text


def test_ato_rejects_bad_ip():
    r = client().post("/api/v1/ato/scan-log", json={"username": "x", "ip_address": "999.1.1.1"})
    assert r.status_code == 422


def _png() -> bytes:
    buf = io.BytesIO()
    Image.fromarray(np.random.default_rng(0).integers(0, 255, (128, 128), dtype=np.uint8)).save(buf, "PNG")
    return buf.getvalue()


def test_deepfake_upload_ok_unsupported_and_too_large():
    c = client(max_upload_bytes=50_000)
    ok = c.post("/api/v1/deepfake/scan", files={"file": ("a.png", _png(), "image/png")})
    assert ok.status_code == 200 and ok.json()["module"] == "deepfake"
    bad = c.post("/api/v1/deepfake/scan", files={"file": ("a.exe", b"MZ" + b"0" * 100, "image/png")})
    assert bad.status_code == 415
    big = c.post("/api/v1/deepfake/scan", files={"file": ("a.png", b"\x89PNG" + b"0" * 60_000, "image/png")})
    assert big.status_code == 413
    empty = c.post("/api/v1/deepfake/scan", files={"file": ("a.png", b"", "image/png")})
    assert empty.status_code == 422
