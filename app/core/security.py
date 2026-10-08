"""Optional API-key authentication for scan endpoints."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(request: Request, key: str | None = Security(_api_key_header)) -> None:
    """If API_KEY is configured, require a matching X-API-Key header (constant-time compare)."""
    expected = request.app.state.settings.api_key
    if not expected:
        return
    if not key or not hmac.compare_digest(key.encode(), expected.encode()):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
