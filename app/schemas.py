"""Pydantic request / response models."""

from __future__ import annotations

import ipaddress
from typing import Any

from pydantic import AliasChoices, BaseModel, Field, field_validator

DISCLAIMER = (
    "Heuristic triage signal only; not proof that content is malicious, synthetic or "
    "compromised. Do not use as the sole basis for identity, hiring, credit or access decisions."
)


class UrlScanRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048, examples=["https://example.com/login"])
    text: str | None = Field(
        default=None,
        max_length=5000,
        description="Optional email/page text for the urgency and credential-harvesting check.",
    )


class BatchScanRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=50)

    @field_validator("urls")
    @classmethod
    def _limit_len(cls, v: list[str]) -> list[str]:
        if any(len(u) > 2048 for u in v):
            raise ValueError("each URL must be at most 2048 characters")
        return v


class ScanLogRequest(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    failed_attempts: int = Field(default=0, ge=0, le=10_000)
    ip_address: str | None = Field(
        default=None, max_length=45, validation_alias=AliasChoices("ip_address", "ip")
    )
    user_agent: str | None = Field(
        default=None, max_length=512, validation_alias=AliasChoices("user_agent", "device")
    )
    country: str | None = Field(default=None, pattern=r"^[A-Za-z]{2}$")
    asn: str | None = Field(default=None, max_length=32)

    @field_validator("ip_address")
    @classmethod
    def _valid_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            return str(ipaddress.ip_address(v.strip()))
        except ValueError as exc:
            raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from exc


class FindingOut(BaseModel):
    module: str
    code: str
    points: int
    explanation: str


class ScanResponse(BaseModel):
    request_id: str
    module: str
    risk_score: int = Field(ge=0, le=100)
    risk_tier: str
    decision: str
    summary: str
    recommended_action: str
    module_scores: dict[str, int]
    findings: list[FindingOut]
    evidence: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    disclaimer: str = DISCLAIMER


class BatchItem(BaseModel):
    url: str
    result: ScanResponse | None = None
    error: str | None = None


class BatchResponse(BaseModel):
    request_id: str
    count: int
    highest_risk_score: int
    results: list[BatchItem]
