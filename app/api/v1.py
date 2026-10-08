"""Versioned scan endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool

from app.core.logging import get_logger
from app.core.security import require_api_key
from app.modules.deepfake import engine as deepfake
from app.modules.phishing import engine as phishing
from app.schemas import (
    BatchItem,
    BatchResponse,
    BatchScanRequest,
    FindingOut,
    ScanLogRequest,
    ScanResponse,
    UrlScanRequest,
)
from app.shared.models import ModuleResult
from app.shared.xai_engine import aggregate

router = APIRouter(dependencies=[Depends(require_api_key)])
log = get_logger("audit")


def _respond(request: Request, result: ModuleResult, **audit: object) -> ScanResponse:
    report = aggregate([result])
    log.info(
        "scan_completed",
        module=result.module,
        risk_score=report.score,
        risk_tier=report.tier,
        decision=report.decision,
        **audit,
    )
    return ScanResponse(
        request_id=getattr(request.state, "request_id", ""),
        module=result.module,
        risk_score=report.score,
        risk_tier=report.tier,
        decision=report.decision,
        summary=report.summary,
        recommended_action=report.recommended_action,
        module_scores=report.module_scores,
        findings=[FindingOut(**vars(f)) for f in report.findings],
        evidence=result.evidence,
        notes=result.notes,
    )


def _scan_url(request: Request, body: UrlScanRequest) -> ScanResponse:
    try:
        result = phishing.analyze(body.url, body.text)
    except phishing.InvalidURLError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _respond(request, result, target_host=result.evidence.get("host"))


@router.post("/scan-url", response_model=ScanResponse, tags=["phishing"])
def scan_url(request: Request, body: UrlScanRequest) -> ScanResponse:
    return _scan_url(request, body)


@router.post("/phishing/scan", response_model=ScanResponse, tags=["phishing"])
def phishing_scan(request: Request, body: UrlScanRequest) -> ScanResponse:
    return _scan_url(request, body)


@router.post("/scan-batch", response_model=BatchResponse, tags=["phishing"])
def scan_batch(request: Request, body: BatchScanRequest) -> BatchResponse:
    items: list[BatchItem] = []
    for url in body.urls:
        try:
            result = phishing.analyze(url)
            items.append(BatchItem(url=url, result=_respond(request, result)))
        except phishing.InvalidURLError as exc:
            items.append(BatchItem(url=url, error=str(exc)))
    top = max((i.result.risk_score for i in items if i.result), default=0)
    return BatchResponse(
        request_id=getattr(request.state, "request_id", ""),
        count=len(items),
        highest_risk_score=top,
        results=items,
    )


@router.post("/deepfake/scan", response_model=ScanResponse, tags=["deepfake"])
async def deepfake_scan(request: Request, file: UploadFile = File(...)) -> ScanResponse:
    limit = request.app.state.settings.max_upload_bytes
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit + 1_048_576:
        raise HTTPException(status_code=413, detail="Upload too large")
    buf = bytearray()
    while chunk := await file.read(64 * 1024):
        buf.extend(chunk)
        if len(buf) > limit:
            raise HTTPException(status_code=413, detail=f"Upload exceeds {limit} bytes")
    if not buf:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")
    try:
        result = await run_in_threadpool(deepfake.analyze, bytes(buf))
    except deepfake.UnsupportedMediaError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except deepfake.MediaError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _respond(request, result, media_format=result.evidence.get("format"))


@router.post("/ato/scan-log", response_model=ScanResponse, tags=["ato"])
def ato_scan_log(request: Request, body: ScanLogRequest) -> ScanResponse:
    result = request.app.state.ato.analyze(
        username=body.username,
        failed_attempts=body.failed_attempts,
        ip=body.ip_address,
        user_agent=body.user_agent,
        country=body.country,
        asn=body.asn,
    )
    return _respond(request, result, account_ref=result.evidence.get("account_ref"))
