"""FastAPI application factory."""

from __future__ import annotations

import uuid

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1 import router as v1_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.modules.ato.engine import ATOEngine


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    log = get_logger("app")

    app = FastAPI(title=settings.app_name, version=settings.app_version)
    app.state.settings = settings
    app.state.ato = ATOEngine()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.origins,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        rid = uuid.uuid4().hex
        request.state.request_id = rid
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid, path=request.url.path)
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        log.error("unhandled_error", error=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "request_id": getattr(request.state, "request_id", ""),
            },
        )

    app.include_router(v1_router, prefix="/api/v1")

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": settings.app_version}

    @app.get("/readyz", tags=["ops"])
    def readyz() -> dict[str, str]:
        return {"status": "ready"}

    return app


app = create_app()
