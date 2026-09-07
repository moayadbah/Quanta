"""FastAPI application factory (§4.2).

A design property worth stating plainly: **the API process never touches repository
content.** It validates a URL, writes a job record and reads a file. Every byte of
untrusted input is handled in a short-lived child process. That is why the service is
cheap to secure — the dangerous half of the pipeline was never deployed here (§4.3).

Errors leave as RFC 9457 ``application/problem+json`` carrying the stable ``error_code``
from :data:`quanta.errors.ERROR_CODES`. Internal exceptions and tracebacks are never
serialised to a client (§5.2.4).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from quanta.config import get_settings
from quanta.errors import Reject
from quanta.version import __version__
from quanta.web.jobs import JobRegistry
from quanta.web.routes import router

log = structlog.get_logger()

STATIC_DIR = Path(__file__).resolve().parent / "static"

#: CSP for the single-page app. JavaScript and CSS are served as separate files
#: specifically so this needs no ``'unsafe-inline'`` — an inline-script allowance would
#: defeat most of the protection CSP offers. ``frame-src 'self'`` permits the sandboxed
#: iframe that embeds the canonical report.
SPA_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "connect-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "frame-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

SPA_HEADERS = {
    "Content-Security-Policy": SPA_CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "no-referrer",
}


def problem(
    status: int,
    title: str,
    error_code: str,
    detail: str = "",
    correlation_id: str | None = None,
) -> JSONResponse:
    """An RFC 9457 problem document (§5.2.4)."""
    return JSONResponse(
        status_code=status,
        media_type="application/problem+json",
        headers=SPA_HEADERS,
        content={
            "type": "about:blank",
            "title": title,
            "status": status,
            "error_code": error_code,
            "detail": detail,
            "correlation_id": correlation_id or str(uuid.uuid4()),
        },
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    registry: JobRegistry = app.state.registry
    try:
        yield
    finally:
        registry.shutdown()


def create_app(artifact_root: Path | None = None, db_path: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="Quanta",
        version=__version__,
        description="Cryptographic agility measurement for Python repositories.",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )

    cfg = get_settings()
    root = artifact_root or cfg.artifact_root
    database = db_path or (root.parent / "quanta.db" if artifact_root else cfg.db)
    app.state.registry = JobRegistry(root, database, cfg)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return problem(
            422, "Invalid request", "SCHEMA_INVALID", "Request body does not match the API schema."
        )

    @app.exception_handler(HTTPException)
    async def _http_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return problem(
            exc.status_code,
            "Request failed",
            "NOT_FOUND" if exc.status_code == 404 else "SCHEMA_INVALID",
        )

    @app.exception_handler(Reject)
    async def _reject_handler(request: Request, exc: Reject) -> JSONResponse:
        """A refused input is a client answer, not an incident."""
        return problem(
            status=exc.http_status,
            title=exc.code.replace("_", " ").title(),
            error_code=exc.code,
            detail=exc.detail,
        )

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        """Log with a correlation id; return the id, never the traceback (§5.2.4, A09)."""
        correlation_id = str(uuid.uuid4())
        log.error(
            "unhandled_error",
            correlation_id=correlation_id,
            error_type=type(exc).__name__,
            path=request.url.path,
        )
        return problem(
            status=500,
            title="Internal error",
            error_code="INTERNAL",
            detail="An internal error occurred. Quote the correlation id when reporting it.",
            correlation_id=correlation_id,
        )

    @app.middleware("http")
    async def _security_headers(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        # The report route sets its own, stricter, policy — never override it.
        if "Content-Security-Policy" not in response.headers:
            for header, value in SPA_HEADERS.items():
                response.headers[header] = value
        return response

    app.include_router(router, prefix="/api/v1")

    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")

    return app
