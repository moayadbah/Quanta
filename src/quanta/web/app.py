"""FastAPI application factory (§4.2).

Repository acquisition and analysis run in separate local processes or cloud microVMs.
The API handles authentication, durable jobs, bounded fix review, and GitHub publication.
It never imports or executes repository code.

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
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from quanta.config import get_settings
from quanta.errors import Reject
from quanta.resources import asset_path
from quanta.version import __version__
from quanta.web import assets
from quanta.web.auth import Auth
from quanta.web.auth import router as auth_router
from quanta.web.cloud import router as cloud_router
from quanta.web.documents import router as documents_router
from quanta.web.jobs import JobRegistry
from quanta.web.product import router as product_router
from quanta.web.review import router as review_router
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
    # Signed-in users see their GitHub avatar; images only, no other external origin.
    "img-src 'self' data: https://avatars.githubusercontent.com; "
    "font-src 'self'; "
    "frame-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

#: Public, per-deploy data the home page reads; everything else under /api stays private.
PUBLIC_API = frozenset({"/api/v1/sample", "/api/v1/standards"})

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
    app.state.auth = Auth(
        app.state.registry.db, cfg.auth, durable_required=cfg.deployment == "vercel"
    )

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
        path = request.url.path
        if path in PUBLIC_API and request.method == "GET" and response.status_code == 200:
            # The same for every visitor and fixed per deploy: the home page's data.
            response.headers["Cache-Control"] = "public, max-age=300, stale-while-revalidate=86400"
        elif path.startswith(("/api/", "/auth/")):
            response.headers["Cache-Control"] = "private, no-store"
        elif "Cache-Control" not in response.headers and response.status_code == 200:
            response.headers["Cache-Control"] = assets.cache_control(path.lstrip("/"))
        # The report route sets its own, stricter, policy — never override it.
        if "Content-Security-Policy" not in response.headers:
            for header, value in SPA_HEADERS.items():
                response.headers[header] = value
        return response

    app.include_router(auth_router)
    app.include_router(product_router, prefix="/api/v1")
    app.include_router(review_router, prefix="/api/v1")
    app.include_router(cloud_router, prefix="/api/v1")
    app.include_router(documents_router, prefix="/api/v1")
    app.include_router(router, prefix="/api/v1")

    @app.get("/content/site.json", include_in_schema=False)
    def site_content() -> FileResponse:
        """Every visible string, in English and Arabic (``content/site.json``)."""
        return FileResponse(
            asset_path("content/site.json"),
            media_type="application/json",
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/_v/{build}/content/site.json", include_in_schema=False)
    def versioned_content(build: str) -> FileResponse:
        current = build == assets.build_id()
        return FileResponse(
            asset_path("content/site.json"),
            media_type="application/json",
            headers={"Cache-Control": assets.IMMUTABLE if current else "no-cache"},
        )

    @app.get("/_v/{build}/{path:path}", include_in_schema=False)
    def versioned(build: str, path: str) -> FileResponse:
        """Static files under a build hash: cached for a year, never stale."""
        found = assets.static_file(path)
        if found is None:
            raise HTTPException(status_code=404)
        # An older page asking for its build gets today's file, uncached under that key.
        current = build == assets.build_id()
        return FileResponse(
            found, headers={"Cache-Control": assets.IMMUTABLE if current else "no-cache"}
        )

    def _page(request: Request, name: str) -> Response:
        lang = assets.page_language(
            request.query_params.get("lang"),
            request.cookies.get("quanta-language"),
            request.headers.get("accept-language"),
        )
        account, login = "", ""
        if name == "workspace.html":
            service: Auth = app.state.auth
            identity = service.identity(request, required=False)
            if not service.settings.required:
                account = "local"
            elif identity:
                account, login = "user", identity.login
            else:
                account = "doors"
        page = assets.render_page(name, lang, account)
        if account:
            page = assets.workspace_state(page, account, login, lang)
        return Response(
            page,
            media_type="text/html; charset=utf-8",
            headers=assets.page_headers(),
        )

    @app.get("/", include_in_schema=False)
    def home(request: Request) -> Response:
        return _page(request, "index.html")

    @app.get("/index.html", include_in_schema=False)
    def home_file(request: Request) -> Response:
        return _page(request, "index.html")

    @app.get("/workspace.html", include_in_schema=False)
    def workspace(request: Request) -> Response:
        return _page(request, "workspace.html")

    @app.get("/privacy.html", include_in_schema=False)
    def privacy(request: Request) -> Response:
        return _page(request, "privacy.html")

    if STATIC_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="spa")

    return app
