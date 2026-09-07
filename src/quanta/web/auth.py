"""GitHub OAuth with PKCE, one-time state, encrypted tokens and opaque sessions."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse

from quanta.config import AuthSettings
from quanta.errors import Reject
from quanta.web.db import Database, timestamp

router = APIRouter(prefix="/auth")


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def github_client(token: str) -> httpx.Client:
    return httpx.Client(
        base_url="https://api.github.com",
        timeout=15,
        follow_redirects=False,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Quanta",
        },
    )


@dataclass(frozen=True)
class Identity:
    user_id: str
    login: str
    token: str = field(repr=False)
    csrf: str = field(repr=False)


class Auth:
    def __init__(
        self, db: Database, settings: AuthSettings, *, durable_required: bool = False
    ) -> None:
        self.db = db
        self.settings = settings
        self.durable_required = durable_required
        self.secure = settings.public_url.startswith("https://")
        self.cookie = "__Host-quanta" if self.secure else "quanta-local"
        self.state_cookie = "__Host-quanta-state" if self.secure else "quanta-state-local"
        self.cipher: Fernet | None = None
        key = settings.encryption_key.get_secret_value()
        if key:
            try:
                self.cipher = Fernet(key.encode())
            except (ValueError, TypeError) as exc:
                raise ValueError("QUANTA_AUTH__ENCRYPTION_KEY must be a Fernet key") from exc

    @property
    def configured(self) -> bool:
        return bool(
            self.cipher
            and self.settings.github_client_id
            and self.settings.github_client_secret.get_secret_value()
            and (self.db.url or not self.durable_required)
        )

    def require_configuration(self) -> None:
        if not self.configured:
            raise Reject("AUTH_UNAVAILABLE", "GitHub sign-in is being configured. Try the sample.")

    def identity(self, request: Request, *, required: bool = True) -> Identity | None:
        raw = request.cookies.get(self.cookie, "")
        row = None
        if raw and len(raw) <= 128:
            with self.db.connect() as conn:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE id=? AND expires_at>?",
                    (fingerprint(raw), timestamp()),
                ).fetchone()
        if row and self.cipher:
            try:
                token = self.cipher.decrypt(row["token"].encode()).decode()
                return Identity(row["user_id"], row["login"], token, row["csrf"])
            except InvalidToken:
                pass
        if required:
            raise Reject("AUTH_REQUIRED", "Sign in with GitHub to continue.")
        return None

    def csrf(self, request: Request, identity: Identity) -> None:
        if request.headers.get("origin") != self.settings.public_url.rstrip(
            "/"
        ) or not secrets.compare_digest(request.headers.get("x-csrf-token", ""), identity.csrf):
            raise Reject("CSRF_INVALID", "Refresh the page and try again.")

    def own(self, job_id: str, identity: Identity) -> None:
        with self.db.connect() as conn:
            found = conn.execute(
                "SELECT 1 FROM analysis_access WHERE job_id=? AND user_id=?",
                (job_id, identity.user_id),
            ).fetchone()
        if not found:
            raise Reject("REPO_NOT_FOUND", "no such analysis")

    def create_session(self, identity: Identity, lifetime: int | None = None) -> str:
        self.require_configuration()
        if self.cipher is None:
            raise Reject("AUTH_UNAVAILABLE")
        raw = secrets.token_urlsafe(32)
        seconds = min(lifetime or 86400, self.settings.session_hours * 3600)
        with self.db.connect(write=True) as conn:
            conn.execute("DELETE FROM sessions WHERE expires_at<?", (timestamp(),))
            conn.execute(
                "INSERT INTO sessions(id,user_id,login,token,csrf,expires_at) VALUES(?,?,?,?,?,?)",
                (
                    fingerprint(raw),
                    identity.user_id,
                    identity.login,
                    self.cipher.encrypt(identity.token.encode()).decode(),
                    identity.csrf,
                    timestamp(time.time() + seconds),
                ),
            )
        return raw


def auth(request: Request) -> Auth:
    service: Auth = request.app.state.auth
    return service


@router.get("/login")
def login(request: Request) -> RedirectResponse:
    service = auth(request)
    service.require_configuration()
    # Opaque per-hour keys cap anonymous state creation across function instances.
    ip = request.client.host if request.client else "unknown"
    bucket = "oauth:" + fingerprint(ip) + ":" + timestamp()[:13]
    with service.db.connect(write=True) as conn:
        conn.execute(
            "INSERT INTO usage_counters(id,used) VALUES(?,0) ON CONFLICT(id) DO NOTHING", (bucket,)
        )
        if not conn.execute(
            "UPDATE usage_counters SET used=used+1 WHERE id=? AND used<20", (bucket,)
        ).rowcount:
            raise Reject("RATE_LIMITED", "Too many sign-in attempts. Try again later.")
    state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=")
    with service.db.connect(write=True) as conn:
        conn.execute("DELETE FROM oauth_states WHERE expires_at<?", (timestamp(),))
        conn.execute(
            "INSERT INTO oauth_states(id,verifier,expires_at) VALUES(?,?,?)",
            (fingerprint(state), verifier, timestamp(time.time() + 600)),
        )
    query = urlencode(
        {
            "client_id": service.settings.github_client_id,
            "redirect_uri": service.settings.public_url.rstrip("/") + "/auth/callback",
            "scope": "read:user public_repo",
            "state": state,
            "code_challenge": challenge.decode(),
            "code_challenge_method": "S256",
        }
    )
    response = RedirectResponse(
        "https://github.com/login/oauth/authorize?" + query, status_code=303
    )
    response.set_cookie(
        service.state_cookie,
        state,
        max_age=600,
        secure=service.secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@router.get("/callback")
def callback(request: Request, code: str = "", state: str = "") -> RedirectResponse:
    service = auth(request)
    service.require_configuration()
    saved = request.cookies.get(service.state_cookie, "")
    if not state or len(state) > 128 or not secrets.compare_digest(state, saved):
        raise Reject("AUTH_INVALID", "Sign-in expired. Please start again.")
    with service.db.connect(write=True) as conn:
        row = conn.execute(
            "DELETE FROM oauth_states WHERE id=? AND expires_at>? RETURNING *",
            (fingerprint(state), timestamp()),
        ).fetchone()
    if row is None or not code or len(code) > 512:
        raise Reject("AUTH_INVALID", "Sign-in expired. Please start again.")
    try:
        with httpx.Client(timeout=15, follow_redirects=False) as client:
            reply = client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                data={
                    "client_id": service.settings.github_client_id,
                    "client_secret": service.settings.github_client_secret.get_secret_value(),
                    "code": code,
                    "code_verifier": row["verifier"],
                    "redirect_uri": service.settings.public_url.rstrip("/") + "/auth/callback",
                },
            )
            reply.raise_for_status()
            data = reply.json()
        token = data.get("access_token")
        if not isinstance(token, str) or not token:
            raise Reject("AUTH_INVALID", "GitHub did not authorize sign-in. Please try again.")
        scopes = set(re.split(r"[, ]+", data.get("scope", "")))
        if not {"read:user", "public_repo"}.issubset(scopes):
            raise Reject("AUTH_INVALID", "Quanta needs profile and public repository access.")
        with github_client(token) as client:
            reply = client.get("/user")
            reply.raise_for_status()
            profile = reply.json()
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", str(profile.get("login", ""))):
            raise Reject("AUTH_INVALID", "Could not verify the GitHub account.")
        identity = Identity(
            str(int(profile["id"])), profile["login"], token, secrets.token_urlsafe(32)
        )
        raw = service.create_session(identity, data.get("expires_in"))
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        raise Reject("AUTH_INVALID", "GitHub sign-in failed. Please try again.") from exc
    response = RedirectResponse("/#workspace", status_code=303)
    response.set_cookie(
        service.cookie,
        raw,
        max_age=service.settings.session_hours * 3600,
        secure=service.secure,
        httponly=True,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(service.state_cookie, path="/", secure=service.secure, httponly=True)
    return response


@router.get("/session")
def session(request: Request) -> dict[str, Any]:
    service = auth(request)
    identity = service.identity(request, required=False)
    return {
        "required": service.settings.required,
        "configured": service.configured,
        "user": {"login": identity.login} if identity else None,
        "csrf_token": identity.csrf if identity else None,
    }


@router.post("/logout")
def logout(request: Request) -> JSONResponse:
    service = auth(request)
    identity = service.identity(request)
    if identity is None:
        raise Reject("AUTH_REQUIRED")
    service.csrf(request, identity)
    with service.db.connect(write=True) as conn:
        conn.execute(
            "DELETE FROM sessions WHERE id=?",
            (fingerprint(request.cookies.get(service.cookie, "")),),
        )
    response = JSONResponse({"signed_out": True})
    response.delete_cookie(service.cookie, path="/", secure=service.secure, httponly=True)
    return response
