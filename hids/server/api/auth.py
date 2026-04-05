# server/api/auth.py
# Authentication API
# POST /api/v1/auth/token   — login with username+password or API key, returns token
# GET  /api/v1/auth/me      — returns current user info
# POST /api/v1/auth/logout  — invalidates token

import hashlib
import logging
import os
import time
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

log    = logging.getLogger("sentinel.api.auth")
router = APIRouter()
bearer = HTTPBearer(auto_error=False)

# ── Config ────────────────────────────────────────────────────
API_KEY    = os.getenv("API_KEY",    "changeme")
SECRET_KEY = os.getenv("SECRET_KEY", "sentinel-secret-change-this")

# Simple user store — replace with DB in production
USERS = {
    "admin":   {"password": API_KEY,      "role": "admin",   "name": "Administrator"},
    "analyst": {"password": "analyst123", "role": "analyst", "name": "SOC Analyst"},
}

# In-memory valid tokens (token → username)
VALID_TOKENS: dict = {}

# In-memory revoked tokens
REVOKED_TOKENS: set = set()


def _make_token(username: str) -> str:
    payload = f"{username}:{time.time()}:{SECRET_KEY}"
    return hashlib.sha256(payload.encode()).hexdigest()


# ── CORE DEPENDENCY — use this on every protected route ───────
async def verify_api_key(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer)
) -> str:
    """
    Validates the Bearer token on every protected request.
    Returns the username if valid, raises 401 otherwise.

    Accepts:
      - A token issued by POST /api/v1/auth/token
      - The raw API_KEY directly as a Bearer token (for agent compatibility)
    """
    if not creds:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header — provide: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = creds.credentials

    # Check revoked
    if token in REVOKED_TOKENS:
        raise HTTPException(status_code=401, detail="Token has been revoked")

    # Accept raw API key directly (agents use this)
    if token == API_KEY:
        return "agent"

    # Accept issued session tokens
    if token in VALID_TOKENS:
        return VALID_TOKENS[token]

    log.warning(f"Rejected invalid token: {token[:12]}...")
    raise HTTPException(
        status_code=401,
        detail="Invalid or expired token — please log in again",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── LOGIN ─────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/token")
async def login(body: LoginRequest):
    user = USERS.get(body.username)

    # Accept: correct user password OR raw API key as password
    valid = (user and user["password"] == body.password) or (body.password == API_KEY)

    if not valid:
        log.warning(f"Failed login: username='{body.username}'")
        raise HTTPException(status_code=401, detail="Invalid username or API key")

    token = _make_token(body.username)
    VALID_TOKENS[token] = body.username
    log.info(f"Login success: {body.username} → token {token[:12]}...")

    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     body.username,
        "role":         user["role"] if user else "analyst",
        "name":         user["name"] if user else body.username,
    }


# ── ME ────────────────────────────────────────────────────────
@router.get("/me")
async def me(username: str = Depends(verify_api_key)):
    user = USERS.get(username, {})
    return {
        "authenticated": True,
        "username":      username,
        "role":          user.get("role", "agent"),
        "name":          user.get("name", username),
    }


# ── LOGOUT ────────────────────────────────────────────────────
@router.post("/logout")
async def logout(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    username: str = Depends(verify_api_key),
):
    if creds:
        token = creds.credentials
        REVOKED_TOKENS.add(token)
        VALID_TOKENS.pop(token, None)
        log.info(f"Logout: {username}")
    return {"status": "logged_out"}
