# OIDC/SSO flow: PKCE, token exchange, ID-token validation, user provisioning.
# Local password auth lives in auth_service.py.
import hashlib
import base64
import logging
import secrets
import time
from datetime import datetime

import httpx
from authlib.jose import JsonWebKey, jwt as authlib_jwt
from fastapi import HTTPException

from app.config import (
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_DISCOVERY_URL,
    OIDC_REDIRECT_URI,
    OIDC_VERIFY_SSL,
)
from app.database import get_database
from app.services.auth_service import create_token, update_last_sign_in, _resolve_client_ids
from app.services.audit_service import write_audit

logger = logging.getLogger(__name__)

_metadata: dict | None = None
_jwks_cache: dict | None = None
_jwks_cached_at: float = 0.0
_JWKS_TTL = 3600  # seconds


async def get_provider_metadata() -> dict:
    global _metadata
    if _metadata:
        return _metadata
    async with httpx.AsyncClient(verify=OIDC_VERIFY_SSL) as c:
        r = await c.get(OIDC_DISCOVERY_URL, timeout=10)
        r.raise_for_status()
    _metadata = r.json()
    return _metadata


async def _get_jwks(jwks_uri: str) -> JsonWebKey:
    global _jwks_cache, _jwks_cached_at
    if _jwks_cache and (time.monotonic() - _jwks_cached_at) < _JWKS_TTL:
        return JsonWebKey.import_key_set(_jwks_cache)
    async with httpx.AsyncClient(verify=OIDC_VERIFY_SSL) as c:
        r = await c.get(jwks_uri, timeout=10)
        r.raise_for_status()
    _jwks_cache = r.json()
    _jwks_cached_at = time.monotonic()
    return JsonWebKey.import_key_set(_jwks_cache)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


async def build_authorization_url(session: dict) -> str:
    from urllib.parse import urlencode

    meta = await get_provider_metadata()
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    session["oidc_state"] = state
    session["oidc_nonce"] = nonce
    session["pkce_verifier"] = verifier

    params = {
        "response_type": "code",
        "client_id": OIDC_CLIENT_ID,
        "redirect_uri": OIDC_REDIRECT_URI,
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return meta["authorization_endpoint"] + "?" + urlencode(params)


async def exchange_code(code: str, state: str, session: dict, ip: str) -> str:
    if state != session.get("oidc_state"):
        raise HTTPException(status_code=400, detail="Invalid OIDC state")

    meta = await get_provider_metadata()
    verifier = session.pop("pkce_verifier", "")
    nonce = session.pop("oidc_nonce", "")
    session.pop("oidc_state", None)

    async with httpx.AsyncClient(verify=OIDC_VERIFY_SSL) as c:
        r = await c.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": OIDC_REDIRECT_URI,
                "client_id": OIDC_CLIENT_ID,
                "client_secret": OIDC_CLIENT_SECRET,
                "code_verifier": verifier,
            },
            timeout=15,
        )
        r.raise_for_status()
    tokens = r.json()

    jwks = await _get_jwks(meta["jwks_uri"])
    claims = authlib_jwt.decode(tokens["id_token"], jwks)

    # Validate standard claims with leeway for clock skew
    claims.validate(now=time.time(), leeway=60)

    # Explicit issuer + audience check — prevents accepting tokens from other clients
    expected_iss = meta.get("issuer", "")
    if expected_iss and claims.get("iss") != expected_iss:
        raise HTTPException(status_code=400, detail="ID token issuer mismatch")
    aud = claims.get("aud", [])
    if isinstance(aud, str):
        aud = [aud]
    if OIDC_CLIENT_ID not in aud:
        raise HTTPException(status_code=400, detail="ID token audience mismatch")
    if claims.get("nonce") != nonce:
        raise HTTPException(status_code=400, detail="Nonce mismatch")

    user = await _provision_user(claims)
    await update_last_sign_in(user["username"])
    await write_audit(user["username"], "sso_login", ip=ip)
    client_ids = _resolve_client_ids(user)
    return create_token(user["username"], user["role"], client_ids=client_ids)


async def _provision_user(claims: dict) -> dict:
    username = (
        claims.get("email")
        or claims.get("preferred_username")
        or claims.get("sub", "")
    ).lower().strip()

    if not username:
        raise HTTPException(status_code=400, detail="OIDC token contained no usable identifier")

    db = get_database()
    col = db["users"]
    user = await col.find_one({"username": username})

    if user is None:
        doc = {
            "username": username,
            "hashed_password": None,
            "role": "analyst",
            "is_active": True,
            "force_pw_change": False,
            "sso_sub": claims.get("sub"),
            "auth_provider": "oidc",
            "created_at": datetime.utcnow().isoformat(),
            "created_by": "oidc",
        }
        await col.insert_one(doc)
        await write_audit(username, "sso_provisioned", ip="")
        return doc

    updates: dict = {}
    if not user.get("sso_sub"):
        updates["sso_sub"] = claims.get("sub")
    if updates:
        await col.update_one({"username": username}, {"$set": updates})
    return user


async def build_logout_url(post_redirect: str) -> str | None:
    from urllib.parse import urlencode

    meta = await get_provider_metadata()
    ep = meta.get("end_session_endpoint")
    if not ep:
        return None
    return ep + "?" + urlencode({"post_logout_redirect_uri": post_redirect})
