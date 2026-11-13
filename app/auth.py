# FastAPI dependency injectors. Import these in routers.
# For JWT/user logic see app/services/auth_service.py
# For OIDC/SSO flow see app/services/oidc_service.py
from fastapi import Depends, Header, HTTPException
from jose import JWTError
from app.services.auth_service import decode_token
from app.services.role_service import role_has_permission


async def get_current_user(authorization: str | None = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ", 1)[1]
    try:
        payload = decode_token(token)
        # backward compat: old tokens have client_id:str, new have client_ids:list
        raw = payload.get("client_ids")
        if isinstance(raw, list) and raw:
            client_ids = raw
        else:
            client_ids = [payload.get("client_id", "default")]
        return {
            "username":   payload["sub"],
            "role":       payload.get("role", "analyst"),
            "client_ids": client_ids,
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def require_auth(user: dict = Depends(get_current_user)) -> dict:
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin role required")
    return user


async def require_superadmin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Superadmin role required")
    return user


def require_permission(permission: str):
    """Dependency factory: allow superadmin, or any role whose stored permissions include `permission`."""
    async def _dep(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] == "superadmin":
            return user
        if not await role_has_permission(user["role"], permission):
            raise HTTPException(status_code=403, detail=f"Permission required: {permission}")
        return user
    return _dep


def effective_client_id(user: dict, x_client_id: str | None) -> str:
    """Return active client_id for this request.
    Superadmin: any header value accepted.
    Others: header value must be in their client_ids list."""
    client_ids: list[str] = user.get("client_ids", ["default"])
    if not x_client_id:
        return client_ids[0] if client_ids else "default"
    if user["role"] == "superadmin":
        return x_client_id
    # non-superadmin: only allow if in their list
    return x_client_id if x_client_id in client_ids else client_ids[0]
