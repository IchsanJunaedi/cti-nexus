import asyncio
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from app.models.auth import (
    LoginRequest, TokenResponse, UserCreate, UserClientsUpdate, UserRoleUpdate,
    PasswordResetRequest, ChangePasswordRequest, PolicySettings,
)
from app.services.client_service import get_client
from app.services.auth_service import (
    get_user, verify_password, create_token, decode_token,
    create_user, list_users, user_count, reset_password, flag_force_pw_change,
    update_last_sign_in, update_user_clients, update_user_role, _resolve_client_ids,
    delete_user, get_user_role,
)
from app.services.audit_service import write_audit, get_audit_log
from app.services.policy_service import get_policy, save_policy, validate_password, policy_hint
from app.services.role_service import role_exists
from app.services.rate_limit_service import is_rate_limited
from app.auth import require_auth, require_permission
from app.config import JWT_EXPIRE_MIN
from jose import JWTError

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _pw_error(errors: list[str]) -> HTTPException:
    return HTTPException(status_code=422, detail=f"Password missing: {', '.join(errors)}")


# ── Policy ───────────────────────────────────────────────────

@router.get("/policy")
async def get_pw_policy():
    policy = await get_policy()
    return {**policy, "hint": policy_hint(policy)}


@router.put("/policy")
async def update_pw_policy(body: PolicySettings, request: Request, admin: dict = Depends(require_permission("manage_policy"))):
    policy = body.model_dump(exclude={"force_all_change"})
    await save_policy(policy)
    flagged = 0
    if body.force_all_change:
        flagged = await flag_force_pw_change()
    await write_audit(admin["username"], "update_pw_policy",
                      detail={**policy, "force_all_change": body.force_all_change}, ip=_ip(request))
    return {"ok": True, "flagged_users": flagged, "hint": policy_hint(policy)}


# ── Auth ─────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, request: Request, response: Response):
    ip = _ip(request)
    if await is_rate_limited(f"login:{ip}", max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in a minute.")
    user = await get_user(body.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("hashed_password"):
        raise HTTPException(status_code=400, detail="This account uses SSO. Please sign in via the SSO button.")
    if not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    client_ids = _resolve_client_ids(user)
    token = create_token(user["username"], user["role"], client_ids=client_ids)
    client_doc = await get_client(client_ids[0]) if client_ids else None
    client_countries = (client_doc or {}).get("countries", [])
    await write_audit(user["username"], "login", ip=ip)
    await update_last_sign_in(user["username"])
    response.set_cookie(
        key="cti_auth",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=int(JWT_EXPIRE_MIN) * 60,
        path="/",
    )
    return TokenResponse(
        access_token=token,
        username=user["username"],
        role=user["role"],
        client_ids=client_ids,
        client_countries=client_countries,
        force_pw_change=bool(user.get("force_pw_change", False)),
    )


@router.post("/logout")
async def logout(response: Response, _user: dict = Depends(require_auth)):
    response.delete_cookie(key="cti_auth", path="/")
    return {"ok": True}


@router.post("/change-password")
async def change_password(body: ChangePasswordRequest, request: Request, user: dict = Depends(require_auth)):
    policy = await get_policy()
    errors = validate_password(body.new_password, policy)
    if errors:
        raise _pw_error(errors)
    ok = await reset_password(user["username"], body.new_password)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(user["username"], "change_password", ip=_ip(request))
    return {"ok": True}


@router.post("/init")
async def init_admin(body: UserCreate):
    """Bootstrap: create first superadmin. Fails if any user already exists."""
    if await user_count() > 0:
        raise HTTPException(status_code=409, detail="Users already exist — use /api/auth/users")
    policy = await get_policy()
    errors = validate_password(body.password, policy)
    if errors:
        raise _pw_error(errors)
    result = await create_user(body.username, body.password, "superadmin", "system", client_ids=["default"])
    return result


@router.get("/me")
async def me(user: dict = Depends(require_auth)):
    client_ids = _resolve_client_ids(user)
    client_docs = await asyncio.gather(*[get_client(cid) for cid in client_ids]) if client_ids else []
    clients_map = {
        cid: (doc or {}).get("countries", [])
        for cid, doc in zip(client_ids, client_docs)
    }
    clients_sectors_map = {
        cid: (doc or {}).get("sectors", [])
        for cid, doc in zip(client_ids, client_docs)
    }
    first_countries = clients_map.get(client_ids[0], []) if client_ids else []
    first_sectors = clients_sectors_map.get(client_ids[0], []) if client_ids else []
    return {
        **user,
        "client_countries": first_countries,
        "clients_map": clients_map,
        "client_sectors": first_sectors,
        "clients_sectors_map": clients_sectors_map,
    }


@router.get("/users")
async def get_users(admin: dict = Depends(require_permission("manage_users"))):
    return await list_users()


@router.post("/users")
async def add_user(body: UserCreate, request: Request, admin: dict = Depends(require_permission("manage_users"))):
    policy = await get_policy()
    errors = validate_password(body.password, policy)
    if errors:
        raise _pw_error(errors)
    if not await role_exists(body.role):
        raise HTTPException(status_code=422, detail=f"Role '{body.role}' does not exist")
    if body.role == "superadmin" and admin["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can grant superadmin role")
    existing = await get_user(body.username)
    if existing:
        raise HTTPException(status_code=409, detail="Username already exists")
    result = await create_user(body.username, body.password, body.role, admin["username"], client_ids=body.client_ids)
    await write_audit(admin["username"], "create_user", target_id=body.username,
                      detail={"role": body.role, "client_ids": body.client_ids}, ip=_ip(request))
    return result


@router.post("/users/{username}/reset-password")
async def reset_user_password(
    username: str,
    body: PasswordResetRequest,
    request: Request,
    admin: dict = Depends(require_permission("reset_password")),
):
    target = await get_user(username)
    if target and target.get("role") == "superadmin" and admin["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can reset a superadmin password")
    if target and not target.get("hashed_password"):
        raise HTTPException(status_code=400, detail="SSO-provisioned accounts do not support password reset.")
    policy = await get_policy()
    errors = validate_password(body.new_password, policy)
    if errors:
        raise _pw_error(errors)
    ok = await reset_password(username, body.new_password)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(admin["username"], "reset_password", target_id=username, ip=_ip(request))
    return {"ok": True}


@router.put("/users/{username}/clients")
async def update_user_client_list(
    username: str,
    body: UserClientsUpdate,
    request: Request,
    admin: dict = Depends(require_permission("manage_users")),
):
    if not body.client_ids:
        raise HTTPException(status_code=400, detail="client_ids must not be empty")
    ok = await update_user_clients(username, body.client_ids)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(admin["username"], "update_user_clients", target_id=username,
                      detail={"client_ids": body.client_ids}, ip=_ip(request))
    return {"ok": True, "client_ids": body.client_ids}


@router.put("/users/{username}/role")
async def update_user_role_endpoint(
    username: str,
    body: UserRoleUpdate,
    request: Request,
    admin: dict = Depends(require_permission("manage_users")),
):
    if not await role_exists(body.role):
        raise HTTPException(status_code=422, detail=f"Role '{body.role}' does not exist")
    if body.role == "superadmin" and admin["role"] != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can grant superadmin role")
    ok = await update_user_role(username, body.role)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(admin["username"], "update_user_role", target_id=username,
                      detail={"role": body.role}, ip=_ip(request))
    return {"ok": True, "role": body.role}


@router.delete("/users/{username}")
async def delete_user_endpoint(
    username: str,
    request: Request,
    admin: dict = Depends(require_permission("manage_users")),
):
    target_role = await get_user_role(username)
    if target_role is None:
        raise HTTPException(status_code=404, detail="User not found")
    if admin["role"] != "superadmin" and target_role == "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can delete superadmin users")
    if admin["role"] == "superadmin" and admin["username"] == username:
        raise HTTPException(status_code=403, detail="Cannot delete your own account")
    ok = await delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    await write_audit(admin["username"], "delete_user", target_id=username,
                      detail={"role": target_role}, ip=_ip(request))
    return {"ok": True}


@router.get("/audit-log")
async def audit_log(
    page:      int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user:      str | None = None,
    action:    str | None = None,
    _admin:    dict = Depends(require_permission("view_audit_log")),
):
    docs, total = await get_audit_log(page=page, page_size=page_size, user=user, action=action)
    return {"logs": docs, "total": total, "page": page, "page_size": page_size}
