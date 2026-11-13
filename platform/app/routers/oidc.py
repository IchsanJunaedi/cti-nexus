import logging

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from app.config import OIDC_ENABLED, JWT_EXPIRE_MIN

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["oidc"])


@router.get("/login")
async def oidc_login(request: Request):
    if not OIDC_ENABLED:
        return RedirectResponse("/")
    from app.services.oidc_service import build_authorization_url
    url = await build_authorization_url(request.session)
    return RedirectResponse(url)


@router.get("/callback")
async def oidc_callback(request: Request, code: str = "", state: str = ""):
    from app.services.oidc_service import exchange_code
    ip = request.client.host if request.client else ""
    try:
        token = await exchange_code(code, state, request.session, ip)
    except Exception as exc:
        logger.warning("OIDC callback failed: %s", exc)
        return RedirectResponse("/?error=sso_failed")
    response = RedirectResponse(f"/#token={token}")
    response.set_cookie(
        key="cti_auth",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=int(JWT_EXPIRE_MIN) * 60,
        path="/",
    )
    return response


@router.get("/logout")
async def oidc_logout(request: Request):
    request.session.clear()
    from app.services.oidc_service import build_logout_url
    url = await build_logout_url(str(request.base_url))
    response = RedirectResponse(url or "/")
    response.delete_cookie(key="cti_auth", path="/")
    return response
