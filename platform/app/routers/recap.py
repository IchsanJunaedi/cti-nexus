from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth import require_auth
from app.services.audit_service import write_audit
from app.services.client_service import get_client
from app.services.recap_service import (
    generate_daily_recap,
    get_progress,
    get_recap,
    list_recaps,
    _yesterday_window,
)


router = APIRouter(prefix="/api/recap", tags=["recap"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


def _validate_date(date: str) -> str:
    try:
        datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(status_code=400, detail="date must be YYYY-MM-DD")
    return date


async def _validate_client(client_id: str) -> None:
    if client_id == "default":
        return
    if not await get_client(client_id):
        raise HTTPException(status_code=404, detail=f"Unknown client_id: {client_id}")


@router.get("/list")
async def recap_list(
    limit: int = Query(30, ge=1, le=180),
    client_id: str = Query("default"),
    _user: dict = Depends(require_auth),
):
    return {"recaps": await list_recaps(limit=limit, client_id=client_id)}


@router.get("/latest")
async def recap_latest(
    client_id: str = Query("default"),
    _user: dict = Depends(require_auth),
):
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
    doc = await get_recap(yesterday, client_id=client_id)
    if not doc:
        return {"recap": None, "date": yesterday}
    return {"recap": doc, "date": yesterday}


@router.get("/progress/status")
async def recap_progress(
    date: str | None = Query(None, description="YYYY-MM-DD — defaults to yesterday"),
    client_id: str = Query("default"),
    _user: dict = Depends(require_auth),
):
    """Poll while a /generate call is in flight for `date`/`client_id` (or yesterday/default if omitted)."""
    if date:
        _validate_date(date)
    date_iso, _, _ = _yesterday_window(date)
    return get_progress(date_iso, client_id=client_id)


@router.get("/{date}")
async def recap_get(
    date: str,
    client_id: str = Query("default"),
    _user: dict = Depends(require_auth),
):
    _validate_date(date)
    doc = await get_recap(date, client_id=client_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"No recap for {date} (client_id={client_id})")
    return {"recap": doc}


@router.post("/generate")
async def recap_generate(
    request: Request,
    date: str | None = Query(None, description="YYYY-MM-DD — defaults to yesterday"),
    force: bool = Query(False, description="Regenerate even if cached"),
    client_id: str = Query("default", description="Personalize to this client's tracked countries/sectors"),
    user: dict = Depends(require_auth),
):
    if date:
        _validate_date(date)
    await _validate_client(client_id)
    doc = await generate_daily_recap(date=date, force=force, client_id=client_id)
    await write_audit(
        user["username"],
        "generate_daily_recap",
        detail={"date": doc.get("date"), "force": force, "client_id": client_id},
        ip=_ip(request),
    )
    return {"recap": doc}
