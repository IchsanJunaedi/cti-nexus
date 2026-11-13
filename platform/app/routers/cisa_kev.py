from fastapi import APIRouter, Depends, Query
from app.models.cisa_kev import CisaKevEntry, CisaKevListResponse, CisaKevStats
from app.services.cisa_kev_catalog_service import list_kev_entries, get_kev_stats
from app.auth import require_auth

router = APIRouter(prefix="/api/cisa-kev-catalog", tags=["cisa-kev"])


@router.get("", response_model=CisaKevListResponse)
async def get_kev_catalog(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    search: str | None = None,
    matched: bool | None = Query(None, description="Filter to entries matched (or not) against cve_tracker"),
    ransomware_only: bool = False,
    sort_by: str = Query("date_added", pattern="^(cve_id|date_added|due_date|vendor_project|product)$"),
    sort_dir: str = Query("desc", pattern="^(asc|desc)$"),
    _user: dict = Depends(require_auth),
):
    items, total = await list_kev_entries(
        search=search, matched=matched, ransomware_only=ransomware_only,
        page=page, page_size=page_size, sort_by=sort_by, sort_dir=sort_dir,
    )
    return CisaKevListResponse(
        items=[CisaKevEntry.from_mongo(i) for i in items],
        total=total, page=page, page_size=page_size,
    )


@router.get("/stats", response_model=CisaKevStats)
async def kev_stats(_user: dict = Depends(require_auth)):
    return await get_kev_stats()
