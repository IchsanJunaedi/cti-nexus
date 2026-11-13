import asyncio
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from app.services.source_score_db_service import (
    list_entries, add_entry, update_entry, delete_entry, get_stats,
    import_default_entries, DEFAULT_TEMPLATE_CLIENT_ID,
    RELIABILITY_LABELS, CREDIBILITY_LABELS,
)
from app.services.audit_service import write_audit
from app.services.admiralty_suggest_service import suggest_rating
from app.auth import require_auth, effective_client_id
from app.database import get_database
from app.config import COLLECTION_NAME

router = APIRouter(prefix="/api/sr", tags=["source-reliability"])

VALID_GRADES = {"A", "B", "C", "D", "E", "F"}
VALID_CODES  = {"1", "2", "3", "4", "5", "6"}


class SREntryAdd(BaseModel):
    source_name:       str = Field(..., min_length=1, max_length=200)
    reliability_grade: str = Field(..., pattern="^[A-Fa-f]$")
    credibility_code:  str = Field(..., pattern="^[1-6]$")
    notes:             str = Field("", max_length=500)


class SREntryUpdate(BaseModel):
    reliability_grade: str = Field(..., pattern="^[A-Fa-f]$")
    credibility_code:  str = Field(..., pattern="^[1-6]$")
    notes:             str = Field("", max_length=500)


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def _ungraded_sources_for(client_id: str) -> list[str]:
    articles_col = get_database()[COLLECTION_NAME]
    from app.services.source_score_db_service import _col as _sr_col
    all_sources, graded_docs = await asyncio.gather(
        articles_col.distinct("source"),
        _sr_col().find({"client_id": client_id}, {"source_name": 1, "_id": 0}).to_list(None),
    )
    graded = {d["source_name"].lower() for d in graded_docs}
    return sorted(s for s in all_sources if s and s.lower() not in graded)


@router.get("/entries")
async def list_sr_entries(
    search:   str | None = None,
    grade:    str | None = None,
    page:     int = Query(1, ge=1),
    page_size:int = Query(50, ge=1, le=500),
    sort_by:  str = Query("source_name"),
    sort_dir: str = Query("asc"),
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    entries, total = await list_entries(
        client_id=client_id,
        search=search, grade=grade,
        page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir,
    )
    return {"entries": entries, "total": total, "page": page, "page_size": page_size}


@router.get("/stats")
async def sr_stats(x_client_id: str | None = Header(None), user: dict = Depends(require_auth)):
    client_id = effective_client_id(user, x_client_id)
    return await get_stats(client_id)


@router.get("/labels")
async def sr_labels():
    return {"reliability": RELIABILITY_LABELS, "credibility": CREDIBILITY_LABELS}


@router.get("/ungraded-sources")
async def ungraded_sources(x_client_id: str | None = Header(None), user: dict = Depends(require_auth)):
    client_id = effective_client_id(user, x_client_id)
    return {"sources": await _ungraded_sources_for(client_id)}


@router.get("/entries/suggest")
async def suggest_sr_entry(
    source_name: str = Query(..., min_length=1, max_length=200),
    user: dict = Depends(require_auth),
):
    try:
        return {"success": True, "suggestion": await suggest_rating(source_name)}
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM suggestion failed: {e}")


@router.post("/entries")
async def add_sr_entry(
    body: SREntryAdd, request: Request,
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    source_name = body.source_name.strip()

    ungraded = await _ungraded_sources_for(client_id)
    if source_name.lower() not in {s.lower() for s in ungraded}:
        return {"success": False, "reason": "invalid_source"}

    result = await add_entry(
        client_id=client_id,
        source_name=source_name,
        analyst_name=user["username"],
        reliability_grade=body.reliability_grade.upper(),
        credibility_code=body.credibility_code,
        notes=body.notes.strip(),
    )
    await write_audit(user["username"], "add_source_rating", target_id=source_name,
                      detail={"grade": body.reliability_grade, "code": body.credibility_code, "client_id": client_id}, ip=_ip(request))
    return result


@router.put("/entries/{entry_id}")
async def update_sr_entry(
    entry_id: str, body: SREntryUpdate, request: Request,
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    result = await update_entry(
        entry_id=entry_id,
        client_id=client_id,
        reliability_grade=body.reliability_grade.upper(),
        credibility_code=body.credibility_code,
        notes=body.notes.strip(),
    )
    await write_audit(user["username"], "update_source_rating", target_id=entry_id,
                      detail={"grade": body.reliability_grade, "client_id": client_id}, ip=_ip(request))
    return result


@router.delete("/entries/{entry_id}")
async def delete_sr_entry(
    entry_id: str, request: Request,
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    result = await delete_entry(entry_id, client_id)
    await write_audit(user["username"], "delete_source_rating", target_id=entry_id, detail={"client_id": client_id}, ip=_ip(request))
    return result


@router.post("/import-defaults")
async def import_defaults(
    request: Request,
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    if client_id == DEFAULT_TEMPLATE_CLIENT_ID:
        raise HTTPException(status_code=400, detail="Cannot import defaults into the default template itself")
    result = await import_default_entries(client_id, user["username"])
    await write_audit(user["username"], "import_default_source_ratings", target_id=client_id,
                      detail={"imported": result["imported"], "skipped": result["skipped"]}, ip=_ip(request))
    return result
