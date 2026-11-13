import io
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header
from fastapi.responses import StreamingResponse
from app.models.pir import PIRCreate, PIRUpdate, PIRNote
from app.services.pir_service import (
    list_pirs, create_pir, update_pir, delete_pir,
    get_pir_articles, get_pir_options,
    get_pir_note, save_pir_note, get_pir_export, export_pir_to_docx_bytes,
)
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/pir", tags=["pir"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("/options")
async def pir_options():
    return await get_pir_options()


@router.get("")
async def get_pirs(
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    return await list_pirs(client_id=cid)


@router.get("/{pir_id}/articles")
async def pir_articles(
    pir_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=50),
):
    result = await get_pir_articles(pir_id, page=page, page_size=page_size)
    if result is None:
        raise HTTPException(status_code=404, detail="PIR not found")
    articles, total = result
    return {"articles": articles, "total": total, "page": page, "page_size": page_size}


@router.get("/{pir_id}/note")
async def pir_get_note(pir_id: str, url: str = Query(...)):
    note = await get_pir_note(pir_id, url)
    return note or {"pir_id": pir_id, "url": url, "note": "", "analyst": "", "updated_at": ""}


@router.put("/{pir_id}/note")
async def pir_save_note(pir_id: str, body: PIRNote, request: Request, user: dict = Depends(require_auth)):
    result = await save_pir_note(pir_id, body.url, body.note, body.analyst)
    await write_audit(user["username"], "save_pir_note", target_id=pir_id,
                      detail={"url": body.url}, ip=_ip(request))
    return result


@router.get("/{pir_id}/export")
async def pir_export(pir_id: str):
    result = await get_pir_export(pir_id)
    if not result:
        raise HTTPException(status_code=404, detail="PIR not found")
    return result


@router.get("/{pir_id}/export/docx")
async def pir_export_docx(pir_id: str):
    try:
        result = await export_pir_to_docx_bytes(pir_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=501, detail=str(exc))
    if not result:
        raise HTTPException(status_code=404, detail="PIR not found")
    docx_bytes, filename = result
    return StreamingResponse(
        io.BytesIO(docx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("")
async def post_pir(
    body: PIRCreate,
    request: Request,
    user: dict = Depends(require_auth),
    x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await create_pir(body.model_dump(), client_id=cid)
    await write_audit(user["username"], "create_pir", detail={"title": body.model_dump().get("title", ""), "client_id": cid}, ip=_ip(request))
    return result


@router.put("/{pir_id}")
async def put_pir(pir_id: str, body: PIRUpdate, request: Request, user: dict = Depends(require_auth)):
    result = await update_pir(pir_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(status_code=404, detail="PIR not found")
    await write_audit(user["username"], "update_pir", target_id=pir_id, ip=_ip(request))
    return result


@router.delete("/{pir_id}")
async def remove_pir(pir_id: str, request: Request, user: dict = Depends(require_auth)):
    ok = await delete_pir(pir_id)
    if not ok:
        raise HTTPException(status_code=404, detail="PIR not found")
    await write_audit(user["username"], "delete_pir", target_id=pir_id, ip=_ip(request))
    return {"deleted": True}
