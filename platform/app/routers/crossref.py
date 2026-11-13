from fastapi import APIRouter, HTTPException, Depends
from app.auth import require_auth
from app.services.cross_reference_service import get_cve_crossrefs, get_pir_crossrefs, get_ta_crossrefs

router = APIRouter(prefix="/api/crossref", tags=["crossref"], dependencies=[Depends(require_auth)])


@router.get("/cve/{cve_id}")
async def cve_crossref(cve_id: str):
    result = await get_cve_crossrefs(cve_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/pir/{pir_id}")
async def pir_crossref(pir_id: str):
    result = await get_pir_crossrefs(pir_id)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/ta/{actor_name:path}")
async def ta_crossref(actor_name: str):
    return await get_ta_crossrefs(actor_name)
