from fastapi import APIRouter, Query, Depends
from fastapi.responses import JSONResponse
from app.auth import require_auth
from app.services.mitre_heatmap_service import get_heatmap, get_ttp_articles, get_navigator_layer
from app.services.d3fend_service import get_d3fend_countermeasures

router = APIRouter(prefix="/api/mitre", tags=["mitre"], dependencies=[Depends(require_auth)])


@router.get("/heatmap")
async def mitre_heatmap(
    view: str = Query("ta", pattern="^(ta|industry)$"),
    days: int = Query(90, ge=7, le=365),
    top_rows: int = Query(15, ge=3, le=30),
    top_ttps: int = Query(20, ge=5, le=40),
):
    return await get_heatmap(view=view, days=days, top_rows=top_rows, top_ttps=top_ttps)


@router.get("/d3fend/{technique_id}")
async def d3fend_countermeasures(technique_id: str):
    return {
        "technique_id": technique_id,
        "countermeasures": await get_d3fend_countermeasures(technique_id),
    }


@router.get("/navigator-layer")
async def navigator_layer(
    view: str = Query("ta", pattern="^(ta|industry)$"),
    days: int = Query(90, ge=7, le=365),
):
    layer = await get_navigator_layer(view=view, days=days)
    return JSONResponse(content=layer)


@router.get("/navigator-export")
async def navigator_export(
    view: str = Query("ta", pattern="^(ta|industry)$"),
    days: int = Query(90, ge=7, le=365),
):
    layer = await get_navigator_layer(view=view, days=days)
    filename = f"cti_navigator_{view}_{days}d.json"
    return JSONResponse(
        content=layer,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/articles")
async def mitre_ttp_articles(
    ttp_id: str,
    row: str,
    view: str = Query("ta", pattern="^(ta|industry)$"),
    days: int = Query(90, ge=7, le=365),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=50),
):
    docs, total = await get_ttp_articles(
        ttp_id=ttp_id, row=row, view=view, days=days, page=page, page_size=page_size,
    )
    return {"articles": docs, "total": total, "page": page, "page_size": page_size}
