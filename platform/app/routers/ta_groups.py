from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from app.models.ta_group import TAGroup, TAGroupAdd, TAGroupListResponse
from app.services.ta_service import (
    list_groups, add_group, delete_group, merge_group, list_aliases, get_ta_stats,
    list_whitelist, remove_from_whitelist,
    list_ta_watchlist, get_watchlist_names, add_to_ta_watchlist, remove_from_ta_watchlist,
)
from app.services.ta_profile_service import generate_ta_profile, get_ta_profile, get_ta_timeline, get_dormancy_states
from app.services.attack_sync_service import TECH_ID_RE
from app.services.ta_relevance_service import compute_actor_relevance, compute_relevance_for_watchlist
from app.services.ioc_service import get_iocs_for_actor
from app.services.audit_service import write_audit
from app.auth import require_auth, effective_client_id

router = APIRouter(prefix="/api/ta", tags=["threat-actor-groups"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""


@router.get("/groups", response_model=TAGroupListResponse)
async def get_ta_groups(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
):
    groups, total = await list_groups(
        search=search, page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir,
    )
    return TAGroupListResponse(
        groups=[TAGroup.from_mongo(g) for g in groups],
        total=total, page=page, page_size=page_size,
    )


@router.get("/stats")
async def ta_stats():
    return await get_ta_stats()


@router.post("/groups")
async def post_ta_group(body: TAGroupAdd, request: Request, user: dict = Depends(require_auth)):
    result = await add_group(body.name)
    await write_audit(user["username"], "add_ta_group", target_id=body.name, ip=_ip(request))
    return result


@router.delete("/groups/{group_id}")
async def delete_ta_group(group_id: str, group_name: str, request: Request, user: dict = Depends(require_auth)):
    result = await delete_group(group_id, group_name)
    await write_audit(user["username"], "delete_ta_group", target_id=group_name, ip=_ip(request))
    return result


class TAGroupMergeBody(BaseModel):
    source_id: str
    target_id: str


@router.post("/groups/merge")
async def merge_ta_group(body: TAGroupMergeBody, request: Request, user: dict = Depends(require_auth)):
    result = await merge_group(body.source_id, body.target_id)
    await write_audit(user["username"], "merge_ta_group", target_id=f"{body.source_id}->{body.target_id}", ip=_ip(request))
    return result


@router.get("/aliases")
async def get_ta_aliases(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    items, total = await list_aliases(search=search, page=page, page_size=page_size)
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/whitelist")
async def get_whitelist(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
):
    items, total = await list_whitelist(
        search=search, page=page, page_size=page_size,
        sort_by=sort_by, sort_dir=sort_dir,
    )
    for item in items:
        item["_id"] = str(item["_id"])
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.delete("/whitelist/{name}")
async def restore_from_whitelist(name: str, request: Request, user: dict = Depends(require_auth)):
    result = await remove_from_whitelist(name)
    await write_audit(user["username"], "remove_whitelist", target_id=name, ip=_ip(request))
    return result


@router.get("/watchlist-names")
async def get_ta_watchlist_names(x_client_id: str | None = Header(None)):
    cid = x_client_id or "default"
    names = await get_watchlist_names(client_id=cid)
    return {"names": names}


@router.get("/watchlist")
async def get_ta_watchlist(
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_by: str = Query("name"),
    sort_dir: str = Query("asc"),
    x_client_id: str | None = Header(None),
):
    cid = x_client_id or "default"

    if sort_by == "relevance":
        # Relevance is computed, not stored — fetch the full (small) watchlist,
        # score every item, sort, then paginate in Python.
        all_items, total = await list_ta_watchlist(
            search=search, page=1, page_size=500,
            sort_by="name", sort_dir="asc", client_id=cid,
        )
        await compute_relevance_for_watchlist(all_items, cid)
        reverse = sort_dir != "asc"
        all_items.sort(key=lambda it: (it.get("relevance_score") if it.get("relevance_score") is not None else -1), reverse=reverse)
        start = (page - 1) * page_size
        items = all_items[start:start + page_size]
    else:
        items, total = await list_ta_watchlist(
            search=search, page=page, page_size=page_size,
            sort_by=sort_by, sort_dir=sort_dir, client_id=cid,
        )
        await compute_relevance_for_watchlist(items, cid)

    names = [item["name"] for item in items if item.get("name")]
    dormancy = await get_dormancy_states(names)
    for item in items:
        item["_id"] = str(item["_id"])
        item["dormancy_state"] = dormancy.get(item.get("name", ""), "DORMANT")
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/{actor}/timeline")
async def get_actor_timeline(
    actor: str,
    months: int = Query(24, ge=3, le=60),
    request: Request = None,
    user: dict = Depends(require_auth),
):
    await write_audit(user["username"], "ta_timeline_view", target_id=actor, ip=_ip(request))
    data = await get_ta_timeline(actor, months=months)
    return data


@router.post("/watchlist")
async def post_ta_watchlist(
    body: TAGroupAdd, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await add_to_ta_watchlist(body.name, client_id=cid)
    await write_audit(user["username"], "add_watchlist", target_id=body.name, ip=_ip(request))
    return result


@router.delete("/watchlist/{name}")
async def delete_ta_watchlist(
    name: str, request: Request,
    user: dict = Depends(require_auth), x_client_id: str | None = Header(None),
):
    cid = effective_client_id(user, x_client_id)
    result = await remove_from_ta_watchlist(name, client_id=cid)
    await write_audit(user["username"], "delete_watchlist", target_id=name, ip=_ip(request))
    return result


class TAProfileGenerateBody(BaseModel):
    name: str


@router.post("/profile/generate")
async def post_ta_profile_generate(
    body: TAProfileGenerateBody,
    request: Request,
    user: dict = Depends(require_auth),
):
    try:
        profile = await generate_ta_profile(body.name)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    await write_audit(user["username"], "generate_ta_profile", target_id=body.name, ip=_ip(request))
    return {"success": True, "profile": profile}


@router.get("/profile/{name}")
async def get_ta_profile_endpoint(name: str, x_client_id: str | None = Header(None)):
    profile = await get_ta_profile(name)
    if profile is None:
        return {"exists": False, "profile": None}

    cid = x_client_id or "default"
    relevance = await compute_actor_relevance(name, cid, profile=profile)
    org_rel = profile.get("organizational_relevance") or {}
    org_rel["sector_relevance"] = relevance["label"]
    org_rel["_relevance_score"] = relevance["score"]
    org_rel["_relevance_breakdown"] = relevance["breakdown"]
    profile["organizational_relevance"] = org_rel

    return {"exists": True, "profile": profile}


@router.get("/{actor}/iocs")
async def get_actor_iocs(actor: str):
    iocs = await get_iocs_for_actor(actor)
    return {"iocs": iocs}


@router.get("/watchlist/navigator-layer")
async def watchlist_navigator_layer(x_client_id: str | None = Header(None)):
    cid = x_client_id or "default"
    names = await get_watchlist_names(client_id=cid)

    # technique_id -> {count, actors}
    tech_map: dict[str, dict] = {}

    for name in names:
        result = await get_ta_profile(name)
        if not result:
            continue
        profile = result if isinstance(result, dict) else {}
        cap = profile.get("capability_assessment") or {}
        attack_techniques = cap.get("attack_techniques") or {}

        seen_for_actor: set[str] = set()
        for tactic, entries in attack_techniques.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, str):
                    continue
                for tid in TECH_ID_RE.findall(entry):
                    if tid in seen_for_actor:
                        continue
                    seen_for_actor.add(tid)
                    if tid not in tech_map:
                        tech_map[tid] = {"count": 0, "actors": []}
                    tech_map[tid]["count"] += 1
                    tech_map[tid]["actors"].append(name)

    max_count = max((v["count"] for v in tech_map.values()), default=1)

    techniques = []
    for tid, data in tech_map.items():
        score = round((data["count"] / max_count) * 100)
        actor_list = ", ".join(data["actors"])
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "comment": f"Used by: {actor_list}",
            "enabled": True,
            "showSubtechniques": False,
        })

    layer = {
        "name": "Watchlist — TTP Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"TTPs aggregated from {len(names)} watched threat actor profile(s). Score = actor coverage (darker = more actors use it).",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffe766", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1a1a2e",
        "selectTechniquesAcrossTactics": True,
    }
    return JSONResponse(content=layer)
