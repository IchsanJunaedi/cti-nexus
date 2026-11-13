import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import ValidationError
from app.models.article import ArticleOut, ArticleListResponse, FilterOptions, DashboardStats
from app.services.article_service import get_articles, get_filter_options, get_dashboard_stats
from app.services.dedup_service import find_dedup_groups, get_dedup_groups
from app.services.confidence_service import compute_and_store, recompute_all_confidence
from app.services.audit_service import write_audit
from app.country_groups import COUNTRY_GROUPS
from app.auth import require_auth


def _ip(request: Request) -> str:
    return request.client.host if request.client else ""

router = APIRouter(prefix="/api", tags=["articles"])


@router.get("/articles/dedup-groups")
async def article_dedup_groups(
    days: int = Query(7, ge=1, le=30),
    threshold: float = Query(0.75, ge=0.5, le=0.99),
    limit: int = Query(500, ge=50, le=2000),
):
    return await get_dedup_groups(days=days, threshold=threshold, limit=limit)


@router.get("/articles", response_model=ArticleListResponse)
async def list_articles(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
    industry: list[str] | None = Query(None),
    country: list[str] | None = Query(None),
    source: list[str] | None = Query(None),
    news_type: list[str] | None = Query(None),
    region: list[str] | None = Query(None),
    threat_actor: list[str] | None = Query(None),
    search: str | None = None,
    victim_country: list[str] | None = Query(None),
    actor_country: list[str] | None = Query(None),
    title_keyword: list[str] | None = Query(None),
    cve_id: list[str] | None = Query(None),
    dedup: bool = Query(False),
    dedup_threshold: float = Query(0.75, ge=0.5, le=0.99),
):
    articles, total = await get_articles(
        page=page,
        page_size=page_size,
        posted_on_start=posted_on_start,
        posted_on_end=posted_on_end,
        industries=industry,
        countries=country,
        sources=source,
        news_types=news_type,
        regions=region,
        threat_actors=threat_actor,
        search=search,
        victim_countries=victim_country,
        actor_countries=actor_country,
        title_keywords=title_keyword,
        cve_ids=cve_id,
    )
    if dedup and articles:
        # find_dedup_groups expects plain dicts; convert _id to str first so
        # it survives the ArticleOut.from_mongo call below unchanged.
        raw_dicts = []
        for a in articles:
            d = dict(a)
            d["_id"] = str(d["_id"])
            raw_dicts.append(d)
        raw_dicts = await find_dedup_groups(raw_dicts, dedup_threshold)
        parsed = []
        for a in raw_dicts:
            try:
                parsed.append(ArticleOut.from_mongo(a))
            except Exception as e:
                logging.warning("Skipped article _id=%s: %s", a.get("_id"), e)
        return ArticleListResponse(
            articles=parsed,
            total=total,
            page=page,
            page_size=page_size,
        )
    parsed = []
    for a in articles:
        try:
            parsed.append(ArticleOut.from_mongo(a))
        except Exception as e:
            logging.warning("Skipped article _id=%s: %s", a.get("_id"), e)
    return ArticleListResponse(
        articles=parsed,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/filters", response_model=FilterOptions)
async def list_filters():
    return await get_filter_options()


@router.get("/country-groups")
async def country_groups():
    return COUNTRY_GROUPS


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard_stats(
    posted_on_start: str | None = None,
    posted_on_end: str | None = None,
):
    return await get_dashboard_stats(
        posted_on_start=posted_on_start,
        posted_on_end=posted_on_end,
    )


@router.get("/articles/{article_id}", response_model=ArticleOut, dependencies=[Depends(require_auth)])
async def get_article_by_id(article_id: str):
    from app.database import get_database
    from app.config import COLLECTION_NAME
    from bson import ObjectId
    try:
        oid = ObjectId(article_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid article ID")
    doc = await get_database()[COLLECTION_NAME].find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Article not found")
    return ArticleOut.from_mongo(doc)


@router.post("/articles/{article_id}/confidence")
async def compute_article_confidence(
    article_id: str,
    request: Request,
    user: dict = Depends(require_auth),
):
    score = await compute_and_store(article_id)
    if score is None:
        raise HTTPException(status_code=404, detail="Article not found")
    await write_audit(user["username"], "compute_confidence", target_id=article_id,
                      detail={"score": score}, ip=_ip(request))
    return {"article_id": article_id, "confidence_score": score}


@router.post("/articles/confidence/recompute")
async def recompute_confidence_all(request: Request, user: dict = Depends(require_auth)):
    result = await recompute_all_confidence()
    await write_audit(user["username"], "recompute_confidence_all",
                      detail={"updated": result.get("updated"), "total": result.get("total")},
                      ip=_ip(request))
    return result


@router.post("/articles/backfill-iocs")
async def backfill_iocs(
    request: Request,
    user: dict = Depends(require_auth),
):
    """Tag articles with IOCs already in the iocs collection by matching source URL."""
    from app.database import get_database
    from app.config import COLLECTION_NAME, IOC_COLLECTION

    db = get_database()
    articles_col = db[COLLECTION_NAME]
    iocs_col = db[IOC_COLLECTION]

    # Build url → {type: [values]} map from iocs collection
    all_iocs = await iocs_col.find({}, {"type": 1, "value": 1, "sources": 1}).to_list(None)

    url_to_iocs: dict[str, dict[str, list]] = {}
    _type_to_field = {
        "ip": "ips", "domain": "domains", "url": "urls",
        "url_with_path": "urls_with_path", "email": "emails",
        "sha256": "sha256", "sha1": "sha1", "md5": "md5", "cve": "cves",
    }
    for ioc in all_iocs:
        field = _type_to_field.get(ioc["type"])
        if not field:
            continue
        for src in ioc.get("sources", []):
            url = src.get("url", "")
            if not url:
                continue
            bucket = url_to_iocs.setdefault(url, {})
            bucket.setdefault(field, [])
            if ioc["value"] not in bucket[field]:
                bucket[field].append(ioc["value"])

    if not url_to_iocs:
        return {"processed": 0, "tagged": 0}

    # For each article URL that has IOCs, write iocs field back
    tagged = 0
    for url, ioc_dict in url_to_iocs.items():
        result = await articles_col.update_one(
            {"url": url},
            {"$set": {"iocs": ioc_dict}},
        )
        if result.matched_count:
            tagged += 1

    await write_audit(user["username"], "backfill_iocs",
                      detail={"processed": len(url_to_iocs), "tagged": tagged},
                      ip=_ip(request))
    return {"processed": len(url_to_iocs), "tagged": tagged}
