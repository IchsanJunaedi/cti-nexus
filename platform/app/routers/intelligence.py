from fastapi import APIRouter, Query, Depends, Header
from app.auth import require_auth, effective_client_id
from app.services.cluster_service import get_clusters, get_recent_campaigns
from app.services.source_score_service import score_sources, get_credibility, get_source_reliability, _CREDIBILITY_LABELS
from app.services.spike_service import get_spikes
from app.services.risk_matrix_service import get_risk_matrix
from app.services.audit_service import write_audit
from app.services.campaign_trend_service import get_campaign_trends, get_campaign_evolution
from app.services.geopolitical_service import get_geopolitical_summary
from app.database import get_database
from app.config import COLLECTION_NAME

router = APIRouter(prefix="/api", tags=["intelligence"], dependencies=[Depends(require_auth)])


@router.get("/clusters")
async def article_clusters(
    days: int = Query(30, ge=7, le=90, description="Lookback window in days"),
    threshold: float = Query(0.35, ge=0.2, le=0.7, description="Cosine similarity threshold"),
    exclude_low_reliability: bool = Query(False, description="Prevent D/E/F-graded sources from anchoring new clusters"),
):
    clusters = await get_clusters(days=days, threshold=threshold, exclude_low_reliability=exclude_low_reliability)
    return {"clusters": clusters, "total": len(clusters)}


@router.get("/source-scores")
async def source_scores():
    col = get_database()[COLLECTION_NAME]
    sources = await col.distinct("source")
    sources = sorted(s for s in sources if s)
    return {"sources": score_sources(sources)}


@router.get("/clusters/recent")
async def recent_campaigns(
    days: int = Query(7, ge=1, le=90),
    min_size: int = Query(3, ge=2, le=50),
    x_client_id: str | None = Header(None),
    user: dict = Depends(require_auth),
):
    client_id = effective_client_id(user, x_client_id)
    campaigns = await get_recent_campaigns(days=days, client_id=client_id, min_size=min_size)
    await write_audit(user["username"], "view_campaigns", detail={"days": days, "min_size": min_size})
    all_links = []
    seen_pairs: set[tuple] = set()
    for c in campaigns:
        for rc in c.get("related_campaigns", []):
            pair = tuple(sorted([c["cluster_id"], rc["cluster_id"]]))
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                all_links.append({
                    "source_id":   c["cluster_id"],
                    "target_id":   rc["cluster_id"],
                    "score":       rc["link_score"],
                    "link_type":   rc["link_type"],
                    "shared_elements": rc["shared_elements"],
                })
    return {"campaigns": campaigns, "campaign_links": all_links, "total": len(campaigns)}


@router.get("/clusters/evolution")
async def campaign_evolution(
    days: int = Query(30, ge=7, le=90),
):
    results = await get_campaign_evolution(days=days)
    return {"campaigns": results, "total": len(results)}


@router.get("/clusters/{cluster_id}/trends")
async def cluster_trends(cluster_id: str):
    trend = await get_campaign_trends(cluster_id)
    if not trend:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Cluster not found")
    return trend


@router.get("/spikes")
async def early_warning(
    lookback_days: int = Query(30, ge=14, le=90),
    z_threshold: float = Query(2.0, ge=1.5, le=4.0),
):
    return await get_spikes(lookback_days=lookback_days, z_threshold=z_threshold)


@router.get("/intelligence/geopolitical")
async def geopolitical_summary(
    days: int = Query(30, ge=7, le=90),
):
    campaigns = await get_recent_campaigns(days=days)
    return await get_geopolitical_summary(campaigns, days=days)


@router.get("/intelligence/risk-matrix")
async def risk_matrix(
    days: int = Query(30, ge=7, le=90),
    compare_days: int = Query(30, ge=7, le=90),
):
    return await get_risk_matrix(days=days, compare_days=compare_days)
