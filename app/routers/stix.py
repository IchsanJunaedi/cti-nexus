"""
stix.py — FastAPI router for STIX 2.1 export endpoints.

Endpoints:
    GET /api/stix/ta/{actor_name}    → STIX bundle for a specific Threat Actor
    GET /api/stix/iocs               → STIX bundle for IOCs (optional ?type=&limit=)
    GET /api/stix/pirs               → STIX bundle for active PIRs
"""

import json
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from app.auth import require_auth

from app.services.stix_service import (
    build_article_stix_bundle,
    build_ioc_stix_bundle,
    build_pir_stix_bundle,
    build_ta_stix_bundle,
)

router = APIRouter(prefix="/api/stix", tags=["stix"])

_TODAY = lambda: date.today().isoformat()  # noqa: E731


def _stix_response(bundle: dict, filename: str) -> JSONResponse:
    """Return the STIX bundle as a downloadable JSON attachment."""
    return JSONResponse(
        content=bundle,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get(
    "/article/{article_id}",
    summary="Export STIX 2.1 bundle for a single article",
    response_class=JSONResponse,
)
async def export_article_stix(article_id: str, user: dict = Depends(require_auth)) -> JSONResponse:
    """
    Build and return a STIX 2.1 bundle containing a report object for the
    article, its TTPs as attack-pattern objects, and threat-actor stubs,
    with relationship objects linking actors to techniques.

    Returns HTTP 404 if the article is not found.
    """
    bundle = await build_article_stix_bundle(article_id)
    if bundle is None:
        raise HTTPException(status_code=404, detail=f"Article '{article_id}' not found.")
    filename = f"stix-article-{article_id[:12]}-{_TODAY()}.json"
    return _stix_response(bundle, filename)


@router.get(
    "/ta/{actor_name}",
    summary="Export STIX 2.1 bundle for a Threat Actor profile",
    response_class=JSONResponse,
)
async def export_ta_stix(actor_name: str) -> JSONResponse:
    """
    Build and return a STIX 2.1 bundle containing the threat-actor object,
    associated attack-patterns (TTPs), malware, and IOC indicators extracted
    from the stored TA profile for *actor_name*.

    Returns HTTP 404 if no profile exists for the given actor name.
    """
    bundle = await build_ta_stix_bundle(actor_name)

    # If only the identity object is present the profile was not found.
    stix_objects = bundle.get("objects", [])
    non_identity = [o for o in stix_objects if o.get("type") != "identity"]
    if not non_identity:
        raise HTTPException(
            status_code=404,
            detail=f"No TA profile found for actor '{actor_name}'. "
                   "Generate one first via the TA Profiles endpoint.",
        )

    safe_name = actor_name.replace(" ", "_").replace("/", "-")[:50]
    filename = f"stix-ta-{safe_name}-{_TODAY()}.json"
    return _stix_response(bundle, filename)


@router.get(
    "/iocs",
    summary="Export STIX 2.1 bundle for IOC indicators",
    response_class=JSONResponse,
)
async def export_ioc_stix(
    type: str | None = Query(
        default=None,
        alias="type",
        description="Filter by IOC type (ip, domain, url, sha256, sha1, md5, email, cve)",
    ),
    limit: int = Query(
        default=500,
        ge=1,
        le=2000,
        description="Maximum number of IOCs to export (default 500, max 2000)",
    ),
) -> JSONResponse:
    """
    Fetch IOCs from the database and return them as STIX 2.1 indicator objects
    inside a bundle.

    Optionally filter by IOC *type* and cap the result set with *limit*.
    """
    bundle = await build_ioc_stix_bundle(ioc_type=type, limit=limit)

    type_label = type if type else "all"
    filename = f"stix-iocs-{type_label}-{_TODAY()}.json"
    return _stix_response(bundle, filename)


@router.get(
    "/pirs",
    summary="Export STIX 2.1 bundle for active PIRs",
    response_class=JSONResponse,
)
async def export_pir_stix() -> JSONResponse:
    """
    Fetch all active Priority Intelligence Requirements (PIRs) from the database
    and represent each as a STIX 2.1 course-of-action object inside a bundle.
    """
    bundle = await build_pir_stix_bundle()
    filename = f"stix-pirs-{_TODAY()}.json"
    return _stix_response(bundle, filename)
