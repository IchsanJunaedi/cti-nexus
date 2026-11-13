from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import require_auth
from app.services.mermaid_service import (
    get_cached_mindmap,
    get_or_generate,
    save_mindmap,
    save_custom_syntax,
    get_display_syntax,
    _BUILDERS,
)

router = APIRouter(prefix="/api/mindmap", tags=["mindmap"])


class SaveSyntaxRequest(BaseModel):
    syntax: str


def _check_type(feature_type: str):
    if feature_type not in _BUILDERS:
        raise HTTPException(status_code=400, detail=f"Unknown feature type: {feature_type}")


@router.get("/{feature_type}/{doc_id}")
async def get_mindmap(
    feature_type: str,
    doc_id: str,
    _user=Depends(require_auth),
):
    _check_type(feature_type)
    builder = _BUILDERS[feature_type]
    doc = await get_or_generate(feature_type, doc_id, lambda: builder(doc_id))
    if doc is None:
        raise HTTPException(status_code=404, detail=f"{feature_type} {doc_id} not found")

    return {
        "feature_type": feature_type,
        "doc_id": doc_id,
        "title": doc.get("title", ""),
        "mermaid_syntax": doc.get("mermaid_syntax", ""),
        "custom_syntax": doc.get("custom_syntax") or None,
        "display_syntax": get_display_syntax(doc),
        "generated_at": doc.get("generated_at", ""),
        "edited_at": doc.get("edited_at") or None,
    }


@router.put("/{feature_type}/{doc_id}")
async def save_mindmap_edit(
    feature_type: str,
    doc_id: str,
    body: SaveSyntaxRequest,
    _user=Depends(require_auth),
):
    _check_type(feature_type)
    doc = await get_cached_mindmap(feature_type, doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail=f"No mindmap found for {feature_type} {doc_id}. Generate first.")
    updated = await save_custom_syntax(feature_type, doc_id, body.syntax)
    if not updated:
        raise HTTPException(status_code=500, detail="Save failed")
    return {
        "feature_type": feature_type,
        "doc_id": doc_id,
        "edited_at": updated.get("edited_at"),
        "display_syntax": get_display_syntax(updated),
    }


@router.post("/{feature_type}/{doc_id}/regenerate")
async def regenerate_mindmap(
    feature_type: str,
    doc_id: str,
    _user=Depends(require_auth),
):
    _check_type(feature_type)
    builder = _BUILDERS[feature_type]
    result = await builder(doc_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"{feature_type} {doc_id} not found")

    title, syntax = result
    doc = await save_mindmap(feature_type, doc_id, title, syntax)

    return {
        "feature_type": feature_type,
        "doc_id": doc_id,
        "title": doc.get("title", ""),
        "mermaid_syntax": doc.get("mermaid_syntax", ""),
        "custom_syntax": None,
        "display_syntax": syntax,
        "generated_at": doc.get("generated_at", ""),
    }
