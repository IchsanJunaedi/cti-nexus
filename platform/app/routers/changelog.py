import re
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from app.auth import require_auth

router = APIRouter(prefix="/api/changelog", tags=["changelog"], dependencies=[Depends(require_auth)])

_CHANGELOG_PATH = Path(__file__).parent.parent.parent / "CHANGELOG.md"

_HEADER_RE = re.compile(r"^## \[([^\]]+)\]\s*-\s*(.+)$", re.MULTILINE)


def _parse() -> list[dict]:
    text = _CHANGELOG_PATH.read_text(encoding="utf-8")
    matches = list(_HEADER_RE.finditer(text))
    entries = []
    for i, m in enumerate(matches):
        start = m.end()
        end   = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = text[start:end].strip().strip("---").strip()
        entries.append({
            "version": m.group(1).strip(),
            "date":    m.group(2).strip(),
            "content": content,
        })
    return entries


@router.get("")
async def list_versions():
    return [{"version": e["version"], "date": e["date"]} for e in _parse()]


@router.get("/{version}")
async def get_version(version: str):
    for e in _parse():
        if e["version"] == version:
            return e
    raise HTTPException(status_code=404, detail="Version not found")
