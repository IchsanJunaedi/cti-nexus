from datetime import datetime, timezone
from app.database import get_database
from app.config import CLIENTS_COLLECTION


def _col():
    return get_database()[CLIENTS_COLLECTION]


async def ensure_default_client() -> None:
    col = _col()
    await col.create_index("client_id", unique=True, background=True)
    existing = await col.find_one({"client_id": "default"})
    if not existing:
        await col.insert_one({
            "client_id":   "default",
            "name":        "Default",
            "created_at":  datetime.now(timezone.utc).isoformat(),
        })


async def list_clients() -> list[dict]:
    docs = await _col().find({}, {"_id": 0}).sort("client_id", 1).to_list(500)
    return docs


async def get_client(client_id: str) -> dict | None:
    return await _col().find_one({"client_id": client_id}, {"_id": 0})


async def create_client(
    client_id: str,
    name: str,
    countries: list[str] | None = None,
    sectors: list[str] | None = None,
    recipients: list[str] | None = None,
    newsletter_css: str = "",
    newsletter_intro: str = "",
    newsletter_footer: str = "",
) -> dict:
    col = _col()
    await col.create_index("client_id", unique=True, background=True)
    doc = {
        "client_id":         client_id,
        "name":              name,
        "countries":         countries or [],
        "sectors":           sectors or [],
        "recipients":        recipients or [],
        "newsletter_css":    newsletter_css,
        "newsletter_intro":  newsletter_intro,
        "newsletter_footer": newsletter_footer,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await col.insert_one(doc)
    doc.pop("_id", None)
    return doc


async def update_client(
    client_id: str,
    name: str,
    countries: list[str],
    sectors: list[str] | None = None,
    recipients: list[str] | None = None,
    newsletter_css: str = "",
    newsletter_intro: str = "",
    newsletter_footer: str = "",
) -> dict | None:
    col = _col()
    result = await col.find_one_and_update(
        {"client_id": client_id},
        {"$set": {
            "name":              name,
            "countries":         countries,
            "sectors":           sectors or [],
            "recipients":        recipients or [],
            "newsletter_css":    newsletter_css,
            "newsletter_intro":  newsletter_intro,
            "newsletter_footer": newsletter_footer,
        }},
        return_document=True,
        projection={"_id": 0},
    )
    return result


async def delete_client(client_id: str) -> bool:
    if client_id == "default":
        return False
    result = await _col().delete_one({"client_id": client_id})
    return result.deleted_count > 0
