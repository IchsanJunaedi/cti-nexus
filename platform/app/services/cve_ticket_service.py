from datetime import datetime, timezone, timedelta
import re

_TZ_UTC7 = timezone(timedelta(hours=7))
from app.database import get_database

TICKET_COLLECTION = "cve_tickets"


def _col():
    return get_database()[TICKET_COLLECTION]


def _client_filter(client_id: str) -> dict:
    return {"client_id": client_id}


async def get_next_ticket_id(client_id: str = "default") -> str:
    col = _col()
    now = datetime.utcnow()
    client_code = re.sub(r"[^A-Za-z0-9]", "", client_id).upper() or "DEFAULT"
    prefix = f"CTI-{client_code}-{now.year}-{now.month:02d}-"
    cursor = col.find(
        {"ticket_id": {"$regex": f"^{re.escape(prefix)}"}, **_client_filter(client_id)},
        {"ticket_id": 1, "_id": 0},
    )
    docs = await cursor.to_list(None)
    max_num = 0
    for doc in docs:
        try:
            num = int(doc["ticket_id"].split("-")[-1])
            if num > max_num:
                max_num = num
        except (ValueError, IndexError):
            pass
    return f"{prefix}{(max_num + 1):03d}"


async def get_ticket(cve_id: str, client_id: str = "default") -> dict | None:
    col = _col()
    return await col.find_one({"cve_id": cve_id, **_client_filter(client_id)}, {"_id": 0})


async def upsert_ticket(cve_id: str, data: dict, client_id: str = "default") -> None:
    col = _col()
    data["cve_id"]     = cve_id
    data["client_id"]  = client_id
    data["updated_at"] = datetime.now(_TZ_UTC7).strftime("%Y-%m-%d %H:%M:%S")
    await col.update_one({"cve_id": cve_id, **_client_filter(client_id)}, {"$set": data}, upsert=True)


async def get_acked_cve_ids(client_id: str = "default") -> list[str]:
    col = _col()
    cursor = col.find(
        {"acknowledged_by": {"$exists": True, "$ne": ""}, **_client_filter(client_id)},
        {"cve_id": 1, "_id": 0},
    )
    docs = await cursor.to_list(None)
    return [d["cve_id"] for d in docs if d.get("cve_id")]


async def get_tickets_map(cve_ids: list[str], client_id: str = "default") -> dict[str, str]:
    """Return {cve_id: ticket_id} for CVEs that already have a tracking ID assigned
    (from a prior acknowledge or draft). CVEs with no doc / no ticket_id are absent."""
    col = _col()
    cursor = col.find(
        {"cve_id": {"$in": cve_ids}, **_client_filter(client_id)},
        {"cve_id": 1, "ticket_id": 1, "_id": 0},
    )
    docs = await cursor.to_list(None)
    return {d["cve_id"]: d["ticket_id"] for d in docs if d.get("ticket_id")}


async def mark_drafted(cve_tracking_map: dict[str, str], mode: str, lang: str, client_id: str = "default") -> None:
    """Tag CVEs as having gone through Draft Email. cve_tracking_map is {cve_id: tracking_id}
    already resolved by the caller (existing ticket reused where present, fresh ID otherwise) —
    give CVEs without a ticket_id their tracking_id here so they show up in the Excel export."""
    col = _col()
    now = datetime.now(_TZ_UTC7).strftime("%Y-%m-%d %H:%M:%S")
    for cve_id, tracking_id in cve_tracking_map.items():
        existing = await col.find_one({"cve_id": cve_id, **_client_filter(client_id)}, {"ticket_id": 1})
        update: dict = {
            "cve_id":                 cve_id,
            "client_id":              client_id,
            "email_drafted_at":       now,
            "email_draft_mode":       mode,
            "email_draft_lang":       lang,
            "email_draft_ticket_id":  tracking_id,
        }
        if not existing or not existing.get("ticket_id"):
            update["ticket_id"] = tracking_id
        await col.update_one({"cve_id": cve_id, **_client_filter(client_id)}, {"$set": update}, upsert=True)


async def get_drafted_cve_ids(client_id: str = "default") -> list[str]:
    col = _col()
    cursor = col.find(
        {"email_drafted_at": {"$exists": True, "$ne": ""}, **_client_filter(client_id)},
        {"cve_id": 1, "_id": 0},
    )
    docs = await cursor.to_list(None)
    return [d["cve_id"] for d in docs if d.get("cve_id")]


async def get_ack_statuses(client_id: str = "default") -> dict[str, str]:
    col = _col()
    cursor = col.find(
        {"acknowledged_by": {"$exists": True, "$ne": ""}, **_client_filter(client_id)},
        {"cve_id": 1, "acknowledged_by": 1, "_id": 0},
    )
    docs = await cursor.to_list(None)
    return {d["cve_id"]: d["acknowledged_by"] for d in docs if d.get("cve_id") and d.get("acknowledged_by")}


async def bulk_acknowledge_cves(cve_ids: list[str], analyst_name: str, client_id: str = "default") -> int:
    col = _col()
    now = datetime.now(_TZ_UTC7)
    ack_time = now.strftime("%Y-%m-%d %H:%M:%S")

    already_acked_docs = await col.find(
        {"cve_id": {"$in": cve_ids}, **_client_filter(client_id),
         "acknowledged_by": {"$exists": True, "$ne": ""}},
        {"cve_id": 1, "_id": 0},
    ).to_list(None)
    already_acked = {d["cve_id"] for d in already_acked_docs}
    to_ack = [c for c in cve_ids if c not in already_acked]

    if not to_ack:
        return 0

    existing_tickets = await col.find(
        {"cve_id": {"$in": to_ack}, **_client_filter(client_id)},
        {"cve_id": 1, "ticket_id": 1, "_id": 0},
    ).to_list(None)
    ticket_map = {d["cve_id"]: d.get("ticket_id") for d in existing_tickets}

    for cve_id in to_ack:
        ticket_id = ticket_map.get(cve_id) or await get_next_ticket_id(client_id)
        await col.update_one(
            {"cve_id": cve_id, **_client_filter(client_id)},
            {"$set": {
                "cve_id":           cve_id,
                "client_id":        client_id,
                "ticket_id":        ticket_id,
                "acknowledge_time": ack_time,
                "acknowledged_by":  analyst_name.strip(),
                "updated_at":       now.isoformat(),
            }},
            upsert=True,
        )
    return len(to_ack)


async def acknowledge_cve(cve_id: str, analyst_name: str, client_id: str = "default") -> None:
    col = _col()
    now = datetime.now(_TZ_UTC7)

    existing = await col.find_one({"cve_id": cve_id, **_client_filter(client_id)}, {"ticket_id": 1})
    ticket_id = existing.get("ticket_id") if existing else None
    if not ticket_id:
        ticket_id = await get_next_ticket_id(client_id)

    await col.update_one(
        {"cve_id": cve_id, **_client_filter(client_id)},
        {"$set": {
            "cve_id":           cve_id,
            "client_id":        client_id,
            "ticket_id":        ticket_id,
            "acknowledge_time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "acknowledged_by":  analyst_name.strip(),
            "updated_at":       now.isoformat(),
        }},
        upsert=True,
    )
