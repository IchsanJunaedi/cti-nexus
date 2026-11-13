from datetime import datetime
from app.database import get_database
from app.config import ROLES_COLLECTION

ALL_PERMISSIONS: dict[str, str] = {
    # News & Intelligence
    "view_news":        "View news articles and feeds",
    "export_data":      "Export data as CSV / reports",
    "view_intel":       "View threat intelligence reports",
    "manage_intel":     "Create and edit intelligence reports",
    "view_ta":          "View threat actor profiles",
    "view_ioc":         "View and search IOC database",
    "manage_ioc":       "Add and delete IOCs",
    "view_cve":         "View CVE and vulnerability data",
    "send_cve_email":   "Send CVE email reports",
    "view_stix":        "View STIX intelligence bundles",
    "wisemap_access":   "Access WiseMap CTI mind maps",
    # Operations
    "manage_rfi":       "Create and manage RFIs",
    "manage_pir":       "Create and manage PIRs",
    # Communication
    "view_newsletter":    "Access newsletter",
    "manage_newsletter":  "Create and send newsletters",
    "view_tweets":        "View monitored Twitter/X feeds",
    "manage_tweets":      "Configure monitored accounts",
    # Platform administration
    "view_audit_log":   "View audit log",
    "manage_users":     "Add, edit, and delete users",
    "reset_password":   "Reset other users' passwords",
    "manage_clients":   "Add and delete client tenants",
    "manage_policy":    "Edit password policy",
    "manage_roles":     "Create and delete custom roles",
    "manage_scraper":   "Configure scraper health settings",
    "manage_sources":   "Add and edit news sources",
    "manage_changelog": "Edit changelog entries",
}

_ALL = list(ALL_PERMISSIONS.keys())

SYSTEM_ROLES: dict[str, dict] = {
    "superadmin": {
        "display_name": "Super Admin",
        "permissions": _ALL,
    },
    "admin": {
        "display_name": "Admin",
        "permissions": [p for p in _ALL if p not in ("manage_roles", "manage_clients")],
    },
    "analyst": {
        "display_name": "Analyst",
        "permissions": [
            "view_news", "export_data", "manage_rfi", "manage_pir",
            "view_intel", "view_ta", "view_ioc", "view_cve",
            "view_newsletter", "view_tweets", "view_stix", "wisemap_access",
        ],
    },
}


def _col():
    return get_database()[ROLES_COLLECTION]


async def ensure_system_roles() -> None:
    col = _col()
    for name, spec in SYSTEM_ROLES.items():
        existing = await col.find_one({"name": name})
        if existing:
            # superadmin always synced to full permission list; other system roles keep admin edits
            if name == "superadmin":
                await col.update_one(
                    {"name": name},
                    {"$set": {"permissions": spec["permissions"], "display_name": spec["display_name"]}},
                )
        else:
            await col.insert_one({
                "name":         name,
                "display_name": spec["display_name"],
                "permissions":  spec["permissions"],
                "is_system":    True,
                "created_at":   datetime.utcnow().isoformat(),
                "created_by":   "system",
            })
    await col.create_index("name", unique=True, background=True)


async def list_roles() -> list[dict]:
    return await _col().find({}, {"_id": 0}).to_list(length=200)


async def get_role(name: str) -> dict | None:
    return await _col().find_one({"name": name}, {"_id": 0})


async def role_exists(name: str) -> bool:
    return await _col().count_documents({"name": name}) > 0


async def get_role_names() -> list[str]:
    docs = await _col().find({}, {"name": 1, "_id": 0}).to_list(length=200)
    return [d["name"] for d in docs]


async def create_role(name: str, display_name: str, permissions: list[str], created_by: str) -> dict:
    col = _col()
    doc = {
        "name":         name,
        "display_name": display_name,
        "permissions":  permissions,
        "is_system":    False,
        "created_at":   datetime.utcnow().isoformat(),
        "created_by":   created_by,
    }
    await col.insert_one(doc)
    doc.pop("_id", None)
    return doc


async def delete_role(name: str) -> bool:
    role = await _col().find_one({"name": name})
    if not role:
        return False
    if role.get("is_system"):
        raise ValueError("Cannot delete system role")
    result = await _col().delete_one({"name": name})
    return result.deleted_count > 0


async def update_role(name: str, display_name: str, permissions: list[str]) -> dict | None:
    """Update a role. Returns updated doc, None if missing. Raises ValueError for superadmin."""
    col = _col()
    role = await col.find_one({"name": name})
    if not role:
        return None
    if name == "superadmin":
        raise ValueError("Cannot edit superadmin role")
    await col.update_one(
        {"name": name},
        {"$set": {"display_name": display_name, "permissions": permissions}},
    )
    return await col.find_one({"name": name}, {"_id": 0})


async def role_has_permission(role_name: str, permission: str) -> bool:
    role = await _col().find_one({"name": role_name}, {"permissions": 1, "_id": 0})
    return bool(role) and permission in role.get("permissions", [])
