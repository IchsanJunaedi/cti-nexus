from pydantic import BaseModel, Field
from typing import Any


class CisaKevEntry(BaseModel):
    id: str = Field(alias="_id")
    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""
    known_ransomware_use: str = "Unknown"
    notes: str = ""
    cwes: list[str] = []
    matched_tracker: bool = False
    last_synced: str = ""

    model_config = {"populate_by_name": True}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "CisaKevEntry":
        doc = dict(doc)
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class CisaKevListResponse(BaseModel):
    items: list[CisaKevEntry]
    total: int
    page: int
    page_size: int


class CisaKevStats(BaseModel):
    total: int
    matched: int
    unmatched: int
    ransomware_known: int
    due_soon: int  # due_date within next 7 days, not yet matched/remediated
