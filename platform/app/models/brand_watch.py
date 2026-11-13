from pydantic import BaseModel, Field
from typing import Optional


class MonitoredBrand(BaseModel):
    id: str = Field(alias="_id")
    name: str                               # full domain, e.g. "example.com"
    client_id: str = "default"
    added_date: str
    last_scan: Optional[str] = None
    favicon_hash: Optional[str] = None
    match_count: int = 0
    new_match_count: int = 0
    suspicious_count: int = 0

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "MonitoredBrand":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class MonitoredBrandAdd(BaseModel):
    name: str


class MonitoredBrandListResponse(BaseModel):
    items: list[MonitoredBrand]
    total: int
    page: int
    page_size: int


class BrandFaviconMatch(BaseModel):
    id: str = Field(alias="_id")
    base_name: str
    client_id: str = "default"
    ip_str: str = ""
    port: int = 0
    hostnames: list[str] = []
    org: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    favicon_hash: str = ""
    is_own_domain: bool = False
    first_seen: str = ""
    last_seen: str = ""
    newly_seen: bool = False
    acknowledged: bool = False
    ack_by: Optional[str] = None
    ack_date: Optional[str] = None

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "BrandFaviconMatch":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class BrandFaviconMatchListResponse(BaseModel):
    items: list[BrandFaviconMatch]
    total: int
    page: int
    page_size: int


class BrandWatchStats(BaseModel):
    brands: int
    total_matches: int
    new_matches: int
    suspicious: int
    unacknowledged: int
