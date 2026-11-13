from pydantic import BaseModel, Field
from typing import Optional


class MonitoredDomain(BaseModel):
    id: str = Field(alias="_id")
    name: str                               # base domain, no TLD (e.g. "example")
    client_id: str = "default"
    added_date: str
    last_scan: Optional[str] = None
    tld_count: int = 0
    registered_count: int = 0
    alive_count: int = 0
    newly_registered_count: int = 0
    risk_count: int = 0
    parked_count: int = 0

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "MonitoredDomain":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class MonitoredDomainAdd(BaseModel):
    name: str


class MonitoredDomainListResponse(BaseModel):
    items: list[MonitoredDomain]
    total: int
    page: int
    page_size: int


class DomainScanResult(BaseModel):
    id: str = Field(alias="_id")
    base_name: str
    domain: str                             # base_name.tld
    tld: str
    client_id: str = "default"
    timestamp: str = ""
    registered: bool = False
    alive: bool = False
    newly_registered: bool = False
    risk_indicators: list[str] = []
    url: str = ""
    dns: dict = {}
    whois: dict = {}
    tls: dict = {}
    http: dict = {}
    ip_info: dict = {}
    asn_info: dict = {}
    acknowledged: bool = False
    ack_by: Optional[str] = None
    ack_date: Optional[str] = None
    parked: bool = False
    parked_provider: Optional[str] = None

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "DomainScanResult":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class DomainScanResultListResponse(BaseModel):
    items: list[DomainScanResult]
    total: int
    page: int
    page_size: int


class DomainWatchStats(BaseModel):
    domains: int
    total_findings: int
    registered: int
    alive: int
    newly_registered: int
    at_risk: int
    unacknowledged: int
    parked: int
