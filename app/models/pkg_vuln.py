from pydantic import BaseModel, Field
from typing import Optional


_VALID_ECOSYSTEMS = {"npm", "PyPI", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist", "Hex"}


class MonitoredPackage(BaseModel):
    id: str = Field(alias="_id")
    name: str
    ecosystem: str
    version: Optional[str] = None          # pinned version (if known)
    client_id: str = "default"
    added_date: str
    last_scan: Optional[str] = None
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    highest_severity: str = "NONE"
    latest_version: Optional[str] = None
    source: str = "manual"                  # manual | lockfile
    dep_direct_count: int = 0
    dep_indirect_count: int = 0
    dep_total_count: int = 0
    dep_resolved_at: Optional[str] = None
    scorecard_score: Optional[float] = None
    scorecard_date: Optional[str] = None

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "MonitoredPackage":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class MonitoredPackageAdd(BaseModel):
    name: str
    ecosystem: str
    version: Optional[str] = None

    def validate_ecosystem(self) -> bool:
        return self.ecosystem in _VALID_ECOSYSTEMS


class MonitoredPackageEdit(BaseModel):
    version: Optional[str] = None
    ecosystem: Optional[str] = None


class MonitoredPackageListResponse(BaseModel):
    items: list[MonitoredPackage]
    total: int
    page: int
    page_size: int


class PackageVuln(BaseModel):
    id: str = Field(alias="_id")
    package_name: str
    ecosystem: str
    pinned_version: Optional[str] = None    # the version that was queried
    advisory_id: str
    aliases: list[str] = []
    summary: str = ""
    details: str = ""
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    # Composite enrichment
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    kev: bool = False
    kev_date_added: Optional[str] = None
    adjusted_score: Optional[float] = None  # composite: cvss × epss_mult × kev_mult
    adjusted_severity: Optional[str] = None # re-label after composite
    # Vuln metadata
    published: Optional[str] = None
    modified: Optional[str] = None
    fixed_version: Optional[str] = None
    affected_version_ranges: list[str] = []
    references: list[str] = []
    client_id: str = "default"
    acknowledged: bool = False
    ack_by: Optional[str] = None
    ack_date: Optional[str] = None
    source: str = "osv.dev"

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "PackageVuln":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)


class PackageVulnListResponse(BaseModel):
    items: list[PackageVuln]
    total: int
    page: int
    page_size: int


class LockfileImportResult(BaseModel):
    parsed: int
    added: int
    skipped: int
    errors: list[str] = []
    packages: list[dict] = []


class DepNode(BaseModel):
    name: str
    version: Optional[str] = None
    system: Optional[str] = None


class ScorecardCheck(BaseModel):
    name: str
    score: Optional[int] = None
    reason: str = ""


class PackageDepGraph(BaseModel):
    id: str = Field(alias="_id")
    pkg_id: str
    package_name: str
    ecosystem: str
    version: Optional[str] = None
    client_id: str = "default"
    resolved_at: Optional[str] = None
    direct_count: int = 0
    indirect_count: int = 0
    total_count: int = 0
    direct_deps: list[DepNode] = []
    indirect_deps: list[DepNode] = []
    scorecard_score: Optional[float] = None
    scorecard_date: Optional[str] = None
    scorecard_project: Optional[str] = None
    scorecard_checks: list[ScorecardCheck] = []
    error: Optional[str] = None

    class Config:
        populate_by_name = True

    @classmethod
    def from_mongo(cls, doc: dict) -> "PackageDepGraph":
        doc = dict(doc)
        doc["_id"] = str(doc.get("_id", ""))
        return cls(**doc)
