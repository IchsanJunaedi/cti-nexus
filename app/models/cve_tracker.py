from pydantic import BaseModel, Field, field_validator
from typing import Any


class CveReference(BaseModel):
    url: str
    tags: list[str] = []

    @field_validator('tags', mode='before')
    @classmethod
    def coerce_tags(cls, v):
        if v is None or v == '':
            return []
        if isinstance(v, str):
            return [v]
        return v


class CvePoc(BaseModel):
    url: str
    source: str = ""
    type: str = "poc"   # exploit | poc | metasploit_module | nuclei_template


class CveOut(BaseModel):
    id: str = Field(alias="_id")
    cve_id: str
    tech: str
    link: str
    summary: str
    published: str
    reference: list[CveReference] = []
    affected: list[dict] = []
    solutions: str = ""
    cve_score: float = 0
    cve_severity: str = ""
    cvss_vector: str = ""
    last_updated: str = ""
    cve_modified_date: str = ""
    updated_since_detected: bool = False
    last_changed_on: str = ""
    poc_available: bool = False
    pocs: list[CvePoc] = []
    false_positive: bool = False
    detected_on: str = ""
    news_mentions_count: int = 0
    news_mentions: list[dict] = []
    cisa_kev: bool = False
    cisa_kev_date_added: str = ""
    cisa_kev_due_date: str = ""
    cisa_kev_vendor: str = ""
    cisa_kev_product: str = ""
    cisa_kev_name: str = ""
    cisa_kev_description: str = ""
    cisa_kev_action: str = ""
    active_exploitation: str = ""
    exploit_db_checked_at: str = ""
    exploit_db_hits: list[dict] = []
    newsletter_mentions: list[dict] = []
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str = ""
    epss_checked_at: str = ""
    tech_exposure: str = "internal"
    hosting_type: str = "on_prem"
    adjusted_risk_score: float = 0.0
    epss_multiplier: float = 1.0
    hosting_multiplier: float = 1.0

    model_config = {"populate_by_name": True}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "CveOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class CveListResponse(BaseModel):
    cves: list[CveOut]
    total: int
    page: int
    page_size: int


class CveStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class CveTicket(BaseModel):
    cve_id: str
    ticket_id: str = ""
    cve_reported_date: str = ""
    affected_asset: str = ""
    affected_version: str = ""
    fixed_version: str = ""
    asset_owner: str = ""
    owner_email: str = ""
    owner_team: str = ""
    active_exploitation: str = ""
    remediation_date_plan: str = ""
    remediation_status: str = ""
    actual_remediation_date: str = ""
    escalation_required: bool = False
    comments: str = ""
    risk_acceptance: str = ""
    closure_date: str = ""
    updated_at: str = ""


class AcknowledgeRequest(BaseModel):
    analyst_name: str
