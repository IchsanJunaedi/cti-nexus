from pydantic import BaseModel, Field
from typing import Any

EXPOSURE_MULTIPLIER = {"public": 1.5, "both": 1.25, "internal": 1.0}
HOSTING_MULTIPLIER  = {"on_prem": 1.0, "cloud": 1.0, "saas": 0.8}


class TechStack(BaseModel):
    id: str = Field(alias="_id")
    name: str
    added_date: str
    source: str
    exposure: str = "internal"
    hosting_type: str = "on_prem"
    vendor: str = ""

    model_config = {"populate_by_name": True}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "TechStack":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class TechStackAdd(BaseModel):
    name: str
    exposure: str = "internal"
    hosting_type: str = "on_prem"
    vendor: str = ""


class TechStackExposureUpdate(BaseModel):
    exposure: str


class TechStackHostingUpdate(BaseModel):
    hosting_type: str


class TechStackVendorUpdate(BaseModel):
    vendor: str


class TechStackListResponse(BaseModel):
    items: list[TechStack]
    total: int
    page: int
    page_size: int
