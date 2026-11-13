from pydantic import BaseModel, Field
from typing import Any, Optional


class DiagramCreate(BaseModel):
    name: str
    doc: dict = {"nodes": [], "edges": [], "zones": []}
    view: dict = {"x": 0, "y": 0, "k": 1}


class DiagramUpdate(BaseModel):
    name: Optional[str] = None
    doc: Optional[dict] = None
    view: Optional[dict] = None


class DiagramOut(BaseModel):
    id: str = Field(alias="_id")
    name: str = ""
    doc: dict = {}
    view: dict = {}
    client_id: str = ""
    owner: str = ""
    created_at: str = ""
    updated_at: str = ""

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "DiagramOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class DiagramListOut(BaseModel):
    id: str = Field(alias="_id")
    name: str = ""
    owner: str = ""
    updated_at: str = ""

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "DiagramListOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)
