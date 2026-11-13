from pydantic import BaseModel, Field
from typing import Any


class TAGroup(BaseModel):
    id: str = Field(alias="_id")
    name: str
    added_date: str | None = None
    source: str
    aliases: list[str] = []

    model_config = {"populate_by_name": True}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "TAGroup":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class TAGroupAdd(BaseModel):
    name: str


class TAGroupListResponse(BaseModel):
    groups: list[TAGroup]
    total: int
    page: int
    page_size: int
