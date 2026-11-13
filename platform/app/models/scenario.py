from pydantic import BaseModel, Field
from typing import Any, Optional


class ScenarioStep(BaseModel):
    id: str
    order: int
    note: str = ""
    node_ids: list[str] = []
    edge_ids: list[str] = []
    created_at: str = ""


class ScenarioCreate(BaseModel):
    name: str
    description: str = ""
    diagram_id: str
    steps: list[dict] = []


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class ScenarioStepsReplace(BaseModel):
    steps: list[dict]


class ScenarioOut(BaseModel):
    id: str = Field(alias="_id")
    name: str = ""
    description: str = ""
    diagram_id: str = ""
    client_id: str = ""
    owner: str = ""
    steps: list[ScenarioStep] = []
    version: int = 1
    created_at: str = ""
    updated_at: str = ""

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "ScenarioOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class ScenarioListOut(BaseModel):
    id: str = Field(alias="_id")
    name: str = ""
    description: str = ""
    diagram_id: str = ""
    owner: str = ""
    step_count: int = 0
    updated_at: str = ""

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "ScenarioListOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)
