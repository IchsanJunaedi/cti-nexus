from pydantic import BaseModel
from typing import Optional


class PIRCriteria(BaseModel):
    threat_actors: list[str] = []
    industries: list[str] = []
    countries: list[str] = []
    news_types: list[str] = []
    keywords: list[str] = []
    ttps: list[str] = []


class PIRCreate(BaseModel):
    title: str
    description: str = ""
    priority: str = "P2"
    owner: str = ""
    criteria: PIRCriteria = PIRCriteria()
    start_date: Optional[str] = None  # YYYY-MM-DD, inclusive
    end_date: Optional[str] = None    # YYYY-MM-DD, inclusive; PIR auto-skips after this


class PIRUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    owner: Optional[str] = None
    status: Optional[str] = None
    criteria: Optional[PIRCriteria] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class PIRNote(BaseModel):
    url: str
    note: str
    analyst: str = ""


class PIROut(BaseModel):
    id: str
    title: str
    description: str
    priority: str
    owner: str
    status: str
    criteria: PIRCriteria
    start_date: Optional[str]
    end_date: Optional[str]
    coverage_count: int
    last_match: Optional[str]
    created_at: str
    updated_at: str
