from pydantic import BaseModel
from typing import Optional


class RFICreate(BaseModel):
    requester: str
    question: str
    due_date: Optional[str] = None       # YYYY-MM-DD
    status: str = "open"                  # open | in_progress | closed
    linked_pir: Optional[str] = None     # PIR _id string
    response: str = ""


class RFIUpdate(BaseModel):
    requester: Optional[str] = None
    question: Optional[str] = None
    due_date: Optional[str] = None
    status: Optional[str] = None
    linked_pir: Optional[str] = None
    response: Optional[str] = None


class RFIOut(BaseModel):
    id: str
    requester: str
    question: str
    due_date: Optional[str]
    status: str
    linked_pir: Optional[str]
    response: str
    created_at: str
    updated_at: str
