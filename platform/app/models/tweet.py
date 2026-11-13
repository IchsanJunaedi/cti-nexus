from pydantic import BaseModel, Field
from typing import Any


class TweetOut(BaseModel):
    id: str = Field(alias="_id")
    tweet_id: str
    url: str
    text: str
    author_username: str
    author_name: str
    author_avatar: str = ""
    author_followers: int = 0
    posted_on: str
    lang: str = "en"
    media_urls: list[str] = []
    fetched_at: str = ""
    # enrichment fields from monitorX scan + LLM
    apac_indicator: bool = False
    mentioned_group: list[str] = []
    mentioned_apac_country: list[str] = []
    mentioned_apac_people: list[str] = []
    cve_list: list[str] = []
    zero_day_list: list[str] = []
    databreach_list: list[str] = []
    ot_status: bool = False
    report_status: bool = False
    related_cyber: bool = True
    confidence: float | None = None
    industries_impacted: list[str] = []
    victim_countries: list[str] = []
    actor_countries: list[str] = []
    confirmed_incident: bool = False
    incident_confidence: float | None = None
    incident_indicators: list[str] = []
    victim_name: str | None = None

    model_config = {"populate_by_name": True, "extra": "ignore"}

    @classmethod
    def from_mongo(cls, doc: dict[str, Any]) -> "TweetOut":
        doc["_id"] = str(doc["_id"])
        return cls(**doc)


class TweetListResponse(BaseModel):
    tweets: list[TweetOut]
    total: int
    page: int
    page_size: int
