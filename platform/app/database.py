from motor.motor_asyncio import AsyncIOMotorClient
from app.config import MONGO_URI, DB_NAME, TA_MONGO_URI, TA_DB_NAME

_client: AsyncIOMotorClient | None = None
_ta_client: AsyncIOMotorClient | None = None


def get_database():
    return _client[DB_NAME]


def get_ta_database():
    return _ta_client[TA_DB_NAME]


async def connect():
    global _client, _ta_client
    _client = AsyncIOMotorClient(MONGO_URI)
    _ta_client = AsyncIOMotorClient(TA_MONGO_URI)


async def disconnect():
    global _client, _ta_client
    if _client:
        _client.close()
        _client = None
    if _ta_client:
        _ta_client.close()
        _ta_client = None
