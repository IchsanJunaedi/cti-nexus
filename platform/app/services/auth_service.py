# Canonical local auth path: password hash, JWT encode/decode, user CRUD.
# OIDC/SSO flow lives in oidc_service.py.
from datetime import datetime, timedelta
import bcrypt
from jose import JWTError, jwt
from app.database import get_database
from app.config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRE_MIN, USERS_COLLECTION


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def _resolve_client_ids(user_doc: dict) -> list[str]:
    """Normalize old client_id:str to client_ids:list for backward compat."""
    if "client_ids" in user_doc and isinstance(user_doc["client_ids"], list):
        return user_doc["client_ids"] or ["default"]
    if "client_id" in user_doc and user_doc["client_id"]:
        return [user_doc["client_id"]]
    return ["default"]


def create_token(username: str, role: str, client_ids: list[str] | None = None) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MIN)
    return jwt.encode(
        {"sub": username, "role": role, "client_ids": client_ids or ["default"], "exp": expire},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def _col():
    return get_database()[USERS_COLLECTION]


async def get_user(username: str) -> dict | None:
    return await _col().find_one({"username": username})


async def user_count() -> int:
    return await _col().count_documents({})


async def create_user(username: str, password: str, role: str, created_by: str, client_ids: list[str] | None = None) -> dict:
    col = _col()
    await col.create_index("username", unique=True, background=True)
    ids = client_ids or ["default"]
    doc = {
        "username":        username,
        "hashed_password": hash_password(password),
        "role":            role,
        "client_ids":      ids,
        "created_at":      datetime.utcnow().isoformat(),
        "created_by":      created_by,
    }
    await col.insert_one(doc)
    return {"username": username, "role": role, "client_ids": ids, "created_at": doc["created_at"]}


async def update_user_clients(username: str, client_ids: list[str]) -> bool:
    result = await _col().update_one(
        {"username": username},
        {"$set": {"client_ids": client_ids}},
    )
    return result.matched_count > 0


async def update_user_role(username: str, role: str) -> bool:
    result = await _col().update_one(
        {"username": username},
        {"$set": {"role": role}},
    )
    return result.matched_count > 0


async def list_users() -> list[dict]:
    docs = await _col().find({}, {"hashed_password": 0, "_id": 0}).to_list(length=500)
    return docs


async def update_last_sign_in(username: str) -> None:
    await _col().update_one(
        {"username": username},
        {"$set": {"last_sign_in": datetime.utcnow().isoformat()}},
    )


async def reset_password(username: str, new_password: str) -> bool:
    result = await _col().update_one(
        {"username": username},
        {"$set": {"hashed_password": hash_password(new_password), "force_pw_change": False}},
    )
    return result.matched_count > 0


async def delete_user(username: str) -> bool:
    result = await _col().delete_one({"username": username})
    return result.deleted_count > 0


async def get_user_role(username: str) -> str | None:
    doc = await _col().find_one({"username": username}, {"role": 1})
    return doc["role"] if doc else None


async def flag_force_pw_change(usernames: list[str] | None = None) -> int:
    """Flag users for forced password change on next login.
    Pass None to flag ALL non-admin users."""
    col = _col()
    query: dict = {"role": {"$ne": "admin"}}
    if usernames is not None:
        query["username"] = {"$in": usernames}
    result = await col.update_many(query, {"$set": {"force_pw_change": True}})
    return result.modified_count
