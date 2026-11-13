import re
from app.database import get_database

POLICY_COLLECTION = "password_policy"

_DEFAULT_POLICY = {
    "min_length":      8,
    "require_upper":   True,
    "require_lower":   True,
    "require_number":  True,
    "require_symbol":  True,
}


def _col():
    return get_database()[POLICY_COLLECTION]


async def get_policy() -> dict:
    doc = await _col().find_one({}, {"_id": 0})
    return doc if doc else dict(_DEFAULT_POLICY)


async def save_policy(policy: dict) -> dict:
    await _col().replace_one({}, {**policy}, upsert=True)
    return policy


def validate_password(password: str, policy: dict) -> list[str]:
    """Return list of violation strings. Empty = valid."""
    errors = []
    min_len = policy.get("min_length", 8)
    if len(password) < min_len:
        errors.append(f"min {min_len} characters")
    if policy.get("require_upper", True) and not re.search(r'[A-Z]', password):
        errors.append("uppercase letter")
    if policy.get("require_lower", True) and not re.search(r'[a-z]', password):
        errors.append("lowercase letter")
    if policy.get("require_number", True) and not re.search(r'[0-9]', password):
        errors.append("number")
    if policy.get("require_symbol", True) and not re.search(r'[^A-Za-z0-9]', password):
        errors.append("symbol")
    return errors


def policy_hint(policy: dict) -> str:
    parts = [f"Min {policy.get('min_length', 8)} chars"]
    if policy.get("require_upper",  True): parts.append("uppercase")
    if policy.get("require_lower",  True): parts.append("lowercase")
    if policy.get("require_number", True): parts.append("number")
    if policy.get("require_symbol", True): parts.append("symbol")
    return " · ".join(parts)
