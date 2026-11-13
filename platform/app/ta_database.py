# Backwards-compat shim. All clients now managed in database.py.
from app.database import get_ta_database, connect as ta_connect, disconnect as ta_disconnect

__all__ = ["get_ta_database", "ta_connect", "ta_disconnect"]
