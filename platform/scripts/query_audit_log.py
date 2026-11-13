#!/usr/bin/env python3
"""Query the CTI Nexus audit log API.

Usage:
  python query_audit_log.py                          # all logs
  python query_audit_log.py --user admin           # filter by user
  python query_audit_log.py --action mark_false_positive
  python query_audit_log.py --page 2 --page-size 100
  python query_audit_log.py --export audit.json      # save to file

Config: set BASE_URL, USERNAME, PASSWORD below or via env vars:
  AUDIT_BASE_URL, AUDIT_USERNAME, AUDIT_PASSWORD
"""
import argparse
import json
import os
import sys
import urllib.parse
import urllib.request


BASE_URL = os.getenv("AUDIT_BASE_URL", "http://localhost:8000")
USERNAME = os.getenv("AUDIT_USERNAME", "admin")
PASSWORD = os.getenv("AUDIT_PASSWORD", "")


def _post(path: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def _get(path: str, token: str) -> dict:
    req = urllib.request.Request(
        BASE_URL + path,
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def get_token(username: str, password: str) -> str:
    if not password:
        password = input(f"Password for {username}: ")
    try:
        data = _post("/api/auth/login", {"username": username, "password": password})
        return data["access_token"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Login failed ({e.code}): {body}", file=sys.stderr)
        sys.exit(1)


def fetch_logs(token: str, page: int, page_size: int,
               user: str | None, action: str | None) -> dict:
    params: dict = {"page": page, "page_size": page_size}
    if user:
        params["user"] = user
    if action:
        params["action"] = action
    qs = urllib.parse.urlencode(params)
    try:
        return _get(f"/api/auth/audit-log?{qs}", token)
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f"Request failed ({e.code}): {body}", file=sys.stderr)
        sys.exit(1)


def print_table(logs: list[dict]) -> None:
    if not logs:
        print("No logs found.")
        return
    cols = ["timestamp", "user", "action", "target_id", "ip"]
    widths = {c: max(len(c), max(len(str(r.get(c, ""))) for r in logs)) for c in cols}
    header = "  ".join(c.upper().ljust(widths[c]) for c in cols)
    sep    = "  ".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for r in logs:
        row = "  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols)
        detail = r.get("detail") or {}
        if detail:
            row += f"  {json.dumps(detail)}"
        print(row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Query CTI Nexus audit log")
    parser.add_argument("--user",      help="Filter by username (partial match)")
    parser.add_argument("--action",    help="Filter by action name (partial match)")
    parser.add_argument("--page",      type=int, default=1)
    parser.add_argument("--page-size", type=int, default=50, dest="page_size")
    parser.add_argument("--export",    metavar="FILE", help="Save full result JSON to file")
    parser.add_argument("--username",  default=USERNAME, help="Login username")
    parser.add_argument("--password",  default=PASSWORD, help="Login password")
    args = parser.parse_args()

    token = get_token(args.username, args.password)
    data  = fetch_logs(token, args.page, args.page_size, args.user, args.action)

    logs  = data.get("logs", [])
    total = data.get("total", 0)

    print(f"\nAudit Log  —  {total} total entries  (page {args.page}, showing {len(logs)})\n")
    print_table(logs)

    if args.export:
        with open(args.export, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nSaved to {args.export}")


if __name__ == "__main__":
    main()
