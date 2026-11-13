"""End-to-end API checks for IOC Management. Needs server + DB running.

Run:
    IOC_USER=admin IOC_PASS=secret \
    BASE=https://localhost:8443 FEED_TOKEN=xxx \
    python test_ioc_api.py

Env vars:
    BASE        default https://localhost:8443
    IOC_USER    required — login username
    IOC_PASS    required — login password
    FEED_TOKEN  optional — value of IOC_FEED_TOKEN (skips feed test if unset)
    SAMPLE_TYPE/SAMPLE_VALUE  optional — a real IOC to exercise detail/related/tag

Self-signed cert → verification disabled.
"""
import os
import sys
import httpx

BASE = os.getenv("BASE", "https://localhost:8443").rstrip("/")
USER = os.getenv("IOC_USER", "")
PASS = os.getenv("IOC_PASS", "")
FEED_TOKEN = os.getenv("FEED_TOKEN", "")

results: list[tuple[str, bool, str]] = []


def rec(name: str, ok: bool, detail: str = ""):
    results.append((name, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail and not ok else ""))


def main() -> int:
    if not USER or not PASS:
        print("Set IOC_USER and IOC_PASS env vars.")
        return 2

    c = httpx.Client(base_url=BASE, verify=False, timeout=20.0)

    # ── login ──────────────────────────────────────────────────────────
    r = c.post("/api/auth/login", json={"username": USER, "password": PASS})
    if r.status_code != 200:
        print(f"LOGIN FAILED {r.status_code}: {r.text[:200]}")
        return 2
    token = r.json().get("access_token") or r.json().get("token")
    if not token:
        print(f"No token in login response: {r.text[:200]}")
        return 2
    H = {"Authorization": f"Bearer {token}"}
    print(f"logged in as {USER}\n")

    # ── auth guard: no token -> 401 ────────────────────────────────────
    rec("auth guard 401", c.get("/api/iocs").status_code == 401)

    # ── P0-A: list returns enrichment + verdict filter ─────────────────
    r = c.get("/api/iocs", params={"page_size": 5}, headers=H)
    ok = r.status_code == 200 and "iocs" in r.json()
    rec("P0-A list iocs", ok, f"{r.status_code}")
    iocs = r.json().get("iocs", []) if ok else []
    rec("P0-A enrichment field present", any("enrichment" in d for d in iocs) or len(iocs) == 0)
    rec("P0-A enrichment_verdict filter",
        c.get("/api/iocs", params={"enrichment_verdict": "malicious"}, headers=H).status_code == 200)

    # pick a sample IOC for detail/related/tag tests
    st = os.getenv("SAMPLE_TYPE")
    sv = os.getenv("SAMPLE_VALUE")
    if not st and iocs:
        st, sv = iocs[0].get("type"), iocs[0].get("value")

    # ── P0-A detail returns providers ──────────────────────────────────
    if st and sv:
        r = c.get(f"/api/iocs/{st}/{sv}", headers=H)
        rec("P0-A ioc detail", r.status_code == 200, f"{r.status_code}")

    # ── P1-B: CSV export, STIX, feed ───────────────────────────────────
    r = c.get("/api/iocs/export.csv", params={"actionability": "block_now"}, headers=H)
    rec("P1-B csv export", r.status_code == 200 and "text/csv" in r.headers.get("content-type", ""),
        f"{r.status_code} {r.headers.get('content-type','')}")
    r = c.get("/api/stix/iocs", params={"limit": 5}, headers=H)
    rec("P1-B stix export", r.status_code == 200 and r.json().get("type") == "bundle", f"{r.status_code}")

    rec("P1-B feed rejects bad token",
        c.get("/api/iocs/feed", params={"format": "plain", "token": "WRONG"}).status_code == 401)
    if FEED_TOKEN:
        r = c.get("/api/iocs/feed", params={"format": "plain", "token": FEED_TOKEN})
        rec("P1-B feed accepts good token", r.status_code == 200, f"{r.status_code}")
    else:
        print("SKIP  P1-B feed good-token (set FEED_TOKEN)")

    # ── P2-A: related pivot (route must precede catch-all) ─────────────
    if st and sv:
        r = c.get(f"/api/iocs/related/{st}/{sv}", headers=H)
        rec("P2-A related pivot", r.status_code in (200, 404),
            f"{r.status_code} (500=route shadowed by catch-all)")

    # ── P2-C: bulk lookup + CIDR search ────────────────────────────────
    r = c.post("/api/iocs/lookup", headers=H, json={"values": [sv or "8.8.8.8", "no-such-ioc.invalid"]})
    ok = r.status_code == 200 and "found" in r.json() and "not_found" in r.json()
    rec("P2-C bulk lookup", ok, f"{r.status_code}")
    rec("P2-C cidr search",
        c.get("/api/iocs", params={"search": "8.8.8.0/24"}, headers=H).status_code == 200)

    # ── P2-B: TLP set (mutates — only if sample present) ───────────────
    if st and sv:
        r = c.post(f"/api/iocs/{st}/{sv}/tlp", headers=H, json={"tlp": "TLP:AMBER"})
        rec("P2-B set tlp", r.status_code in (200, 404), f"{r.status_code}")

    # ── summary ────────────────────────────────────────────────────────
    fails = [n for n, ok, _ in results if not ok]
    print(f"\n{len(results)-len(fails)}/{len(results)} passed" +
          (f"  — FAILED: {', '.join(fails)}" if fails else "  — ALL PASS"))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
