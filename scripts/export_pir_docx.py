"""
PIR Report Generator — baseline script (standalone).

Fetches a PIR + all matching articles + analyst notes from MongoDB,
then builds a Word document (.docx).

Expand this file to customise: cover page, logos, table of contents,
charts, custom styles, conditional sections, etc.

Usage:
    python export_pir_docx.py <pir_id> [output.docx]

Requirements:
    pip install python-docx pymongo
"""
import io
import re
import sys
from datetime import datetime

from bson import ObjectId
from pymongo import MongoClient

# ── Connection (edit to match your environment) ───────────────────
MONGO_URI  = "mongodb://ti-news:ElbiRxywfCcolEI@10.8.20.78:27017/?authSource=news_db"
DB_NAME    = "news_db"
ARTICLES_COLLECTION = "articles"
PIR_COLLECTION      = "pir_requirements"
NOTES_COLLECTION    = "pir_notes"


# ─────────────────────────────────────────────────────────────────
# DATA LAYER
# ─────────────────────────────────────────────────────────────────

def _build_article_query(criteria: dict) -> dict:
    q: dict = {}
    if criteria.get("threat_actors"):
        q["threat_actors"] = {"$in": criteria["threat_actors"]}
    if criteria.get("industries"):
        q["impacted_industries"] = {"$in": criteria["industries"]}
    if criteria.get("countries"):
        q["mentioned_countries"] = {"$in": criteria["countries"]}
    if criteria.get("news_types"):
        q["news_type"] = {"$in": criteria["news_types"]}
    if criteria.get("keywords"):
        pattern = "|".join(re.escape(k) for k in criteria["keywords"])
        q["title"] = {"$regex": pattern, "$options": "i"}
    if criteria.get("ttps"):
        q["ttps.id"] = {"$in": criteria["ttps"]}
    return q


def fetch_pir_data(pir_id: str) -> dict:
    """Connect to MongoDB, pull PIR + articles + notes, return unified dict."""
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]

    pir = db[PIR_COLLECTION].find_one({"_id": ObjectId(pir_id)})
    if not pir:
        raise ValueError(f"PIR not found: {pir_id}")

    q = _build_article_query(pir.get("criteria", {}))
    proj = {
        "_id": 1, "title": 1, "url": 1, "posted_on": 1, "source": 1,
        "news_type": 1, "threat_actors": 1, "impacted_industries": 1,
        "mentioned_countries": 1,
    }
    articles_raw = list(
        db[ARTICLES_COLLECTION].find(q, proj).sort("posted_on", -1)
    )

    pir_id_str = str(pir["_id"])
    notes_raw  = list(db[NOTES_COLLECTION].find({"pir_id": pir_id_str}))
    notes_by_url = {n["url"]: n for n in notes_raw}

    articles = []
    for a in articles_raw:
        a["_id"] = str(a["_id"])
        a["analyst_note"] = notes_by_url.get(a.get("url", ""), {})
        articles.append(a)

    client.close()

    return {
        "pir": pir,
        "articles": articles,
        "total_articles": len(articles),
        "exported_at": datetime.utcnow().isoformat(),
    }


# ─────────────────────────────────────────────────────────────────
# DOCUMENT BUILDER  ← expand this section
# ─────────────────────────────────────────────────────────────────

def build_docx(data: dict) -> bytes:
    """
    Build a .docx report from the PIR data dict.

    data shape:
        {
          "pir": { title, description, priority, owner, status, criteria, ... },
          "articles": [ { title, url, source, posted_on, news_type,
                          threat_actors, impacted_industries, mentioned_countries,
                          analyst_note: { note, analyst, updated_at } }, ... ],
          "total_articles": int,
          "exported_at": ISO-string,
        }
    """
    from docx import Document
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH

    doc  = Document()
    pir  = data["pir"]
    arts = data["articles"]

    # ── Cover / Title ─────────────────────────────────────────────
    h = doc.add_heading(level=1)
    h.alignment = WD_ALIGN_PARAGRAPH.LEFT
    h.add_run(f"PIR Report: {pir.get('title', 'Untitled')}")

    p_meta = doc.add_paragraph()
    meta_run = p_meta.add_run(
        f"Priority: {pir.get('priority','—')}  ·  "
        f"Owner: {pir.get('owner','—')}  ·  "
        f"Status: {pir.get('status','—').upper()}  ·  "
        f"Generated: {data['exported_at'][:10]}"
    )
    meta_run.font.size = Pt(9)
    meta_run.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

    doc.add_paragraph()

    # ── Intelligence Requirement ──────────────────────────────────
    doc.add_heading("Intelligence Requirement", level=2)
    doc.add_paragraph(pir.get("description") or "No description provided.")

    # ── Collection Criteria ───────────────────────────────────────
    doc.add_heading("Collection Criteria", level=2)
    criteria = pir.get("criteria", {})
    for label, key in [
        ("Threat Actors",  "threat_actors"),
        ("Industries",     "industries"),
        ("Countries",      "countries"),
        ("News Types",     "news_types"),
        ("Keywords",       "keywords"),
        ("MITRE TTPs",     "ttps"),
    ]:
        vals = criteria.get(key, [])
        if vals:
            p = doc.add_paragraph(style="List Bullet")
            r = p.add_run(f"{label}: ")
            r.bold = True
            p.add_run(", ".join(str(v) for v in vals))

    # ── Coverage Summary ──────────────────────────────────────────
    doc.add_heading("Coverage Summary", level=2)
    noted = sum(1 for a in arts if a.get("analyst_note", {}).get("note"))
    p = doc.add_paragraph()
    p.add_run(f"Total Matching Articles: {data['total_articles']}\n")
    p.add_run(f"Articles with Analyst Notes: {noted}\n")
    if arts:
        p.add_run(
            f"Date Range: {arts[-1].get('posted_on','—')}"
            f" → {arts[0].get('posted_on','—')}"
        )

    doc.add_paragraph()

    # ── Articles ──────────────────────────────────────────────────
    doc.add_heading(f"Matching Articles ({data['total_articles']})", level=2)

    for idx, a in enumerate(arts, 1):
        # Article title
        art_h = doc.add_heading(level=3)
        art_h.add_run(f"{idx}. {a.get('title','Untitled')}")

        # Source / date / type
        meta_parts = [a.get("source",""), a.get("posted_on",""), a.get("news_type","")]
        p_m = doc.add_paragraph()
        r_m = p_m.add_run("  ·  ".join(x for x in meta_parts if x))
        r_m.font.size = Pt(9)
        r_m.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

        # URL
        if a.get("url"):
            p_u = doc.add_paragraph()
            r_u = p_u.add_run(a["url"])
            r_u.font.size = Pt(8)
            r_u.font.color.rgb = RGBColor(0x00, 0x78, 0xD4)

        # Intelligence tags
        tags = []
        if a.get("threat_actors"):
            tags.append("TA: " + ", ".join(a["threat_actors"]))
        if a.get("impacted_industries"):
            tags.append("IND: " + ", ".join(a["impacted_industries"]))
        if a.get("mentioned_countries"):
            tags.append("CTY: " + ", ".join(a["mentioned_countries"]))
        if tags:
            p_t = doc.add_paragraph()
            r_t = p_t.add_run(" | ".join(tags))
            r_t.font.size = Pt(9)

        # Analyst note
        note = a.get("analyst_note", {})
        if note and note.get("note"):
            p_n = doc.add_paragraph()
            r_lbl = p_n.add_run("Analyst Note: ")
            r_lbl.bold = True
            r_lbl.font.size = Pt(10)
            p_n.add_run(note["note"]).font.size = Pt(10)

            by_parts = []
            if note.get("analyst"):
                by_parts.append(f"By: {note['analyst']}")
            if note.get("updated_at"):
                by_parts.append(f"Saved: {note['updated_at'][:16].replace('T',' ')}")
            if by_parts:
                p_by = doc.add_paragraph()
                r_by = p_by.add_run("  ".join(by_parts))
                r_by.font.size = Pt(8)
                r_by.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

        doc.add_paragraph()  # spacer between articles

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf.read()


# ─────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python export_pir_docx.py <pir_id> [output.docx]")
        sys.exit(1)

    pir_id      = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else f"PIR_Export_{pir_id}.docx"

    print(f"Fetching PIR {pir_id} …")
    data = fetch_pir_data(pir_id)
    print(f"Found {data['total_articles']} articles, {data['exported_at'][:10]}")

    print("Building document …")
    docx_bytes = build_docx(data)

    with open(output_path, "wb") as f:
        f.write(docx_bytes)
    print(f"Saved: {output_path}")
