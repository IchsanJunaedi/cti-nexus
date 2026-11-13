#!/usr/bin/env bash
# export_db.sh — Dump all MongoDB databases for ScraperNewsWeb + ScraperNewsRevamp
# Creates timestamped dump directory. Restore with: mongorestore --dir <dump_dir>
#
# Usage:
#   bash scripts/export_db.sh
#   bash scripts/export_db.sh --out /path/to/output

set -euo pipefail

HOST="10.8.20.78"
PORT="27017"
OUT_DIR="${1:-./db_export_$(date +%Y%m%d_%H%M%S)}"

# ── Databases ──────────────────────────────────────────────
NEWS_USER="ti-news"
NEWS_PASS="ElbiRxywfCcolEI"
NEWS_DB="news_db"

TA_USER="ti-api"
TA_PASS="ElbiRxywfCcolEI"
TA_DB="threatintel"

mkdir -p "$OUT_DIR"
echo "Output directory: $OUT_DIR"
echo ""

# ── news_db ────────────────────────────────────────────────
echo "[1/2] Dumping $NEWS_DB ..."
mongodump \
  --host "$HOST" --port "$PORT" \
  --username "$NEWS_USER" --password "$NEWS_PASS" \
  --authenticationDatabase "$NEWS_DB" \
  --db "$NEWS_DB" \
  --out "$OUT_DIR" \
  --gzip
echo "    ✓ $NEWS_DB done"

# ── threatintel ────────────────────────────────────────────
echo "[2/2] Dumping $TA_DB ..."
mongodump \
  --host "$HOST" --port "$PORT" \
  --username "$TA_USER" --password "$TA_PASS" \
  --authenticationDatabase "$TA_DB" \
  --db "$TA_DB" \
  --out "$OUT_DIR" \
  --gzip
echo "    ✓ $TA_DB done"

echo ""
echo "Export complete: $OUT_DIR"
echo ""
echo "To restore on new host:"
echo "  mongorestore --host <NEW_HOST> --port 27017 \\"
echo "    --username <USER> --password <PASS> \\"
echo "    --authenticationDatabase admin \\"
echo "    --gzip --dir $OUT_DIR"
