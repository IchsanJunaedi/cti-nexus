Storage estimate — 3 years

Articles store NO body text — just metadata + LLM fields. Each doc ~3KB.

┌────────────────────┬───────────────────────────┬──────────┐
│       Source       │          Volume           │ Per year │
├────────────────────┼───────────────────────────┼──────────┤
│ Articles           │ ~700/day × 3KB            │ ~770MB   │
├────────────────────┼───────────────────────────┼──────────┤
│ IOCs (after dedup) │ ~1,500 net new/day × 500B │ ~275MB   │
├────────────────────┼───────────────────────────┼──────────┤
│ Tweets             │ ~200/day × 3KB            │ ~220MB   │
├────────────────────┼───────────────────────────┼──────────┤
│ CVE tracker growth │ ~50K new CVEs/yr × 2KB    │ ~100MB   │
├────────────────────┼───────────────────────────┼──────────┤
│ Scraper run logs   │ ~700/day × 200B           │ ~51MB    │
├────────────────────┼───────────────────────────┼──────────┤
│ ATT&CK DB          │ static ~15MB              │ ~15MB    │
├────────────────────┼───────────────────────────┼──────────┤
│ TA profiles/misc   │ slow growth               │ <10MB    │
└────────────────────┴───────────────────────────┴──────────┘

Raw uncompressed/year: ~1.4GB → 3 years: ~4.2GB

MongoDB uses WiredTiger snappy compression by default (~3x ratio on text/JSON). Actual disk:

- Data (compressed): ~1.5GB over 3 years
- Indexes: ~500MB
- MongoDB WiredTiger journal + overhead: ~500MB
- MongoDB total: ~2.5GB

Plus:
- OS + Python env: ~5GB
- Code repos: ~500MB
- Docker (if containerized): ~3GB
- Log files: ~1GB

Total comfortable minimum: ~15GB
Recommended with backups + headroom: ~50GB SSD

If you add VirusTotal/AbuseIPDB enrichment blobs to IOC docs (feature #8 in backlog) those can be 5-20KB each → ~3GB additional over 3 years. Budget 100GB if you plan to enable
enrichment.