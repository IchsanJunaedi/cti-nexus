# How This Application Addresses Cybersecurity Compliance Frameworks

This document maps the CTI platform (ScraperNewsRevamp + ScraperNewsWeb) to major cybersecurity compliance frameworks and standards. The platform is a Cyber Threat Intelligence (CTI) system that collects, enriches, and disseminates threat intelligence for an organization's security operations.

---

## 1. ISO 27001 / ISO 27002:2022 — Information Security Management System

ISO 27001 provides the framework for establishing and maintaining an ISMS. ISO 27002 provides the implementation controls.

| Control | Clause | How the Platform Satisfies It |
|---|---|---|
| Threat intelligence | A.5.7 | Core platform purpose — 60+ source scrapers, LLM-based enrichment, PIR/RFI intelligence lifecycle |
| Access control | A.5.15 | RBAC with `admin` and `analyst` roles enforced via FastAPI dependency injection |
| Privileged access rights | A.8.2 | `require_admin` dependency guard on all destructive/administrative endpoints |
| Secure authentication | A.8.5 | bcrypt password hashing, JWT Bearer tokens, OIDC/SSO integration, forced password change flag |
| Logging | A.8.15 | `audit_service.py` logs every mutating action with user, action type, target ID, IP address, and UTC timestamp |
| Monitoring | A.8.16 | PIR alert loop, CVE enrichment loop, scraper health endpoint, Graylog SIEM integration |
| Configuration management | A.8.9 | All secrets and config loaded from environment variables via `config.py`; no hardcoded production values |
| Web filtering / content classification | A.8.23 | LLM-based `articleValidator` classifies article relevance, incident confirmation, industry impact, and geopolitical context |
| Information classification | A.5.12 | TLP marking field on threat actor profiles; confidence scoring on articles and TA assessments |

**ISO 27000 (vocabulary and concepts):** The platform natively implements the intelligence lifecycle described in ISO 27001 Annex A.5.7 — *Direction → Collection → Processing → Analysis → Dissemination* — as distinct, automated pipeline stages.

---

## 2. NIST Cybersecurity Framework (CSF) 2.0

The NIST CSF 2.0 organizes security activities into six functions.

### GOVERN
- Audit log (`audit_service.py`) provides accountability for all privileged actions
- Source reliability scoring (`source_score_service.py`) enforces intelligence quality governance
- LLM confidence scores on articles and analyst confidence on threat actor profiles provide measurable quality indicators
- Policy service (`policy_service.py`) enforces password complexity requirements

### IDENTIFY
- **Threat actor inventory:** Dedicated threat actor database with profiles, aliases, TTPs, malware, and IOCs
- **Vulnerability tracking:** CVE tracker with CISA KEV enrichment and Exploit-DB cross-reference
- **Asset visibility:** Technology stack tracking (`techstackStore.py`) maps organizational technology to known vulnerabilities
- **Ransomware monitoring:** RansomwareLive integration tracks active ransomware campaigns by sector and geography
- **MITRE ATT&CK heatmap:** Visualizes frequency of observed techniques across the threat landscape

### PROTECT
- HTTPS enforced (TLS certificates, `https_only=True` on session cookie)
- JWT Bearer authentication on all protected endpoints
- Role-based access control (analyst / admin)
- OIDC/SSO integration for enterprise identity provider support
- bcrypt password hashing (work factor via library default)
- Forced password change on next login capability
- Audit log covers all write operations

### DETECT
- **60+ threat intelligence sources** scraped and enriched continuously (ScraperNewsRevamp)
- **CISA KEV enrichment loop** runs every 3 hours — flags CVEs with confirmed active exploitation
- **Exploit-DB cross-reference** identifies CVEs with public exploit code
- **PIR matching loop** — checks new articles against active Priority Intelligence Requirements every 1–15 minutes
- **Zero-day and data breach classifiers** in `nlp.py` — trigger elevated alerts on keyword pattern match
- **LLM article classifier** (`articleValidator.py`) — `confirmed_incident` field with indicator list (named_victim, ransomware_deployment, data_exfiltration, service_disruption, etc.)
- **Scraper health router** — exposes operational status of all collection agents

### RESPOND
- **Priority Intelligence Requirements (PIR):** Formal intelligence collection requirements with P1 (critical, 5-min alert) and P2 (configurable interval) priority tiers
- **Telegram alerting:** Real-time notifications on PIR matches, zero-day disclosures, data breaches, OT incidents
- **CVE email automation:** Automatic stakeholder notification via Microsoft Graph API or SMTP when high-impact CVEs are identified in tracked technology stack
- **RFI (Request for Intelligence) workflow:** Structured mechanism for ad-hoc intelligence requests
- **PIR export:** DOCX export of PIR findings for incident documentation and stakeholder reporting
- **MITRE TTP extraction:** Every article is enriched with MITRE ATT&CK technique IDs, names, and supporting evidence — feeds directly into incident response context

### RECOVER
- Scraper health endpoint enables rapid identification of collection failures
- PIR notes (`pir_service.py`) support analyst annotation of intelligence findings for post-incident review
- Audit log supports forensic review of analyst actions during and after incidents

---

## 3. NIST SP 800-61r3 — Incident Response

| IR Phase | Platform Capability |
|---|---|
| **Preparation** | PIR/RFI framework defines intelligence requirements before incidents occur; techstack tracking pre-maps organizational exposure |
| **Detection & Analysis** | LLM classifier extracts `confirmed_incident`, `incident_indicators`, and `victim_name` from article titles at ingest; MITRE TTP extraction links events to attack techniques |
| **Containment** | CVE email notifications trigger stakeholder response; Telegram P1 alert fires within 5 minutes of a PIR match |
| **Eradication / Recovery** | PIR docx export packages intelligence for operational response teams |
| **Post-Incident** | Audit log provides accountability trail; PIR notes capture analyst assessments for lessons-learned |

---

## 4. NIST SP 800-150 — Guide to Cyber Threat Intelligence Sharing

| Requirement | Implementation |
|---|---|
| Intelligence requirements management | PIR framework — formally defined priorities with owner, criteria (threat actors, industries, countries, TTPs, keywords), and status lifecycle |
| Source evaluation | Source reliability scoring using an Admiralty Code-inspired model (source credibility + information reliability) |
| Standardized sharing format | STIX 2.1 export for threat actors, IOCs, attack patterns, malware, PIRs, and articles |
| TLP classification | TLP marking on threat actor profiles (`x_tlp` field in STIX objects) |
| Confidence communication | Numeric confidence scores on articles and threat actor assessments; mapped to STIX confidence scale |

---

## 5. MITRE ATT&CK Framework

The platform provides direct, code-level implementation of ATT&CK integration:

- **TTP extraction at ingest:** `mitreValidator.py`, `ttpValidator.py`, and `extractTTPs()` use LLM to extract technique ID, name, and supporting evidence from every article
- **ATT&CK data sync:** `attack_sync_service.py` performs weekly auto-sync of ATT&CK STIX data across all domains (Enterprise, Mobile, ICS)
- **Heatmap visualization:** `mitre_heatmap_service.py` generates frequency heatmaps of techniques observed across the collected threat intelligence corpus
- **Threat actor profiles:** Each threat actor stores attack techniques organized by tactic (Initial Access, Execution, Persistence, etc.)
- **STIX export:** ATT&CK techniques exported as `attack-pattern` objects with `external_references` linking to `attack.mitre.org`

---

## 6. STIX 2.1 / TAXII (OASIS CTI Technical Committee)

`stix_service.py` produces valid STIX 2.1 bundles covering the full object model:

| STIX Object Type | Source in Platform |
|---|---|
| `identity` | Platform identity (deterministic UUID, represents producing organization) |
| `threat-actor` | Threat actor profile database |
| `attack-pattern` | Article TTPs and threat actor capability assessments |
| `malware` | Threat actor known malware list |
| `indicator` | IOC database (IP, domain, URL, SHA-256, SHA-1, MD5, email, CVE) |
| `report` | Individual threat intelligence articles |
| `course-of-action` | Active Priority Intelligence Requirements |
| `relationship` | `uses`, `indicates`, `derived-from` links between objects |

IOC types map to standardized STIX patterns (e.g., `[ipv4-addr:value = '...']`). Defanged indicators are automatically normalized on export.

---

## 7. ISO 27035 — Information Security Incident Management

| Incident Management Stage | Platform Support |
|---|---|
| **Plan and Prepare** | PIR framework defines what incidents matter and at what priority before they occur |
| **Detect and Report** | Automated article classification assigns incident type (zero-day, data breach, OT, ransomware, vendor report) at ingest |
| **Assess and Decide** | LLM-extracted `confirmed_incident` flag, `incident_confidence` score, and `incident_indicators` list support analyst triage |
| **Respond** | Telegram notification pipeline routes P1 alerts in ≤5 minutes; CVE email automation notifies technical stakeholders |
| **Lessons Learned** | PIR notes and audit log support post-incident documentation |

---

## 8. CIS Controls v8

| CIS Control | Platform Coverage |
|---|---|
| CIS 1 & 2 — Asset inventory | Technology stack tracking maps organization's software and services to threat intelligence |
| CIS 3 — Data protection | Secrets isolated in environment variables; no PII collection by design |
| CIS 5 — Account management | User CRUD with admin-controlled creation, RBAC roles, last sign-in tracking |
| CIS 6 — Access control | JWT auth, OIDC/SSO, `require_admin` guards, bcrypt password hashing |
| CIS 8 — Audit log management | Structured audit log with user, action, IP, timestamp; queryable via admin API |
| CIS 13 — Network monitoring | Graylog SIEM integration; structured log events for every collection run |
| CIS 17 — Incident response | CVE email + PIR alert pipeline; RFI workflow for analyst-driven investigation |

---

## 9. SOC 2 (Trust Service Criteria)

| Criteria | Coverage |
|---|---|
| CC6 — Logical and physical access | JWT, bcrypt, OIDC, RBAC, `require_admin` enforcement, last_sign_in tracking, force-password-change flag |
| CC7 — System operations | Audit log, PIR alert loop, CVE enrichment loop, scraper health monitoring |
| CC2 — Communication and information | Newsletter generation, CVE stakeholder email, Telegram real-time notifications |
| A1 — Availability | Scraper health router exposes collection agent operational status; background task monitoring |

---

## 10. TLP (Traffic Light Protocol)

TLP classification is supported natively on threat actor profiles via the `x_tlp` field, which is included in STIX 2.1 bundle exports. This enables controlled sharing with external parties and partner organizations in accordance with TLP handling requirements.

---

## Intelligence Lifecycle Summary

The combined platform covers the full intelligence lifecycle as defined by NATO, ISO 27001 A.5.7, and NIST SP 800-150:

```
Direction    →  PIR / RFI framework (priority requirements, owner, criteria)
Collection   →  60+ source scrapers (ScraperNewsRevamp), Twitter/X monitoring, CVE feeds, ransomware tracking
Processing   →  NLP pipeline (spaCy NER, LSA summarization), LLM article validation, TTP extraction
Analysis     →  MITRE ATT&CK heatmap, threat actor profiling, IOC cross-reference, source scoring, CVE enrichment
Dissemination → Newsletter, CVE email, Telegram alerts, PIR docx export, STIX 2.1 export
```
