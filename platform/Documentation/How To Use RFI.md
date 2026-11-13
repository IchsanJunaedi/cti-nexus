# How To Use the RFI Tracker

**RFI = Request for Intelligence** — a formal mechanism for consumers (SOC, management, compliance, hunt teams) to ask the CTI function a specific intelligence question, and for analysts to track, respond, and close the loop.

---

## Where to Find It

**Intelligence tab → RFI** (tab after PIR in the submenu)

You must be signed in. Unauthenticated users see a "Sign in to view RFIs" message.

---

## RFI Lifecycle

```
Consumer asks question
        ↓
Analyst logs it as RFI  →  Status: OPEN  (yellow)
        ↓
Analyst starts working  →  Status: IN PROGRESS  (blue)
        ↓
Analyst writes response →  Status: CLOSED  (dim)
        ↓
Consumer receives answer. Loop closed. Record kept.
```

---

## Creating an RFI

1. Click **+ NEW RFI**
2. Fill in the fields:

| Field | Required | Description |
|-------|----------|-------------|
| **Requester** | Yes | Who asked — person, team, or system (e.g. `SOC L2`, `ciso@org`) |
| **Question** | Yes | The exact intelligence question being asked |
| **Due Date** | No | When the answer is needed (`YYYY-MM-DD`) |
| **Status** | Yes | Start with `Open` |
| **Linked PIR** | No | Tie to an existing PIR if the question maps to one |
| **Response** | No | Leave blank at creation; fill when answering |

3. Click **SAVE RFI**

---

## Updating an RFI

Click **Edit** on any card.

- Change **Status** to `In Progress` when you start working on it
- Paste the **Response** when you have an answer
- Set **Status** to `Closed` to mark it done
- Add or update **Linked PIR** if you created a PIR to cover this topic

---

## Status Reference

| Badge | Color | Meaning |
|-------|-------|---------|
| OPEN | Yellow | Received, not yet started |
| IN PROGRESS | Blue | Analyst actively working |
| CLOSED | Dim | Response delivered, loop closed |

Use the filter chips at the top (**All / Open / In Progress / Closed**) to focus on specific states. The count badge on the RFI tab shows total RFIs for the current filter.

---

## Linking to a PIR

If an RFI maps to an existing Priority Intelligence Requirement:

1. Edit the RFI → **Linked PIR** dropdown → select PIR
2. The card shows the linked PIR ID

**Why link?** Traceability — the PIR shows ongoing coverage, the RFI shows the specific question and answer. Audit trail connects consumer request → platform monitoring → analyst response.

If the RFI reveals a topic with **no PIR**, create one:

1. Go to PIR tab → create PIR covering the topic
2. Return to RFI → link it → close RFI with response pointing to PIR

This converts a one-time request into sustained intelligence coverage.

---

## Deleting an RFI

Click **Del** on the card → confirm in the dialog.

> **Note:** Deletion is permanent and cannot be undone. Prefer closing (status = Closed) over deleting — closed RFIs preserve the audit trail.

---

## Use Cases

### 1. Incident Response Intel Support
SOC detects anomaly → opens RFI: *"Is this C2 pattern linked to a known actor?"* → analyst checks TA profiles, responds with actor name + STIX export link → closed. Creates paper trail for incident report.

### 2. Executive Briefing Prep
CISO asks *"What is our ransomware exposure this quarter?"* before a board meeting → RFI filed with due date = meeting day → analyst queries platform, links to ransomware PIR → response = concise paragraph → exec gets answer, analyst has record of what was communicated.

### 3. Threat Hunt Scoping
Hunt team needs *"All known Lazarus TTPs targeting finance sector 2024–2025"* → RFI filed → analyst exports STIX bundle + pulls PIR coverage → response includes technique list → hunt team uses as hypothesis indicators. Linked PIR shows ongoing coverage after hunt concludes.

### 4. Compliance / Audit Evidence
Auditor asks *"Do you have intelligence on vulnerabilities affecting your tech stack?"* → RFI logged (required for audit trail) → analyst points to CVE Tracker + Tech Stack entries → closed with documented response. Audit has proof the intel function operates and responded.

### 5. Backlog Visibility
Multiple consumers asking different questions simultaneously. Open RFI tab shows all open and in-progress items. No question gets lost in email. Analyst can prioritize by due date and see what is overdue.

### 6. Coverage Gap Discovery
RFI arrives for a topic with no PIR. Analyst creates PIR to address it, links RFI to PIR, closes RFI with response. Future requests on the same topic resolve faster because the PIR is already running. One-time request → sustained coverage.

---

## API Reference (for integrations)

All endpoints require authentication (`Authorization: Bearer <token>`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/rfi` | List RFIs (`?status=open\|in_progress\|closed`, `?page`, `?page_size`) |
| `GET` | `/api/rfi/{id}` | Get single RFI |
| `POST` | `/api/rfi` | Create RFI |
| `PUT` | `/api/rfi/{id}` | Update RFI (partial) |
| `DELETE` | `/api/rfi/{id}` | Delete RFI |

All write operations are recorded in the platform audit log.
