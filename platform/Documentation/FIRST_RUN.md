# First Run Setup

## Prerequisites

- MongoDB running and reachable
- `.env` configured (see `.env.example` or `app/config.py` for required vars)
- Dependencies installed: `pip install -r requirements.txt`

## Step 1 — Start the App

```bash
python run.py
```

On startup the app automatically seeds:
- Default client tenant (`default`)
- System roles: `superadmin`, `admin`, `analyst`

## Step 2 — Create the First Superadmin

Only works when **zero users exist** in the database.

```bash
curl -X POST https://your-host/api/auth/init \
  -H "Content-Type: application/json" \
  -d '{"username": "superadmin", "password": "YourStrongPass123!"}'
```

Password must satisfy the default policy: min 8 chars, uppercase, lowercase, number, symbol.

> **This endpoint is disabled permanently once any user exists.**

## Step 3 — Log In

Go to `https://your-host/login` and sign in with the credentials from Step 2.

## Step 4 — Create Additional Users (Optional)

In the UI: **User Management tab → Add User**

| Role | What it can do |
|------|---------------|
| `superadmin` | Everything — roles, clients, all admin ops |
| `admin` | User management, policy, audit log, all content |
| `analyst` | Read CTI content, create RFIs/PIRs, export data |
| custom | Whatever permissions you assign via Roles section |

To create a custom role: **User Management → User Roles → + Add Role**  
Only `superadmin` can create/delete roles.

## Role Hierarchy

```
superadmin
  └── all 26 permissions

admin
  └── all except: manage_roles, manage_clients

analyst
  └── view_news, export_data, manage_rfi, manage_pir,
      view_intel, view_ta, view_ioc, view_cve,
      view_newsletter, view_tweets, view_stix, wisemap_access

custom role
  └── whatever you pick
```

## Deploying the Geo-Based Local News Panel

The NewsRoom's "Local News" panel shows articles filtered by each client's assigned countries. Required steps when deploying this feature to production.

### Step 1 — Deploy ScraperNewsRevamp

```bash
git pull   # on the Revamp server
python scripts/seed_global_countries.py
```

This seeds the `global-country` MongoDB collection (~195 countries). Safe to re-run — uses upsert.

### Step 2 — Deploy ScraperNewsWeb

```bash
git pull   # on the Web server
# restart FastAPI (systemctl restart / pm2 restart / etc.)
```

No schema migration needed — MongoDB is schemaless.

### Step 3 — Assign Countries to Existing Clients

Existing client docs have no `countries` field → they show "Global News" (safe fallback). To assign countries, either:

**Via MongoDB shell:**
```js
db.clients.updateOne(
  { client_id: "your_client_id" },
  { $set: { countries: ["Indonesia"] } }
)
```

**Via UI (new clients only):** User Management → Client Tenants → + Add Client → fill COUNTRIES field (comma-separated).

Multiple countries supported: `["Singapore", "Malaysia"]` → panel title "Local News", combined query.

### Step 4 — Re-login Existing Users

Existing browser sessions have no `cti_client_countries` in localStorage. Users must re-login once after deploy to get the correct panel. Until then the panel falls back to "Global News" automatically.

### Panel Title Logic

| `countries` field | Panel title |
|-------------------|-------------|
| `[]` (empty/unset) | Global News |
| `["Indonesia"]` | Indonesia News |
| `["Singapore", "Malaysia"]` | Local News |

---

## MongoDB User Permissions

The app requires `readWrite` **and** `dbAdmin` on `news_db`. `dbAdmin` alone is not enough — it only grants schema/index ops, not collection read/write.

If you see:
```
pymongo.errors.OperationFailure: not authorized on news_db to execute command { find: "clients" ... }
```

Grant `readWrite` to the DB user:

```js
use news_db
db.grantRolesToUser("ti-news", [{ role: "readWrite", db: "news_db" }])
```

Verify:
```js
db.getUser("ti-news")
// roles should include both dbAdmin and readWrite on news_db
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `/api/auth/init` returns 409 | Users already exist — log in with existing superadmin account |
| Login fails after role change | JWT stores old role — re-login to pick up new role |
| Role dropdown shows "Loading roles…" | Check app is running and DB is reachable |
| `OperationFailure: not authorized on news_db` | DB user missing `readWrite` role — see [MongoDB User Permissions](#mongodb-user-permissions) above |
