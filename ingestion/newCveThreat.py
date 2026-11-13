from modules.techstackStore import get_tech_list, get_tech_list_by_client
from pymongo import MongoClient, UpdateOne
import time, requests
import re, time, requests, yaml
from lxml import html
from datetime import datetime, timedelta, timezone
import os, sys, json, shutil, subprocess, fcntl

temp_list_of_cve = []
temp_cve_id = []

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

### CVEProject/cvelistV5 feed settings ###
# config.yml (optional):
#   cvelist:
#     live: false          # false = dry-run beside old NVD/Tenable feeds, true = cvelistV5 replaces them
#     path: /opt/cvelistV5 # local clone location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CVELIST_CFG = cfg.get('cvelist') or {}
CVELIST_URL = "https://github.com/CVEProject/cvelistV5.git"
CVELIST_DIR = CVELIST_CFG.get('path') or os.path.join(SCRIPT_DIR, "data", "cvelistV5")
CVELIST_LIVE = bool(CVELIST_CFG.get('live', False))
CVELIST_WINDOW_DAYS = 8      # first run / lost-hash fallback window (same as old feeds)
CVELIST_CLONE_DAYS = 10      # shallow history kept locally, must be > window
CVELIST_MIN_WEAK_LEN = 4     # tech names shorter than this must match vendor/product, not free text
_CVE_FILE_RE = re.compile(r"^cves/\d{4}/[^/]+/CVE-\d+-\d+\.json$")

# Prevent overlapping cron runs (git clone + hash state must not race)
_lock_file = open(os.path.join(SCRIPT_DIR, ".newCveThreat.lock"), "w")
try:
    fcntl.flock(_lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("Another newCveThreat run is active, exiting")
    sys.exit(0)

# Pre-load existing CVE records from MongoDB — used for dedup instead of offset.txt
_news_db_uri = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)
_init_client = MongoClient(_news_db_uri)
_cve_tracker_col = _init_client[cfg['news_db']['db']]['cve_tracker']
# { cve_id: cve_modified_date } — used for global dedup/change-detect
_existing_cves = {
    doc['cve_id']: doc.get('cve_modified_date', '')
    for doc in _cve_tracker_col.find({}, {'cve_id': 1, 'cve_modified_date': 1, '_id': 0})
}
_init_client.close()
print(f"Loaded {len(_existing_cves)} existing CVEs from DB")

# Build per-client tech map for scoped CVE writes
# _tech_by_client = { client_id: [tech_names] }
# _tech_to_clients = { normalized_tech: [client_ids] }  (reverse map for DB write)
_tech_by_client = get_tech_list_by_client()
_tech_to_clients: dict[str, list[str]] = {}
for _cid, _techs in _tech_by_client.items():
    for _t in _techs:
        _key = str(_t).replace(" ", "%20").strip().lstrip()  # matches how nvd_feed encodes tech
        _tech_to_clients.setdefault(_key, [])
        if _cid not in _tech_to_clients[_key]:
            _tech_to_clients[_key].append(_cid)
        # also index un-encoded form
        _tech_to_clients.setdefault(_t.strip(), [])
        if _cid not in _tech_to_clients[_t.strip()]:
            _tech_to_clients[_t.strip()].append(_cid)
print(f"Loaded tech→client map: {len(_tech_by_client)} client(s)")

print(datetime.now())
now_date_raw = datetime.now()
# one_hour_date_raw = (datetime.now() - timedelta(hours=3))
one_hour_date_raw = (datetime.now() - timedelta(days=8))

list_of_tech = get_tech_list()

# list_of_tech = ['zabbix']

def nvd_feed():
    print("NVD Database")
    for tech in list_of_tech:
        tech = str(tech).replace(" ", "%20").strip().lstrip()
        print(f"Tech stack: {tech}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
        }

        now_date = now_date_raw.strftime("%Y-%m-%dT%H:%M:%S.000")
        one_hour_date = one_hour_date_raw.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={tech}&pubStartDate={one_hour_date}%2B07:00&pubEndDate={now_date}%2B07:00"
        # print(cve_url)

        cve_list = requests.get(cve_url, headers=headers)
        # print(cve_list.text)

        if len(cve_list.json()['vulnerabilities']) == 0:
            time.sleep(10)
            continue

        for cve in cve_list.json()['vulnerabilities']:
            cve_id = cve['cve']['id']

            if cve_id in temp_cve_id:
                continue

            cve_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            
            cve_sum_list = cve['cve']['descriptions']
            cve_sum = ""
            for sum in cve_sum_list:
                if sum['lang'] == "en":
                    cve_sum = sum['value']

            cve_data = {
                "tech" : tech,
                "link" : cve_link,
                "id" : cve_id,
                "summary" : cve_sum,
            }
            temp_cve_id.append(cve_id)
            temp_list_of_cve.append(cve_data)
            time.sleep(10)

def tenable_feed():
    print("\nTenable Database")
    for tech in list_of_tech:
        tech = str(tech).replace(" ", "+").strip().lstrip()
        print(f"Tech stack: {tech}")

        now_date = now_date_raw.strftime("%Y-%m-%d")
        one_hour_date = one_hour_date_raw.strftime("%Y-%m-%d")

        cve_url = f"https://www.tenable.com/cve/search?q={tech}+AND+publication_date%3A%28%5B{one_hour_date}+TO+{now_date}%5D%29&sort=newest&page=1"
        # print(cve_url)

        cve_request = requests.get(cve_url)
        # print(cve_request.text)

        tree = html.fromstring(cve_request.content)
        try:
            for i in range(1,7):
                cve_id = tree.xpath(f"/html/body/div/div/div[2]/div/div/div[2]/div/div/div[3]/div/section/div/div/table/tbody/tr[{i}]/td[1]/a/text()")[0]
                cve_link = f"https://www.tenable.com/cve/{cve_id}"

                # same row index as cve_id; a separate counter drifted after a duplicate `continue` and paired the ID with another row's summary
                cve_sum = tree.xpath(f"/html/body/div/div/div[2]/div/div/div[2]/div/div/div[3]/div/section/div/div/table/tbody/tr[{i}]/td[2]/text()")[0]
                if re.search(f'\\b{tech.replace("+", " ")}\\b', cve_sum.lower()): # This is needed because some result from tenable is not correct, so we need to validate if the tech stack found in the cve summary or not
                    if cve_id in temp_cve_id:
                        continue
                    
                    cve_data = {
                        "tech" : tech,
                        "link" : cve_link,
                        "id" : cve_id,
                        "summary" : cve_sum
                    }
                    
                    temp_cve_id.append(cve_id)
                    temp_list_of_cve.append(cve_data)
        except IndexError:
            pass
            time.sleep(10)

### CVEProject/cvelistV5 (git) ###
def _git(*args, cwd=CVELIST_DIR):
    return subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, timeout=900
    ).stdout.strip()

def _cvelist_clone():
    # only ever delete a directory that is already a git clone
    if os.path.isdir(os.path.join(CVELIST_DIR, ".git")):
        shutil.rmtree(CVELIST_DIR)
    os.makedirs(os.path.dirname(CVELIST_DIR), exist_ok=True)
    _git("clone", "--quiet", "--single-branch", "--branch", "main",
         f"--shallow-since={CVELIST_CLONE_DAYS} days ago", CVELIST_URL, CVELIST_DIR, cwd=None)

def cvelist_sync():
    """Bring local clone to origin/main, return HEAD hash. Re-clones if repo is broken."""
    if not os.path.isdir(os.path.join(CVELIST_DIR, ".git")):
        _cvelist_clone()
    else:
        try:
            _git("fetch", "--quiet", f"--shallow-since={CVELIST_CLONE_DAYS} days ago", "origin", "main")
            _git("reset", "--quiet", "--hard", "FETCH_HEAD")
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print(f"git sync failed ({e}), re-cloning")
            _cvelist_clone()
    return _git("rev-parse", "HEAD")

def cvelist_changed_paths(last_hash, new_hash):
    """Added/modified CVE json paths between last_hash and new_hash (date window if no usable last_hash)."""
    if last_hash and last_hash == new_hash:
        return []
    paths = None
    if last_hash:
        try:
            _git("cat-file", "-e", f"{last_hash}^{{commit}}")
            paths = _git("diff", "--name-only", "--diff-filter=AM", last_hash, new_hash, "--", "cves").splitlines()
        except subprocess.CalledProcessError:
            print("last_hash not found in local repo, falling back to date window")
    if paths is None:
        paths = _git("log", f"--since={CVELIST_WINDOW_DAYS} days ago", "--name-only",
                     "--diff-filter=AM", "--pretty=format:", "--", "cves").splitlines()
    return sorted({p for p in paths if _CVE_FILE_RE.match(p)})

def _feed_state(key, value=None):
    """Read (value=None) or write a value in Mongo cve_feed_state/cvelistV5."""
    client = MongoClient(_news_db_uri)
    try:
        col = client[cfg['news_db']['db']]['cve_feed_state']
        if value is None:
            return (col.find_one({"_id": "cvelistV5"}) or {}).get(key)
        col.update_one(
            {"_id": "cvelistV5"},
            {"$set": {key: value, f"{key}_at": datetime.now(timezone.utc).isoformat()}},
            upsert=True,
        )
    finally:
        client.close()

def _build_tech_matchers():
    matchers = {}
    for t in list_of_tech:
        name = str(t).replace("%20", " ").replace("+", " ").strip()
        if not name or name in matchers:
            continue
        pattern = r"[\s_\-]+".join(re.escape(p) for p in name.split())
        matchers[name] = re.compile(rf"(?<![A-Za-z0-9]){pattern}(?![A-Za-z0-9])", re.I)
    return matchers

def _cve_texts(record):
    """(strong, weak, summary): strong = vendor/product fields, weak = title + description."""
    containers = record.get('containers', {})
    cna = containers.get('cna', {})
    strong = []
    for c in [cna] + containers.get('adp', []):
        for a in c.get('affected', []):
            strong += [str(a.get(k, '')) for k in ('vendor', 'product', 'packageName')]
    summary = ""
    for d in cna.get('descriptions', []):
        if str(d.get('lang', '')).startswith('en'):
            summary = d.get('value', '')
            break
    weak = " ".join(filter(None, [cna.get('title', ''), summary]))
    return " | ".join(strong), weak, summary

def cvelist_feed(use_state):
    """Return ([candidate, ...], new_hash). One candidate per (CVE, matched tech)."""
    new_hash = cvelist_sync()
    last_hash = _feed_state('last_hash') if use_state else None
    paths = cvelist_changed_paths(last_hash, new_hash)
    print(f"cvelistV5: {len(paths)} changed CVE file(s) ({(last_hash or 'window')[:8]} -> {new_hash[:8]})")

    matchers = _build_tech_matchers()
    found = []
    for rel in paths:
        try:
            with open(os.path.join(CVELIST_DIR, rel), encoding="utf-8") as f:
                record = json.load(f)
            meta = record.get('cveMetadata', {})
            if meta.get('state') != 'PUBLISHED':
                continue
            cve_id = meta['cveId']
            strong, weak, summary = _cve_texts(record)
            for name, rx in matchers.items():
                if rx.search(strong) or (len(name) >= CVELIST_MIN_WEAK_LEN and rx.search(weak)):
                    found.append({
                        "tech": name,
                        "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        "id": cve_id,
                        "summary": summary,
                        "record": record,  # already CVE 5.x JSON, no cveawg call needed
                    })
        except (OSError, ValueError, KeyError) as e:
            print(f"Skip {rel}: {e}")
    return found, new_hash

def cvelist_dry_run():
    """Run cvelistV5 matcher over the date window and compare with what NVD/Tenable found. Writes nothing to Mongo."""
    found, _ = cvelist_feed(use_state=False)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CVELIST_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
    # old feeds only see CVEs published in window, so compare like with like
    new_map = {}
    for c in found:
        if c['record'].get('cveMetadata', {}).get('datePublished', '') >= cutoff:
            new_map.setdefault(c['id'], set()).add(c['tech'])
    new_ids, old_ids = set(new_map), set(temp_cve_id)
    print(f"[dry-run] old feeds: {len(old_ids)} | cvelistV5: {len(new_ids)} | both: {len(new_ids & old_ids)}")
    with open(os.path.join(SCRIPT_DIR, "cvelist_dryrun.log"), "a") as log:
        for cid in sorted(new_ids - old_ids):
            log.write(f"{datetime.now()} NEW_ONLY {cid} {sorted(new_map[cid])}\n")
        for cid in sorted(old_ids - new_ids):
            log.write(f"{datetime.now()} OLD_ONLY {cid}\n")
    print("[dry-run] details in cvelist_dryrun.log")

_cvelist_new_hash = None
if CVELIST_LIVE:
    temp_list_of_cve, _cvelist_new_hash = cvelist_feed(use_state=True)
else:
    nvd_feed()
    tenable_feed()
    cvelist_dry_run()

list_of_cve = []
for cve in temp_list_of_cve:
    references_list = []
    affected_list = []
    affected_list_temp = []
    cve_data = cve.get('record') or requests.get(f"https://cveawg.mitre.org/api/cve/{cve['id']}").json()
    
    # print(f"CVE Data: {cve_data}")

    ### Getting every reference with each tags ###
    try:
        for reference in cve_data['containers']['cna']['references']:
            refer_url = reference['url']
            try:
                refer_tag = reference['tags']
            except KeyError:
                refer_tag = ""
            
            reference_data = {
                "url" : refer_url,
                "tags" : refer_tag
            }
            references_list.append(reference_data)
    except KeyError:
        references_list = []
    
    ### Getting Base Score and its vector ###
    # Fresh CVEs often have no score yet: keep them (score 0 / "N/A"), re-alert later via cve_modified_date.
    # CNA metrics first, then ADP (CISA-ADP adds CVSS later); highest score wins.
    base_score = 0
    vector_string = ""
    severity_string = "N/A"
    containers = cve_data.get('containers', {})
    for container in [containers.get('cna', {})] + containers.get('adp', []):
        for cvss in container.get('metrics', []):
            for key, metric in dict(cvss).items():
                if key in ("scenarios", "format") or not isinstance(metric, dict) or 'baseScore' not in metric:
                    continue
                if base_score <= metric['baseScore']:
                    base_score = metric['baseScore']
                    vector_string = metric.get('vectorString', '')
                    severity_string = metric.get('baseSeverity', 'N/A')

    ### Getting the affected version ###
    temp_product = []
    try:
        for affected in cve_data['containers']['cna']['affected']:
            product = affected.get('product') or affected.get('packageName') or affected.get('vendor') or "unknown"
            if product in temp_product:
                continue

            temp_product.append(product)
            for version in affected.get('versions', []):
                if version.get('status') == "affected":
                    if 'lessThan' in version:
                        string = f"< {version['lessThan']}"
                    elif 'lessThanOrEqual' in version:
                        string = f"<= {version['lessThanOrEqual']}"
                    elif 'version' in version:
                        string = f"<= {version['version']}"
                    else:
                        continue
                    affected_list_temp.append(string)
            json_data = {
                product : affected_list_temp
            }
            affected_list.append(json_data)
            affected_list_temp = []
    except Exception as e:
        affected_list = []

    solution_string = ""
    try:
        for solution in cve_data['containers']['cna']['solutions']:
            if solution['lang'] == 'en':
                solution_string += solution['value']
    except KeyError:
        solution_string = "No solution yet"

    cve_meta = cve_data.get('cveMetadata', {})
    cve_modified_date = cve_meta.get('dateUpdated') or cve_meta.get('datePublished', '')

    json_data = {
        "tech" : cve['tech'],
        "link" : cve["link"],
        "id" : cve['id'],
        "summary" : cve['summary'],
        "published" : cve_meta.get('datePublished', ''),
        "reference" : references_list,
        "affected" : affected_list,
        "solutions": solution_string,
        "cve_score" : base_score,
        "cve_severity" : severity_string,
        "cvss_vector" : vector_string,
        "cve_modified_date": cve_modified_date,
    }
    list_of_cve.append(json_data)

print("")

bulk_cve = {}
_updated_ids = set()  # CVEs already tracked whose MITRE modified date changed (flagged in cve_tracker for the UI)
for cve in list_of_cve:
    hyperlink = ""
    affected_version = ""

    if len(cve['summary']) >= 200:
        summary = cve['summary'][:200] + "..."
    else:
        summary = cve['summary']

    for url in cve['reference']:
        categories = ""
        if len(url['tags']) != 0 :
            counter = len(url['tags'])
            for i in range(len(url['tags'])):
                if i+1 == counter:
                    if url['tags'][i] == "x_refsource_CONFIRM":
                        url['tags'][i] = str(url['tags'][i]).replace("x_refsource_CONFIRM", "Patch")
                    elif url['tags'][i] == "x_refsource_MISC":
                        url['tags'][i] = str(url['tags'][i]).replace("x_refsource_MISC", "Advisory/Exploit/Release Notes")

                    categories += str(url['tags'][i])
                else:
                    categories += str(url['tags'][i]) + ", "
        hyperlink += f"\n    - <a href='{url['url']}'>Read Now</a> {categories}"

    for affected in cve['affected']:
        for key in dict(affected).keys():
            if len(affected[key]) == 0:
                continue
            else:
                affected_version += f"\n    {key}:"
                for version in affected[key]:
                    if "<=" in version:
                        version = version.replace("<=", "&lt;%3D")
                    elif "<" in version:
                        version = version.replace("<", "&lt;")
                    affected_version += f"\n        - {str(version)}"
    
    if "<=" in summary:
        summary = summary.replace("<=", "&lt;%3D")
    # elif "<" in affected:
    #     summary = summary.replace("<", "&lt;")
    
    cve_id = cve['id']
    stored_modified = _existing_cves.get(cve_id)  # None if new, str if exists

    # Skip notification if CVE exists and MITRE has not updated it
    if stored_modified is not None and stored_modified == cve.get('cve_modified_date', ''):
        continue

    tech_label = str(cve['tech']).upper().replace("%20", " ").replace("+", " ")
    if stored_modified is None:
        if cve['tech'] not in bulk_cve:
            bulk_cve[cve['tech']] = []
        bulk_cve[cve['tech']].append(cve)
    else:
        if stored_modified:  # '' = old row without a modified date, not a real update
            _updated_ids.add(cve_id)
        msg_data = f"""
<b>Score</b>: {cve['cve_score']} {cve['cve_severity']}
<b>Posted On</b>: {str(cve['published']).split(".")[0].replace("T", " ")}
<b>Summary</b>: {summary}
<b>Affected Version</b> : {affected_version}
<b>Solutions</b> : {cve['solutions']}
<b>References</b>: {hyperlink}
<b>CVE Link</b>: <a href="https://nvd.nist.gov/vuln/detail/{cve_id}">Read Now</a>"""

        print(msg_data)
        print("\n")

    # Update in-memory map so duplicate CVE IDs in this run don't re-alert
    _existing_cves[cve_id] = cve.get('cve_modified_date', '')

# try:
#     cveEmailAutomation(bulk_cve)
# except IndexError:
#     pass

### Persist CVEs to MongoDB per-client for the CVE Tracker web UI ###
if list_of_cve:
    _news_db_uri = (
        f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
        f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
    )
    _mongo_client = MongoClient(_news_db_uri)
    _col = _mongo_client[cfg['news_db']['db']]['cve_tracker']
    # Compound unique index: each (cve_id, client_id) pair is one row.
    # Also ensure no old single-field cve_id unique index survives a restart.
    try:
        _col.drop_index("cve_id_1")
    except Exception:
        pass  # doesn't exist — fine
    _col.create_index([("cve_id", 1), ("client_id", 1)], unique=True, background=True)

    ops = []
    seen_ops = set()  # one CVE can match several techs of same client, avoid duplicate upserts in one bulk
    now_str = datetime.today().strftime("%Y-%m-%d %H:%M:%S")
    for cve in list_of_cve:
        tech_raw  = str(cve['tech']).replace("%20", " ").replace("+", " ").strip()
        tech_enc  = str(cve['tech']).strip()  # may be %20-encoded from nvd_feed
        # Find which clients have this tech
        client_ids = (
            _tech_to_clients.get(tech_enc) or
            _tech_to_clients.get(tech_raw) or
            ['default']
        )
        doc = {
            "tech":              tech_raw,
            "link":              cve['link'],
            "summary":           cve['summary'],
            "published":         cve['published'],
            "reference":         cve['reference'],
            "affected":          cve['affected'],
            "solutions":         cve['solutions'],
            "cve_score":         float(cve['cve_score']) if cve['cve_score'] else 0.0,
            "cve_severity":      cve['cve_severity'],
            "cvss_vector":       cve['cvss_vector'],
            "cve_modified_date": cve.get('cve_modified_date', ''),
            "last_updated":      now_str,
        }
        if cve['id'] in _updated_ids:
            doc["updated_since_detected"] = True
            doc["last_changed_on"] = now_str
        for client_id in client_ids:
            if (cve['id'], client_id) in seen_ops:
                continue
            seen_ops.add((cve['id'], client_id))
            ops.append(UpdateOne(
                {"cve_id": cve['id'], "client_id": client_id},
                {
                    "$set": {**doc, "cve_id": cve['id'], "client_id": client_id},
                    "$setOnInsert": {
                        "poc_available":   False,
                        "pocs":            [],
                        "detected_on":     now_str,
                        "registered_date": now_str,
                    },
                },
                upsert=True,
            ))

    if ops:
        _col.bulk_write(ops, ordered=False)
    _mongo_client.close()
    print(f"Saved {len(ops)} CVE upsert(s) to MongoDB cve_tracker (across {len(list_of_cve)} CVEs).")
##########################################################

# Advance hash ONLY after Mongo write succeeded (any crash above => same range reprocessed, upserts are idempotent)
if CVELIST_LIVE and _cvelist_new_hash:
    _feed_state('last_hash', _cvelist_new_hash)
    print(f"cvelistV5 last_hash -> {_cvelist_new_hash[:8]}")

print(datetime.now())

