# Monitor GitHub for CVE POC repos.
# Phase 1: broad year-wildcard search (existing behaviour).
# Phase 2: load True Positive CVEs from DB → targeted GitHub search → update DB.
import requests, time, yaml, re
from datetime import datetime, timedelta
from pymongo import MongoClient, UpdateOne
from modules import dbMongo
from modules.techstackStore import get_tech_list

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']

_news_db_uri = (
    f"mongodb://{cfg['news_db']['user']}:{cfg['news_db']['pass']}"
    f"@{cfg['news_db']['ip']}/?authSource={cfg['news_db']['db']}"
)

year_list = [
    str(datetime.now().year),
    str((datetime.now() - timedelta(days=360)).year)
]

whitelist_url = [
    "https://github.com/ThoristKaw/Anydesk-Exploit-CVE-2025-12654-RCE-Builder",
    "https://github.com/Subha-coder-hash/Anydesk-Exploit-CVE-2025-12654-RCE-Builder",
    "https://github.com/Yuweixn/Anydesk-Exploit-CVE-2025-12654-RCE-Builder",
    "https://github.com/Taonauz/Anydesk-Exploit-CVE-2025-12654-RCE-Builder"
]

HEADERS = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}


def _get_latest_sha(owner, repo):
    r = requests.get(
        f'https://api.github.com/repos/{owner}/{repo}/commits',
        headers=HEADERS,
    ).json()
    try:
        return r[0]['sha']
    except (KeyError, IndexError):
        return None


def _cve_info_from_mitre(cve_id):
    """Return (vendor_name, affected_prod) from MITRE API."""
    try:
        cve_data = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id.upper()}").json()
        vendor_name = ""
        affected_prod = ""
        try:
            for affected in cve_data['containers']['cna']['affected']:
                try:
                    vendor_name = affected['vendor']
                    affected_prod += affected['product'] + " || "
                except KeyError:
                    affected_prod += " || "
            affected_prod = affected_prod[:-4]
        except KeyError:
            try:
                for affected in cve_data['containers']['adp']['affected']:
                    vendor_name = affected['vendor']
                    affected_prod += affected['product'] + " || "
                affected_prod = affected_prod[:-4]
            except KeyError:
                vendor_name = "Unknown"
                affected_prod = "Unknown"
        return vendor_name, affected_prod
    except Exception:
        return "Unknown", "Unknown"


# ── PHASE 1: broad search ───────────────────────────────────
print("=== Phase 1: Broad GitHub POC search ===")
for now_year in year_list:
    query_string = f"cve-{now_year}-*"

    counter = 1
    result_list = []
    temp_id_list = []

    while True:
        if counter == 3:
            break
        API_URL = f'https://api.github.com/search/repositories?q={query_string}&sort=updated&order=desc&per_page=50&page={counter}'
        search_request = requests.get(API_URL, headers=HEADERS).json()
        if len(search_request['items']) != 0:
            result_list.extend(search_request['items'])
            counter += 1
        else:
            break

    for result in result_list:
        repo_id = str(result['id'])
        updated_at = result['updated_at']
        created_at = result['created_at']

        if result['fork']:
            continue

        offset_data = []

        try:
            with open("offset/githubpoc.txt", 'r') as indata:
                raw_offset_data = indata.readlines()
        except FileNotFoundError:
            open("offset/githubpoc.txt", 'w+')
            with open("offset/githubpoc.txt", 'r') as indata:
                raw_offset_data = indata.readlines()

        for raw_offset in raw_offset_data:
            temp_id_list.append(raw_offset.strip().split(":")[0])
            offset_data.append(raw_offset.strip())

        owner_name = result['owner']['login']
        repo_name = result['name']
        print(repo_name)
        print(owner_name)
        print("")

        sha_hash = _get_latest_sha(owner_name, repo_name)
        if sha_hash is None:
            continue

        offset_string = f"{repo_id}:{sha_hash}:{created_at}"
        if offset_string in offset_data:
            continue

        repo_lang = result['language']
        repo_desc = result['description']
        repo_url = result['html_url']

        if repo_id in temp_id_list:
            timestamp_update = (datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=7)).strftime("%H:%M:%S %d-%m-%Y")
            msg_data = f"\n        === <b>UPDATED CVE POC ON GITHUB</b> ===\n<b>Updated On</b>: {timestamp_update}"
        else:
            timestamp_create = (datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ") + timedelta(hours=7)).strftime("%H:%M:%S %d-%m-%Y")
            msg_data = f"\n        === <b>NEW CVE POC ON GITHUB</b> ===\n<b>Posted On</b>: {timestamp_create}"

        try:
            cve_id = re.findall("(cve-\d{4}-\d+)", str(repo_name).lower().replace("_", "-"))[0]
            if len(cve_id) == 0:
                cve_id = re.findall("(cve-\d{4}-\d+)", str(repo_desc).lower().replace("_", "-"))[0]
            vendor_name, affected_prod = _cve_info_from_mitre(cve_id)
        except IndexError:
            vendor_name = "Unknown"
            affected_prod = "Unknown"

        send_status = False
        list_of_tech = get_tech_list()
        for tech in list_of_tech:
            tech = tech.lower().strip()
            if (re.search(f"\\b{tech}\\b", str(vendor_name).lower())
                    or re.search(f"\\b{tech}\\b", str(repo_desc).lower())
                    or re.search(f"\\b{tech}\\b", str(affected_prod).lower())):
                send_status = True
                break

        if send_status:
            if repo_url in whitelist_url:
                continue

            msg_data += f"""
<b>Repo</b>:
    <b>Name</b>: {repo_name} POC for {vendor_name}
    <b>Owner</b>: {owner_name}
    <b>Description</b>: {repo_desc}
    <b>Language</b>: {repo_lang}
<b>Affected CVE Product Version</b>: {affected_prod}
<b>Github Link</b>: <a href="{repo_url}">Link</a>"""
            print(msg_data)
            dbMongo.upsert_alert("github_poc", offset_string, msg_data.strip(),
                                 source="GitHub POC Monitor", title=repo_name, url=repo_url)
            with open('offset/githubpoc.txt', 'a') as offset_data_output:
                offset_data_output.write(str(offset_string) + "\n")


# ── PHASE 2: TP CVE → targeted GitHub search → update DB ─────────────────────
print("\n=== Phase 2: True Positive CVE POC check ===")

_client = MongoClient(_news_db_uri)
_db = _client[cfg['news_db']['db']]
_cve_col = _db['cve_tracker']
_fp_col  = _db['cve_false_positives']

fp_ids = {d['cve_id'] for d in _fp_col.find({}, {'cve_id': 1, '_id': 0})}
tp_cves = list(_cve_col.find(
    {'cve_id': {'$nin': list(fp_ids)}},
    {'cve_id': 1, 'pocs': 1, '_id': 0}
))
print(f"Loaded {len(tp_cves)} true positive CVEs from DB")

db_ops = []
now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

for cve_doc in tp_cves:
    cve_id = cve_doc['cve_id']
    existing_poc_urls = {p['url'] for p in cve_doc.get('pocs', [])}

    query_string = f"{cve_id} in:name,description"
    API_URL = f"https://api.github.com/search/repositories?q={query_string}&sort=updated&order=desc&per_page=10&page=1"
    search_resp = requests.get(API_URL, headers=HEADERS).json()
    time.sleep(2)  # respect GitHub rate limit

    items = search_resp.get('items', [])
    new_pocs = []

    for item in items:
        if item.get('fork'):
            continue
        repo_url = item['html_url']
        if repo_url in whitelist_url or repo_url in existing_poc_urls:
            continue

        repo_name_lower = item['name'].lower().replace("_", "-")
        repo_desc_raw   = item.get('description') or ""

        # Confirm the CVE ID actually appears in name or description
        if (cve_id.lower() not in repo_name_lower
                and cve_id.lower() not in repo_desc_raw.lower()):
            continue

        poc_type = "exploit" if re.search(r"\bexploit\b", repo_name_lower + " " + repo_desc_raw.lower()) else "poc"
        new_pocs.append({
            "url":    repo_url,
            "source": item['owner']['login'],
            "type":   poc_type,
        })
        print(f"  [{cve_id}] Found: {repo_url}")

    if new_pocs:
        db_ops.append(UpdateOne(
            {"cve_id": cve_id},
            {
                "$set":  {"poc_available": True, "last_updated": now_str},
                "$push": {"pocs": {"$each": new_pocs}},
            }
        ))

if db_ops:
    _cve_col.bulk_write(db_ops, ordered=False)
    print(f"Updated {len(db_ops)} CVE(s) with POC data.")
else:
    print("No new POCs found for TP CVEs.")

_client.close()
print(datetime.now())
