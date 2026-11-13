import requests, os, yaml
from datetime import datetime, timedelta
from modules import dbMongo
from modules import iocExtractor

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

offset_dir = "offset"          # Directory to store the 'sha' offset file
offset_file = os.path.join(offset_dir, "deepdarkCTI_offset.txt")  # Path to the offset file

if not os.path.exists(offset_dir):
    os.makedirs(offset_dir)

def save_sha_offset(sha_list):
    with open(offset_file, 'w') as f:
        f.write("\n".join(sha_list))

def load_sha_offset():
    if os.path.exists(offset_file):
        with open(offset_file, 'r') as f:
            return [line.strip() for line in f.readlines()]
    return []

OWNER = "fastfire"
REPO = "deepdarkCTI"

_IOC_PATH_PREFIXES = ("c2/", "ioc/", "phishing/", "ransomware/", "tor/", "darkweb/")
_IOC_TYPE_MAP = {
    "ips": "ip",
    "domains": "domain",
    "urls": "url",
    "urls_with_path": "url",
    "sha256": "hash_sha256",
    "sha1": "hash_sha1",
    "md5": "hash_md5",
    "emails": "email",
}


def _ingest_patch_iocs(filename: str, patch: str) -> int:
    """Extract IOCs from patch additions and upsert to news_db. Returns count of new IOCs."""
    category = next((p.rstrip("/") for p in _IOC_PATH_PREFIXES if filename.startswith(p)), None)
    if not category or not patch:
        return 0
    added_lines = [
        line[1:].strip()
        for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    if not added_lines:
        return 0
    iocs = iocExtractor.extract_iocs("\n".join(added_lines))
    tags = [category]
    count = 0
    for field, ioc_type in _IOC_TYPE_MAP.items():
        for value in iocs.get(field, []):
            if dbMongo.upsert_ioc_from_feed(ioc_type, value, source_name="deepdarkCTI", tags=tags):
                count += 1
            if category == "c2":
                feed_type = "ip" if field == "ips" else "domain"
                dbMongo.upsert_threat_feed("deepdarkCTI_c2", feed_type, value)
    return count

headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {cfg['github']['token']}",
    "X-GitHub-Api-Version": "2022-11-28"
}

# GitHub API endpoint for listing commits
pull_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits"

# Send the request to the GitHub API
pull_response = requests.get(pull_url, headers=headers)

# Check if the request was successful
if pull_response.status_code == 200:
    pulls = pull_response.json()
    latest_commits = pulls[:5]

    processed_shas = load_sha_offset()
    new_shas = []

    for pr in latest_commits:
        current_sha = pr['sha']

        if current_sha in processed_shas:
            continue  # Skip sending the message if it's already processed
        
        # GitHub API endpoint for commit details
        commit_url = f"https://api.github.com/repos/{OWNER}/{REPO}/commits/{current_sha}"
        
        commit_response = requests.get(commit_url, headers=headers)
        
        if commit_response.status_code == 200:
            commit = commit_response.json()
            
            # Parse the date string from the API (UTC time)
            date_str = commit['commit']['author']['date']
            date_obj = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
            
            # Convert to WIB (UTC+7)
            wib_time = date_obj + timedelta(hours=7)
            formatted_wib_time = wib_time.strftime("%B %d, %Y, %H:%M:%S")
            
            msg_data = f"""
=== <b>DEEPDARKCTI GITHUB MONITOR</b> ===
<b>Commit Message</b>: {commit['commit']['message']}
<b>Author</b>: {commit['commit']['author']['name']}
<b>Date</b>: {formatted_wib_time}
<b>Files changed:</b>"""
            for file in commit['files']:
                msg_data += f"""
    <b>Filename</b>: {file['filename']}
    <b>Additions</b>: {file['additions']}
    <b>Deletions</b>: {file['deletions']}\n"""

                patch = file.get('patch', None)
                if patch:
                    filtered_patch = ""
                    for line in patch.splitlines():
                        if line.startswith('+') or line.startswith('-'):
                            line = line.replace("||", "|")
                            filtered_patch += line.replace("|", " | ")[:-3] + "\n"

                    filtered_patch = filtered_patch[:-1]
                    msg_data += f"    <b>Patch</b>: \n{filtered_patch}\n"

                    new_ioc_count = _ingest_patch_iocs(file['filename'], patch)
                    if new_ioc_count:
                        msg_data += f"    <b>New IOCs ingested</b>: {new_ioc_count}\n"
                else:
                    msg_data += "    <b>Patch</b>: No patch available\n"

            print(msg_data)
            dbMongo.upsert_alert("deepdarkcti", current_sha, msg_data.strip(), source="deepdarkCTI GitHub")

            new_shas.append(current_sha)

        else:
            print(f"Failed to retrieve commit details: {commit_response.status_code}")
    
    all_processed_shas = processed_shas + new_shas
    save_sha_offset(all_processed_shas)

else:
    print(f"Failed to retrieve commits: {pull_response.status_code}")