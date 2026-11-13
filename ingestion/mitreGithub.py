# For monitor github of MITRE ATTCK to get latest update for every ATTCK version they released

import requests, time, yaml, re, os
from datetime import datetime
from modules.mitreValidator import mitreJsonURL, mitreUpdateLog
from requests.exceptions import JSONDecodeError
from modules import dbMongo

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']
REPO_OWNER = 'mitre-attack'
REPO_NAME = 'attack-stix-data'
BRANCH = 'main'  

API_URL = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits'
RATE_LIMIT_URL = f'https://api.github.com/rate_limit'
headers = {
    'Authorization': f'Bearer {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
}

response = requests.get(API_URL, headers=headers).json()

for commit in response[0:4]:
    sha_commit = commit['sha']
    
    commit_date = commit['commit']['committer']['date']
    commit_date = datetime.strptime(commit_date, "%Y-%m-%dT%H:%M:%SZ")
    diff_date = (datetime.now() - commit_date).days

    if diff_date >= 7:
        print("skipped commit because more than 5 days")
        continue

    offset_data = []

    try:
        with open("offset/githubsha.txt", 'r') as indata:
            raw_offset_data = indata.readlines()
    except FileNotFoundError:
        open("offset/githubsha.txt", 'w+')
        with open("offset/githubsha.txt", 'r') as indata:
            raw_offset_data = indata.readlines()

    for raw_offset in raw_offset_data:
        offset_data.append(raw_offset.strip())

    if sha_commit in offset_data:
        print("Already in offsets")
        continue
    else:
        if re.fullmatch("^update with att&ck v\d+\.\d+$", str(commit['commit']['message']).lower()):
            try:
                commit_detail = requests.get(API_URL + f"/{sha_commit}", headers=headers).json()
                for file_detail in commit_detail['files']:
                    file_status = file_detail['status']
                    file_url = file_detail['raw_url']
                    file_posted = commit_detail['commit']['committer']['date']

                    if re.fullmatch(".+-\d+\.\d+\.json$", file_detail['filename']) and file_status == "added":
                        file_name = file_detail['filename'].split("/")[1]
                        try:
                            mitre_version = re.findall(".+-(\d+\.\d+)\.json$", file_name)[0]
                        except IndexError:
                            mitre_version = "Error!"

                        raw_data = mitreJsonURL(file_url)

                        filename = f"Mitre_ATTCK_{mitre_version}_Changelog.txt"
                        change_log = mitreUpdateLog(raw_data, filename)

                        msg_data = f"""
        === <b>NEW VERSION OF MITRE ATT&CK UPLOADED ON GIT</b> ===
<b>Report Name</b>: {file_name}
<b>Posted On</b>: {str(file_posted).replace('T', ' ').replace('Z', '')}
<b>Raw File URL</b>: <a href="{file_url}">Read Now</a>
{change_log}"""
                        print(msg_data)
                        dbMongo.upsert_alert("mitre_attck_update", file_name, msg_data.strip(),
                                             source="MITRE ATT&CK GitHub", title=file_name, url=file_url)
                        os.remove(filename)
                
                        with open('offset/githubsha.txt', 'a') as offset_data_output:
                            offset_data_output.write(str(sha_commit)+ "\n")
            except JSONDecodeError:
                continue

