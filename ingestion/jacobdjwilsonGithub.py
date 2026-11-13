# For monitor github of blackobird to get latest update for every threat report he post

import requests, time, yaml
from datetime import datetime
from modules import dbMongo

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']
REPO_OWNER = 'jacobdjwilson'
REPO_NAME = 'awesome-annual-security-reports'
BRANCH = 'main'  

API_URL = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits'

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

response = requests.get(API_URL, headers=headers).json()

latest_commit = response[1]
last_sha = latest_commit['sha']
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

if last_sha in offset_data:
    print("Already in offsets")
    exit()
else:
    commit_detail = requests.get(API_URL + f"/{latest_commit['sha']}").json()

    # print(commit_detail)

    for file_detail in commit_detail['files']:
        if file_detail['status'] == "added":
            file_name = file_detail['filename'].split("/")[2]
            if str(file_name).endswith(".md"):
                continue
            
            file_url = file_detail['raw_url']
            file_posted = commit_detail['commit']['committer']['date']

            msg_data = f"""
        === <b>NEW REPORT UPLOADED ON JACOBDJWILSON GIT</b> ===
<b>Report Name</b>: {file_name}
<b>Posted On</b>: {str(file_posted).replace('T', ' ').replace('Z', '')}
<b>Report URL</b>: <a href="{file_url}">Read Now</a>
"""
            print(msg_data)
            dbMongo.upsert_article({
                "title": file_name,
                "url": file_url,
                "posted_on": datetime.strptime(file_posted, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                "source": "JacobDJWilson GitHub",
                "news_type": "Vendor Report Article",
                "impacted_industries": [],
                "mentioned_countries": [],
                "victim_countries": [],
                "actor_countries": [],
                "threat_actors": [],
                "ttps": [],
            })

        with open('offset/githubsha.txt', 'a') as offset_data_output:
            offset_data_output.write(str(last_sha)+ "\n")