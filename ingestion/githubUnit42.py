# For monitor github of Palo Alto Unit42 to get latest update for every threat report they post

import requests, time, yaml
from datetime import datetime
from modules import dbMongo

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']
REPO_OWNER = 'PaloAltoNetworks'
REPO_NAME = 'Unit42-timely-threat-intel'
BRANCH = 'main'  

API_URL = f'https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits'

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

response = requests.get(API_URL, headers=headers).json()

for commit in response:
    sha_commit = commit['sha']
    
    commit_date = commit['commit']['committer']['date']
    commit_date = datetime.strptime(commit_date, "%Y-%m-%dT%H:%M:%SZ")
    diff_date = (datetime.now() - commit_date).days

    if diff_date > 5:
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
        exit()
    else:
        commit_detail = requests.get(API_URL + f"/{sha_commit}").json()
        # print(commit_detail)
        if commit_detail['commit']['message'] == "Add files via upload":
            for file_detail in commit_detail['files']:
                try:
                    file_name = file_detail['filename'].split("/")[2]
                except IndexError:
                    file_name = file_detail['filename']
                print(file_name)

                file_url = file_detail['raw_url']
                file_posted = commit_detail['commit']['committer']['date']

                msg_data = f"""
        === <b>NEW REPORT UPLOADED ON UNIT42 GIT</b> ===
<b>Report Name</b>: {file_name}
<b>Posted On</b>: {str(file_posted).replace('T', ' ').replace('Z', '')}
<b>Report URL</b>: <a href="{file_url}">Read Now</a>
"""
            print(msg_data)
            dbMongo.upsert_article({
                "title": file_name,
                "url": file_url,
                "posted_on": datetime.strptime(file_posted, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d"),
                "source": "Unit42 GitHub",
                "news_type": "Vendor Report Article",
                "impacted_industries": [],
                "mentioned_countries": [],
                "victim_countries": [],
                "actor_countries": [],
                "threat_actors": [],
                "ttps": [],
            })

        with open('offset/githubsha.txt', 'a') as offset_data_output:
            offset_data_output.write(str(sha_commit)+ "\n")