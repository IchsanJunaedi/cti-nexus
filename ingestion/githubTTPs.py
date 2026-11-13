import requests, yaml, os
from datetime import datetime
import os
from modules import dbMongo

repo_url = 'https://api.github.com/repos/crocodyli/ThreatActors-TTPs'
commits_url = f'{repo_url}/commits'

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']

headers = {
    'Authorization': f'token {GITHUB_TOKEN}'
}

commit_file = 'offset/crocodylyiCommitID.txt.txt'
def get_existing_commit_ids():
    """Read commit IDs from commitID.txt and return as a set."""
    if os.path.exists(commit_file):
        with open(commit_file, 'r') as file:
            return set(line.strip() for line in file.readlines())
    else:
        return set()

def save_commit_id(commit_id):
    """Write the new commit ID to commitID.txt."""
    with open(commit_file, 'a') as file:
        file.write(f"{commit_id}\n")

def get_all_commits():
    """Fetch all commits in the repository and process them."""
    response = requests.get(commits_url + "?per_page=5", headers=headers)

    if response.status_code == 200:
        for commit in response.json():
            commit_id = commit['sha']
            existing_commit_ids = get_existing_commit_ids()
            if commit_id in existing_commit_ids: # Skipping already processed commit {commit_id}
                exit()
            commit_detail = requests.get(commits_url + f"/{commit_id}").json()
            commit_time = commit['commit']['committer']['date']
            commit_time = datetime.fromisoformat(commit_time[:-1])
            
            files = dict(commit_detail).get('files', [])
        
            if files:
                for file in files:
                    file_name = file['filename']
                    status = file['status']
                    status_msg = ""
                    if status == "added":
                        status_msg = "NEW"
                    else:
                        status_msg = "MODIFIED"
                    
                    msg_data = f"""
        === <b>{status_msg} TTP POSTED ON CROCODYLI GITHUB</b> ===
<b>Commit ID On</b>: {str(commit_id)}
<b>Commited On</b>: {str(commit_time)}
<b>Filename</b>: {file_name}
<b>Status</b>: {status}
<b>Github Link</b>: <a href="{file['blob_url']}">Link</a>"""
                    print(msg_data)
                    dbMongo.upsert_alert("github_ttp", f"{commit_id}:{file_name}", msg_data.strip(),
                                         source="Crocodyli GitHub", title=file_name, url=file['blob_url'])
            else:
                continue
            save_commit_id(commit_id)
    else:
        print(f"Failed to fetch commits. Status Code: {response.status_code}")
        print(f"Error Message: {response.text}")

get_all_commits()
