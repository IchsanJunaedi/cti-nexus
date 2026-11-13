import requests,yaml,os
from datetime import datetime, timedelta
from modules import dbMongo

offset_dir = "offset"  
offset_file = os.path.join(offset_dir, "APTattack_offset.txt")

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

GITHUB_TOKEN = cfg['github']['token']
REPO_OWNER = "S3N4T0R-0X0"
REPO_NAME = "APT-Attack-Simulation"
BRANCH = 'main'  

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

headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "X-GitHub-Api-Version": "2022-11-28"
}

pull_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits"

pull_response = requests.get(pull_url, headers=headers)

if pull_response.status_code == 200:
    pulls = pull_response.json()
    
    # Limit to the latest 5 commits
    latest_commits = pulls[:5]

    processed_shas = load_sha_offset()

    new_shas = []

    for pr in latest_commits:
        current_sha = pr['sha']
        
        if current_sha in processed_shas:
            print(f"Commit {current_sha} already processed, skipping...")
            continue  # Skip sending the message if it's already processed
        
        print(f"Processing commit #{current_sha}")
        
        commit_url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/{current_sha}"
        
        commit_response = requests.get(commit_url, headers=headers)
        
        if commit_response.status_code == 200:
            commit = commit_response.json()
            
            changed_files = [file['filename'] for file in commit['files']]
            if len(changed_files) == 1 and changed_files[0] == "README.md":
                print(f"Commit {current_sha} only changed root README.md, skipping...")
                continue

            date_str = commit['commit']['author']['date']
            date_obj = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
            
            wib_time = date_obj + timedelta(hours=7)
            formatted_wib_time = wib_time.strftime("%B %d, %Y, %H:%M:%S")
            
            msg_data = f"""
=== <b>APT TTP SIMULATOR GITHUB MONITOR</b> ===
<b>Commit Message</b>: {commit['commit']['message']}
<b>Author</b>: {commit['commit']['author']['name']}
<b>Date</b>: {formatted_wib_time}
<b>Files changed:</b>
"""

            patch_data = ""

            for file in commit['files']:
                msg_data += (
                    f"      Filename: {file['filename']}\n"
                    f"      Status: {file['status']}\n"
                    f"      Additions: {file['additions']}\n"
                    f"      Deletions: {file['deletions']}\n"
                )

                patch = file.get('patch', None)
                if patch:
                    filtered_patch = '\n'.join(
                        line for line in patch.splitlines() if line.startswith('+') or line.startswith('-')
                    )
                    patch_data += f"\n--- PATCH for {file['filename']} ---\n{filtered_patch}\n"
                else:
                    patch_data += f"\n--- PATCH for {file['filename']} ---\nNo patch available\n"

            output_path = "apt_ttp_update.txt"
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(patch_data)

            print(msg_data.strip())
            dbMongo.upsert_alert("github_apt_ttp", current_sha, msg_data.strip(),
                                 source="APT TTP Simulator GitHub", patch=patch_data)

            new_shas.append(current_sha)

        else:
            print(f"Failed to retrieve commit details: {commit_response.status_code}")
    
    all_processed_shas = processed_shas + new_shas
    save_sha_offset(all_processed_shas)

else:
    print(f"Failed to retrieve commits: {pull_response.status_code}")