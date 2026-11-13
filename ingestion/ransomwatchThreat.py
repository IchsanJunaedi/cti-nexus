import requests
from datetime import datetime
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

now_year = datetime.today().year
now_month = datetime.strftime(datetime.today(), "%m")

ransomare_news_req = requests.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json").json()

ransomware_group_req = requests.get("https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json").json()

for news in ransomare_news_req:
    news_date = news['discovered']

    if str(news_date).split("-")[0] == str(now_year) and str(news_date).split("-")[1] == str(now_month):
        key = str(news['group_name']).title() + str(news['post_title']).title() + news_date
        if is_new_and_mark(current_file, key):

            group_site = "<b>Group Link</b>:"
            for group in ransomware_group_req:
                if group['name'] == news['group_name']:
                    count = 1
                    for link in group['locations']:
                        group_site += f'\n    - <a href="{link["slug"]}">Link {str(count)}</a>'
                        count += 1

            message = {
                "title": str(news['post_title']).title(),
                "group_name": str(news['group_name']).title(),
                "group_site": group_site,
                "posted_on": news_date,
            }
            push_job(message, "NEW RANSOMWARE VICTIM FROM RANSOMWATCH")
