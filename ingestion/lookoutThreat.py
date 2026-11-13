from lxml import html
from datetime import datetime
import requests
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def lookout_feed():
    page = requests.get('https://www.lookout.com/threat-intelligence')
    tree = html.fromstring(page.content)
    link_list = tree.iterlinks()
    
    recent_count = 1
    for i in range(1,7):
        article_url_section_recent = "https://www.lookout.com" + tree.xpath(f"/html/body/div[1]/main/section[3]/div/div/div[2]/section/div/div[1]/div[{recent_count}]/div[1]/div/a[1]/@href")[0]
        article_title_section_recent = tree.xpath(f"/html/body/div[1]/main/section[3]/div/div/div[2]/section/div/div[1]/div[{recent_count}]/div[1]/div/a[1]/h4/text()")[0]

        key = str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : article_title_section_recent,
                "url" : article_url_section_recent,
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM LOOKOUT")
        recent_count += 1

lookout_feed()