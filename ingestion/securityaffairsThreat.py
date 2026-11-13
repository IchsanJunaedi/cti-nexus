from lxml import html
from datetime import datetime
import requests
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def function_name():
    page = requests.get('https://securityaffairs.com/')
    tree = html.fromstring(page.content)
    link_list = tree.iterlinks()

    recent_count = 1
    for i in range(1,4):
        article_url_section_recent = tree.xpath(f"/html/body/div[2]/div/div/div[1]/div[2]/div[{i}]/div[2]/h5/a/@href")[0]
        article_title_section_recent = tree.xpath(f"/html/body/div[2]/div/div/div[1]/div[2]/div[{i}]/div[2]/h5/a/text()")[0]

        key = str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : article_title_section_recent,
                "url" : article_url_section_recent,
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM SECURITY AFFARIS")
        recent_count += 1

function_name()
