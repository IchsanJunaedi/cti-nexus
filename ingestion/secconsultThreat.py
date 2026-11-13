from lxml import html


from datetime import datetime
import requests
import os 
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def function_name():
    page = requests.get('https://sec-consult.com/blog/')
    tree = html.fromstring(page.content)
    link_list = tree.iterlinks()
    
    recent_count = 1
    for i in range(1,7):
        article_url_section_recent = "https://sec-consult.com" + tree.xpath(f"/html/body/div[1]/section/div/section[2]/div/div/div/article[{recent_count}]/div[1]/h3/a/@href")[0]
        article_title_section_recent = tree.xpath(f"/html/body/div[1]/section/div/section[2]/div/div/div/article[{recent_count}]/div[1]/h3/a/span/text()")[0]

        key = str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : article_title_section_recent,
                "url" : article_url_section_recent,
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM SEC CONSULT")
        recent_count += 1

function_name()