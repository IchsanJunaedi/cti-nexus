from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
from lxml import html
import requests, os

current_file = os.path.basename(__file__).split(".")[0]

def function_name():
    page = requests.get('')
    tree = html.fromstring(page.content)

    recent_count = 1
    for i in range(1, 7):
        article_url = tree.xpath(f"/html/body/div[1]/main/section/div/div[2]/div[1]/div[{recent_count}]/div/div/div/div[2]/h5/strong/a/@href")[0]
        article_title = tree.xpath(f"/html/body/div[1]/main/section/div/div[2]/div[1]/div[{recent_count}]/div/div/div/div[2]/h5/strong/a/text()")[0]

        key = str(article_title).lstrip() + str(article_url).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title": article_title,
                "url": article_url,
                "posted_on": datetime.now().date(),
            }, "NEW RECENT ARTICLE FROM NAME")

        recent_count += 1

function_name()
