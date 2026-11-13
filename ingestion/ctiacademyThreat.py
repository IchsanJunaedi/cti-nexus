from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
from lxml import html
import requests, os

current_file = os.path.basename(__file__).split(".")[0]

def ctiacademy():
    page = requests.get('https://ctiacademy.io/blog', headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'})
    tree = html.fromstring(page.content)

    for post in tree.xpath('//a[contains(@class, "post")][starts-with(@href, "/blog/")]'):
        article_title = post.xpath('.//h2/text() | .//h3/text()')[0].strip()
        article_url = "https://ctiacademy.io" + post.get('href')

        key = str(article_title) + str(article_url)
        if is_new_and_mark(current_file, key):
            push_job({
                "title": article_title,
                "url": article_url,
                "posted_on": datetime.now().date(),
            }, "NEW ARTICLE FROM CTI ACADEMY")

ctiacademy()
