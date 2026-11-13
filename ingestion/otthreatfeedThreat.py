from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
from lxml import html
import requests, os

current_file = os.path.basename(__file__).split(".")[0]

# otthreatfeed.com is a Wix shell that embeds this dashboard in an iframe
dashboard_url = 'https://utilsec.github.io/ot-threat-dashboard/'

def otthreatfeed():
    page = requests.get(dashboard_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'})
    tree = html.fromstring(page.content)

    for story in tree.xpath('//*[starts-with(@id, "story-")][@data-published]'):
        article_title = story.xpath('.//h2/text() | .//h3/text()')[0].strip()
        article_url = dashboard_url + "#" + story.get('id')

        key = str(article_title) + str(article_url)
        if is_new_and_mark(current_file, key):
            push_job({
                "title": article_title,
                "url": article_url,
                "posted_on": datetime.now().date(),
            }, "NEW ARTICLE FROM OT THREAT FEED")

otthreatfeed()
