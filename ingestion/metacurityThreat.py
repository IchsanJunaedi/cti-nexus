import requests, xmltodict
from datetime import datetime
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def metacurity_feed():
    rss_feed = requests.get("https://rss.beehiiv.com/feeds/LcNUEHbD8m.xml")
    rss_feed = xmltodict.parse(rss_feed.text)

    for news in rss_feed['rss']['channel']['item']:
        key = str(news['title']) + str(news['link'])
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : news['title'],
                "url" : news['link'],
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM METACURITY")

metacurity_feed()
