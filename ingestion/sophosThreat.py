import requests, xmltodict
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark

message_list = []
import os
current_file = os.path.basename(__file__).split(".")[0]

rss_feed = requests.get("https://www.sophos.com/en-us/blog/feed?id=blt6f15f4f7deaf4242")
rss_feed = xmltodict.parse(rss_feed.text)

def sophos_feed():
    count = 1
    # driver.implicitly_wait(10)
    for news in rss_feed['rss']['channel']['item']:
        if count == 5:
            break
        
        article_data = {
            "title" : news['title'],
            "url" : news['link'],
            "desc" : news['description'],
            "posted_on" : datetime.now().date()
        }
        message_list.append(article_data)
        count += 1

    for message in message_list:
        key = str(message['title']) + str(message['url'])
        if is_new_and_mark(current_file, key):
            push_job(message, "NEW ARTICLE FROM SOPHOS")
            # nlp_scan(message, "NEW ARTICLE FROM SOPHOS")

sophos_feed()