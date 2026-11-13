from datetime import datetime
from lxml import html
import requests, os
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark

current_file = os.path.basename(__file__).split(".")[0]
message_list = []

page = requests.get('https://www.cyfirma.com/research/')
tree = html.fromstring(page.content)
link_list = tree.iterlinks()

def cyfirma_feed():
    for i in range(1,7):
        article_url_section_recent = tree.xpath(f"/html/body/div[2]/div[1]/section[3]/div/div/div[1]/div[{i}]/div[2]/h6/a/@href")[0]
        article_title_section_recent = tree.xpath(f"/html/body/div[2]/div[1]/section[3]/div/div/div[1]/div[{i}]/div[2]/h6/a/text()")[0]

        section_2_json_data = {
            "title" : article_title_section_recent,
            "url" : article_url_section_recent,
            "posted_on" : datetime.now().date()
        }
        message_list.append(section_2_json_data)

    for message in message_list:
        key = str(message['title']) + str(message['url'])
        if is_new_and_mark(current_file, key):
            push_job(message, "NEW ARTICLE FROM CYFIRMA")

cyfirma_feed()