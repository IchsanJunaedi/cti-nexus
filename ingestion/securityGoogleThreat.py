from datetime import datetime
import defusedxml.ElementTree as ET
import requests
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36'}

def function_name():
    response = requests.get('https://blog.google/security/rss/', headers=headers)
    if response.status_code != 200:
        print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')
        return

    root = ET.fromstring(response.content)
    for item in root.findall('.//item')[:6]:
        article_title = item.find('title').text
        article_url = item.find('link').text

        key = str(article_title).lstrip() + str(article_url).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : article_title,
                "url" : article_url,
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM SECURITY GOOGLE")

function_name()
