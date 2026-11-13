import defusedxml.ElementTree as ET
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import requests, os, re
import html as html_lib

current_file = os.path.basename(__file__).split(".")[0]

url = 'https://www.detectionengineering.net/feed'
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    raw = html_lib.unescape(response.content.decode("utf-8", errors='ignore'))
    fixed = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)', '&amp;', raw)
    root = ET.fromstring(fixed)

    for item in root.findall('.//item'):
        featured_title = item.find('title').text
        featured_link = item.find('link').text
        key = str(featured_title) + str(featured_link)

        if is_new_and_mark(current_file, key):
            push_job({
                'title': featured_title,
                'url': featured_link,
                'posted_on': datetime.now().date(),
            }, "NEW ARTICLE FROM DETECTION ENGINEERING")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')
