import defusedxml.ElementTree as ET
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import requests, os

current_file = os.path.basename(__file__).split(".")[0]

url = 'https://dmpdump.github.io/feed.xml'
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}
ns = {'atom': 'http://www.w3.org/2005/Atom'}

response = requests.get(url, headers=headers)
if response.status_code == 200:
    root = ET.fromstring(response.content)

    for entry in root.findall('atom:entry', ns):
        featured_title = entry.find('atom:title', ns).text
        featured_link = entry.find('atom:link', ns).get('href')
        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title': featured_title,
                'url': featured_link,
                'posted_on': datetime.now().date(),
            }, "NEW ARTICLE FROM DMPDUMP")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')
