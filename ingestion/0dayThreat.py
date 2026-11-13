import requests
import defusedxml.ElementTree as ET
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import os
current_file = os.path.basename(__file__).split(".")[0]

# Configure the SOCKS5 proxy to route through TOR
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}

# Make a request through TOR
response = requests.get('http://sq542reyqwagfkghieehykb6hh6ohku5irarrrbeeo5iyozdbhe5n3id.onion/rss', proxies=proxies) # feeds from https://0day.today/

root = ET.fromstring(response.content)
print(root)
for item in root.findall('.//item'):
        featured_title = item.find('title').text
        featured_link = item.find('link').text

        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title' : featured_title,
                'url' : featured_link,
                'posted_on' : datetime.now().date()
            }, "NEW ARTICLE FROM 0-DAY EXPLOIT")

    # nlp_scan(message, "NEW ARTICLE FROM 0-DAY EXPLOIT")
    

