import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os 
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://trustedsec.com/feed.rss'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    root = ET.fromstring(html_lib.unescape(response.content.decode("utf-8", errors='ignore').replace("&ndash;", "").replace("&", "&amp;")).lstrip())
    # Iterate over each 'item' element in the XML
    for item in root.findall('.//item'):
        featured_title = item.find('title').text
        featured_link = item.find('link').text

        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title' : featured_title,
                'url' : featured_link,
                'posted_on' : datetime.now().date()
            }, "NEW ARTICLE FROM TRUSTEDSEC")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

