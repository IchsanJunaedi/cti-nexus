import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os, re

from lxml import etree

parser = etree.XMLParser(recover=True)
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://www.rapid7.com/rss.xml'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    # root = ET.fromstring(html_lib.unescape(response.content.decode("utf-8", errors='ignore').replace("&ndash;", "").replace("&", "&amp;")))

    # root = html_lib.unescape(response.content.decode("utf-8", errors='ignore'))

    # fixed = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)', '&amp;', root)

    # root = etree.fromstring(fixed.encode('utf-8'), parser)

    raw = response.content.decode("utf-8", errors='ignore')

    fixed = re.sub(
        r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)',
        '&amp;',
        raw
    )

    parser = etree.XMLParser(recover=True)
    root = etree.fromstring(fixed.encode('utf-8'), parser)

    for item in root.findall('.//item'):

        news_status = False

        for cat in item.findall('category'):
            if cat.text == "Emergent Threat Response" or cat.text == "Research" or cat.text == "Threat Intel" or cat.text == "Labs":
                news_status = True

        if news_status == False:
            continue

        featured_title = item.find('title').text
        featured_link = item.find('link').text

        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title' : featured_title,
                'url' : featured_link,
                'posted_on' : datetime.now().date()
            }, "NEW ARTICLE FROM RAPID7")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

