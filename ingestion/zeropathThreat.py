import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os, re
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://zeropath.com/blog/rss.xml'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    # root = ET.fromstring(html_lib.unescape(response.content.decode("utf-8", errors='ignore').replace("&ndash;", "").replace("&", "&amp;")))

    root = html_lib.unescape(response.content.decode("utf-8", errors='ignore'))

    fixed = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)', '&amp;', root)

    root = ET.fromstring(fixed)
    
    for item in root.findall(".//item"):
        categories = [
            cat.text.strip()
            for cat in item.findall("category")
            if cat.text
        ]

        # Skip items that are not in the Research category
        if "Research" not in categories:
            continue

    featured_title = item.find("title").text
    featured_link = item.find("link").text

    print(featured_title)

    key = f"{featured_title}{featured_link}"

    if is_new_and_mark(current_file, key):
        push_job(
            {
                "title": featured_title,
                "url": featured_link,
                "posted_on": datetime.now().date(),
            },
            "NEW ARTICLE FROM ZEROPATH",
        )

else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

