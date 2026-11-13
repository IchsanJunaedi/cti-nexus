from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import time, requests
import os, re
 
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://www.tripwire.com/blogs.xml'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    # root = ET.fromstring(html_lib.unescape(response.content.decode("utf-8", errors='ignore').replace("&ndash;", "").replace("&", "&amp;")))

    root = html_lib.unescape(response.content.decode("utf-8", errors='ignore'))

    fixed = re.sub(r'&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9A-Fa-f]+;)', '&amp;', root)

    root = ET.fromstring(fixed)

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
            }, "NEW ARTICLE FROM TRIPWIRE")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')