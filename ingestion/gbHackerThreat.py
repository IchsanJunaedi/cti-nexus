import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os 
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url_list = [
    "https://gbhackers.com/feed/",
    # "https://gbhackers.com/category/threatsattacks/feed/",
    # "https://gbhackers.com/category/vulnerability-android-2/feed/"
]

for url in url_list:
    # Set a custom user agent
    headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36'}

    # Make a request to the URL
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        # Parse the XML content
        root = ET.fromstring(html_lib.unescape(response.content.decode("utf-8").replace("&ndash;", "").replace("&", "&amp;").replace("%20", " ").replace("&", "")))

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
                }, "NEW ARTICLE FROM GBHACKER")
    else:
        print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

