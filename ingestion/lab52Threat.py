import defusedxml.ElementTree as ET
from datetime import datetime
import requests
import os 
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://lab52.io/blog/feed/'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    root = ET.fromstring(response.content)

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
            }, "NEW ARTICLE FROM LAB52")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

