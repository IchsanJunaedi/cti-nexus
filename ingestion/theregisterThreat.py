import defusedxml.ElementTree as ET
from datetime import datetime
import requests
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import os
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://www.theregister.com/security/headlines.atom'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    # Parse the XML content
    namespace = {'atom': 'http://www.w3.org/2005/Atom'}
    root = ET.fromstring(response.content)

    entries = root.findall('atom:entry', namespace)

    for entry in entries:
        featured_title = entry.find('atom:title', namespace).text
        link_element = entry.find('atom:link[@rel="alternate"]', namespace)
        featured_link = link_element.attrib['href'] if link_element is not None else 'No link found'

        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title' : featured_title,
                'url' : featured_link,
                'posted_on' : datetime.now().date()
            }, "NEW ARTICLE FROM THE REGISTER")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

