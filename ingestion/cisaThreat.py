import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os, re
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def remove_invalid_xml_chars(xml_string):
    valid_xml_chars = (
        "[\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\u10000-\u10FFFF]"
    )
    return re.sub(f"[^{valid_xml_chars}]", " ", xml_string)

def remove_invalid_xml_bytes(xml_string):
    byte_data = xml_string

    # Filter out invalid byte sequences
    clean_byte_data = bytearray(b for b in byte_data if 0x20 <= b <= 0xD7FF or 0xE000 <= b <= 0xFFFD or b in (0x09, 0x0A, 0x0D))

    # Convert back to string
    return clean_byte_data.decode('utf-8', 'ignore')

# URL of the XML file
url = 'https://www.cisa.gov/cybersecurity-advisories/all.xml'

# Set a custom user agent
headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Accept-Language': 'en-US,en;q=0.9'
    }

# Make a request to the URL
response = requests.get(url, headers=headers)

if response.status_code == 200:
    content = remove_invalid_xml_bytes(response.content)
    root = ET.fromstring(content)

    for item in root.findall('.//item'):
        featured_title = item.find('title').text
        featured_link = item.find('link').text

        if re.search("news-events/ics-advisories/", featured_link):
            continue
        key = str(featured_title) + str(featured_link)
        if is_new_and_mark(current_file, key):
            push_job({
                'title' : featured_title,
                'url' : featured_link,
                'posted_on' : datetime.now().date()
            }, "NEW CYBERSECURITY ADVISORIES FROM CISA")
else:
    print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

