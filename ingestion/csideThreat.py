import defusedxml.ElementTree as ET
from datetime import datetime
import html as html_lib
import requests
import os, re
import feedparser

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

# URL of the XML file
url = 'https://cside.dev/blog/rss.xml'

# Set a custom user agent
headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'}

# Make a request to the URL
# response = requests.get(url, headers=headers)

feed = feedparser.parse('https://cside.dev/blog/rss.xml')

for entry in feed.entries:
    featured_title = entry.title
    featured_link = entry.link

    key = str(featured_title) + str(featured_link)
    if is_new_and_mark(current_file, key):
        push_job({
            'title' : featured_title,
            'url' : featured_link,
            'posted_on' : datetime.now().date()
        }, "NEW ARTICLE FROM CSIDE")

