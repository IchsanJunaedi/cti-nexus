from datetime import datetime
import requests
from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
import os
import defusedxml.ElementTree as ET
import html as html_lib
import re

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

def cloudflare_feed():
    # URL of the XML file
    url = 'https://blog.cloudflare.com/rss'

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
                }, "NEW ARTICLE FROM CLOUDFLARE")
    else:
        print(f'Error: Unable to fetch the XML. Status Code: {response.status_code}')

message_list = []

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()

        page.set_extra_http_headers({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        page.goto("https://www.cloudflare.com/resource-hub/?resourcetype=Report", wait_until="domcontentloaded") # Change with the website you want to scrape

        for i in range(1, 5):
            try:
                article_title = page.locator(f'xpath=/html/body/div[1]/div[1]/div/div[4]/div[2]/div/div[3]/div[1]/div[{i}]/div/h4').text_content().lstrip().strip() # Change 'xxx' with the XPath of the title you want to scrape
                article_url = page.locator(f'xpath=/html/body/div[1]/div[1]/div/div[4]/div[2]/div/div[3]/div[1]/div[{i}]/div/a').get_attribute("href").lstrip().strip() # Change 'xxx' with the XPath of the url you want to scrape
                article_posted = datetime.now().date()
            except TimeoutError:
                continue

            message_data = {
                "title": article_title,
                "posted_on": article_posted,
                "url": "https://www.cloudflare.com" + article_url,
            }

            message_list.append(message_data)
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW ARTICLE FROM CLOUDFLARE")

cloudflare_feed()
