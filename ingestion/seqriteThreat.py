import defusedxml.ElementTree as ET
import requests
from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
import os
 
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

message_list = []

def seqrite_news():
    response = requests.get('https://www.seqrite.com/blog/feed/', headers={'User-Agent': 'Mozilla/5.0'})
    root = ET.fromstring(response.content)

    for item in root.findall('.//item')[:6]:
        article_title_section_recent = item.find('title').text
        article_url_section_recent = item.find('link').text

        key = str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip()
        if is_new_and_mark(current_file, key):
            push_job({
                "title" : article_title_section_recent,
                "url" : article_url_section_recent,
                "posted_on" : datetime.now().date()
            }, "NEW RECENT ARTICLE FROM SEQRITE")

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()

        page.set_extra_http_headers({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        page.goto("https://www.seqrite.com/resources/cat/threat-reports", wait_until="domcontentloaded") # Change with the website you want to scrape

        for i in range(1, 5):
            try:
                article_title = page.locator(f'xpath=/html/body/div[1]/main/section[2]/div/div/div[{i}]/div/div[2]/h3/a').text_content().lstrip().strip() # Change 'xxx' with the XPath of the title you want to scrape
                article_url = page.locator(f'xpath=/html/body/div[1]/main/section[2]/div/div/div[{i}]/div/div[2]/h3/a').get_attribute("href").lstrip().strip() # Change 'xxx' with the XPath of the url you want to scrape
                article_posted = datetime.now().date()
            except TimeoutError:
                continue

            message_data = {
                "title": article_title,
                "posted_on": article_posted,
                "url": article_url,
            }

            message_list.append(message_data)
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW RECENT ARTICLE FROM SEQRITE")
        

seqrite_news()
#browser.close()