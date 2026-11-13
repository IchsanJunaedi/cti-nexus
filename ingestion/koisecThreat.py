from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

message_list = []

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()

        page.set_extra_http_headers({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        page.goto("https://www.koi.security/blog", wait_until="domcontentloaded") # Change with the website you want to scrape

        for i in range(1, 5):
            try:
                article_title = page.locator(f'xpath=/html/body/div/div[4]/main/section/div/div/div/div[3]/div/div[{i}]/div[1]/div[1]/h3').text_content().lstrip().strip() # Change 'xxx' with the XPath of the title you want to scrape
                article_url = page.locator(f'xpath=/html/body/div/div[4]/main/section/div/div/div/div[3]/div/div[{i}]/a').get_attribute("href").lstrip().strip() # Change 'xxx' with the XPath of the url you want to scrape
                article_posted = datetime.now().date()
            except TimeoutError:
                continue

            message_data = {
                "title": article_title,
                "posted_on": article_posted,
                "url": "https://www.koi.ai/blog" + article_url,
            }

            message_list.append(message_data)
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW ARTICLE FROM KOI SECURITY")

