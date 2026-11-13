from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import os

current_file = os.path.basename(__file__).split(".")[0]

BROWSER_ARGS = [
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
    '--disable-renderer-backgrounding', '--disable-extensions', '--disable-plugins',
    '--disable-default-apps', '--disable-background-networking', '--disable-sync',
    '--disable-translate', '--no-first-run', '--single-process',
    '--js-flags=--max-old-space-size=512', '--blink-settings=imagesEnabled=false',
]

message_list = []

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
    try:
        page = browser.new_page()
        page.set_extra_http_headers({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })
        page.goto("https://www.splunk.com/en_us/blog/security.html", wait_until="domcontentloaded")

        for i in range(1, 4):
            try:
                article_title = page.locator(f'xpath=/html/body/main/div[2]/div[2]/div/div/div[{i}]/div[2]/h3/a').nth(0).text_content().lstrip().strip()
                print(article_title)
                article_url = page.locator(f'xpath=/html/body/main/div[2]/div[2]/div/div/div[{i}]/div[2]/h3/a').nth(0).get_attribute("href").lstrip().strip()
                message_list.append({
                    "title": article_title,
                    "posted_on": datetime.now().date(),
                    "url": "https://www.splunk.com" + article_url,
                })
            except TimeoutError:
                continue
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW RECENT ARTICLE FROM SPLUNK")
