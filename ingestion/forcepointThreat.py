from playwright.sync_api import sync_playwright
from datetime import datetime
import os
from urllib.parse import urljoin

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

message_list = []

source = [
    "https://www.forcepoint.com/blog"
]

BROWSER_ARGS = [
    '--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
    '--disable-renderer-backgrounding', '--disable-extensions', '--disable-plugins',
    '--disable-default-apps', '--disable-background-networking', '--disable-sync',
    '--disable-translate', '--no-first-run',
    '--js-flags=--max-old-space-size=512', '--blink-settings=imagesEnabled=false',
]

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
    try:
        page = browser.new_page(user_agent=USER_AGENT, viewport={"width": 1920, "height": 1080})
        page.goto(source[0], wait_until="domcontentloaded")

        page.wait_for_selector("main a:has(h4)", timeout=30000)
        # Site redesigned: old absolute XPath is gone, anchor wrapping each post's <h4> is stable
        for article in page.locator("main a:has(h4)").all()[:2]:
            message_list.append({
                "title": article.locator("h4").text_content().strip(),
                "posted_on": datetime.now().date(),
                "url": urljoin(source[0], article.get_attribute("href").strip()),
            })
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW ARTICLE FROM FORCEPOINT")
