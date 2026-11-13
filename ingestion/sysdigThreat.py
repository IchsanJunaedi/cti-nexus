from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import os, time

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
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
        })
        page.goto("https://www.sysdig.com/threat-research", wait_until="domcontentloaded")
        
        # try:
        #     page.get_by_test_id("axeptio_btn_acceptAll").click(timeout=5000)
        # except Exception:
        #     pass  # already accepted / not shown

        for i in range(1, 4):
            # try:
                article_title = page.locator(f'xpath=/html/body/div[2]/main/section[2]/div/div[2]/div/div/div[1]/div[{i}]/div[2]/div[1]/h3').nth(0).text_content().lstrip().strip()

                article_url = page.locator(f'xpath=/html/body/div[2]/main/section[2]/div/div[2]/div/div/div[1]/div[{i}]/a').nth(0).get_attribute("href").lstrip().strip()
                
                message_list.append({
                    "title": article_title,
                    "posted_on": datetime.now().date(),
                    "url": "https://www.sysdig.com" + article_url,
                })
            # except TimeoutError:
            #     continue
    finally:
        browser.close()

for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW ARTICLE FROM SYSDIG")
