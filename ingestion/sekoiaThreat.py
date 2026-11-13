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
        page.goto("https://www.sekoia.com/blog", wait_until="domcontentloaded")

        try:
            page.get_by_test_id("xpath=/html/body/div[1]/div//div/div/div[1]/div[2]/button[2]").click(timeout=5000)
        except Exception:
            pass  # already accepted / not shown

        page.wait_for_selector('main a[href^="/blog/"]', timeout=30000)
        hrefs = page.eval_on_selector_all(
            'main a[href^="/blog/"]',
            "els => [...new Set(els.map(e => e.getAttribute('href')))]"
        )
        for url in hrefs[:5]:
            title = url.replace("/blog/", "").replace("-", " ").title()
            message_list.append({
                "title": title,
                "posted_on": datetime.now().date(),
                "url": "https://www.sekoia.com" + url,
            })
    finally:
        browser.close()
print(message_list)
exit()
for message in message_list:
    key = str(message['title']) + str(message['url'])
    if is_new_and_mark(current_file, key):
        push_job(message, "NEW ARTICLE FROM SEKOIA")
