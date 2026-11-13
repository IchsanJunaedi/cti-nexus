from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

message_list = []

def checkpoint_latest_feed():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()

            page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            })

            page.goto("https://research.checkpoint.com/latest-publications/") # Change with the website you want to scrape

            for i in range(1, 5):
                try:
                    article_title = page.locator(f'xpath=/html/body/section/div/div[2]/div[1]/div[1]/div[{i}]/div/div[2]/h3/a').text_content() # Change 'xxx' with the XPath of the title you want to scrape
                    article_url = page.locator(f'xpath=/html/body/section/div/div[2]/div[1]/div[1]/div[{i}]/div/div[2]/h3/a').get_attribute("href") # Change 'xxx' with the XPath of the url you want to scrape
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
            push_job(message, "NEW ARTICLE FROM CHECKPOINT RESEARCH")

def checkpoint_ti_feed():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()

            page.set_extra_http_headers({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            })

            page.goto("https://research.checkpoint.com/intelligence-reports/") # Change with the website you want to scrape

            for i in range(1, 5):
                try:
                    article_title = page.locator(f'xpath=/html/body/section/div/div[2]/div[1]/div[1]/div[{i}]/div/div[2]/h3/a').text_content() # Change 'xxx' with the XPath of the title you want to scrape
                    article_url = page.locator(f'xpath=/html/body/section/div/div[2]/div[1]/div[1]/div[{i}]/div/div[2]/h3/a').get_attribute("href") # Change 'xxx' with the XPath of the url you want to scrape
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
            push_job(message, "NEW ARTICLE FROM CHECKPOINT RESEARCH")

checkpoint_latest_feed()
checkpoint_ti_feed()
