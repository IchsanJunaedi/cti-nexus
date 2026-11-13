from playwright.sync_api import sync_playwright
from playwright._impl._errors import TimeoutError
from datetime import datetime
import os

from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    try:
        page = browser.new_page()

        page.set_extra_http_headers({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

        page.goto("https://any.run/malware-trends/") # Change with the website you want to scrape

        recent_count = 3
        malware_trend = "Top 10 Malware Trends based on AnyRun for the past 7 days\n"
        
        for i in range(1,11):
            malware_name = page.locator(f'xpath=/html/body/section/div/div[2]/div/div/ul/li[{recent_count}]/a/div[2]/h2').text_content().lstrip().strip()
            malware_url = page.locator(f'xpath=/html/body/section/div/div[2]/div/div/ul/li[{recent_count}]/a').get_attribute("href").lstrip().strip()
            malware_type = page.locator(f'xpath=/html/body/section/div/div[2]/div/div/ul/li[{recent_count}]/a/div[3]').text_content().lstrip().strip()
            malware_report = page.locator(f'xpath=/html/body/section/div/div[2]/div/div/ul/li[{recent_count}]/a/div[6]').text_content().lstrip().strip()
            
            malware_trend += str(i) + ". " + str(malware_name) + " - " + str(malware_type) + " - with report(s) up to : " + str(malware_report) + "\n"

            recent_count += 1

        featured_message = malware_trend
    finally:
        browser.close()
