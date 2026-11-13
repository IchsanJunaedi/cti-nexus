from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import time, os

current_file = os.path.basename(__file__).split(".")[0]

CHROMEDRIVERLOC = "./chromedriver_mac64_arm64/chromedriver"
CHROME_ARGS = [
    "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--headless",
    "--disable-background-networking", "--disable-extensions", "--disable-plugins",
    "--disable-default-apps", "--disable-sync", "--disable-translate", "--no-first-run",
    "--blink-settings=imagesEnabled=false",
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246",
]
source = ["example.com"]

def name_feed():
    message_list = []

    options = Options()
    for arg in CHROME_ARGS:
        options.add_argument(arg)

    driver = webdriver.Chrome(service=Service(executable_path=CHROMEDRIVERLOC), options=options)
    try:
        driver.get(source[0])
        time.sleep(20)
        for i in range(1, 5):
            article_title = driver.find_element(By.XPATH, f"").text
            article_url = driver.find_element(By.XPATH, f"/html/body/main/div/div[2]/div[1]/div/div/div[1]/section/a").get_attribute('href')
            message_list.append({
                "title": article_title,
                "posted_on": datetime.now().date(),
                "url": article_url,
            })
    finally:
        driver.quit()

    for message in message_list:
        key = str(message['title']) + str(message['url'])
        if is_new_and_mark(current_file, key):
            push_job(message, "NEW ARTICLE FROM NAME")

if __name__ == '__main__':
    name_feed()
