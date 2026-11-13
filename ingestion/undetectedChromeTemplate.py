import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from datetime import datetime
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import time, os

current_file = os.path.basename(__file__).split(".")[0]

if __name__ == '__main__':
    driver_path = "./chromedriver_mac64_arm64/chromedriver"
    chrome_options = uc.ChromeOptions()
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-background-networking")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-default-apps")
    chrome_options.add_argument("--no-first-run")
    chrome_options.add_argument("--blink-settings=imagesEnabled=false")

    message_list = []

    driver = uc.Chrome(
        options=chrome_options,
        use_subprocess=True,
        headless=True,
        driver_executable_path=driver_path,
    )
    try:
        driver.get('')
        time.sleep(20)
        for i in range(1, 3):
            article_title = driver.find_element(By.XPATH, f"/html/body/div[2]/div/div/div/div/div[3]/main/section/div[2]/div/div/div/div/div/div[{i}]/div/span/article/div/div/div[2]/a/h3").text
            article_url = driver.find_element(By.XPATH, f"/html/body/div[2]/div/div/div/div/div[3]/main/section/div[2]/div/div/div/div/div/div[{i}]/div/span/article/div/div/div[2]/a").get_attribute('href')
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
