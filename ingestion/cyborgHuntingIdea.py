from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from datetime import datetime
import selenium
import time, json

message_list = []
offset_data = []

source = [
    "https://hunter.cyborgsecurity.io/"
    # "https://hunter.cyborgsecurity.io/research/search?state=(compatible:!f,filters:(),library:!(cyborg_usecases),page:60,size:10,sort:relevance,term:!(),touched:!t)"
]

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
    'Cookie': 'fs_uid=#1453KT#24c86396-8b36-49cf-b38c-0b0c006e9a69:a6828ea1-6ff4-4a06-b89a-8c4c95b237c5:1723030594895::1#04e73f3e#/1751076734; fs_lua=1.1723032504414'
}

###########################CHROMEDRIVER OPTIONS#########################################
options = Options()
# options.add_argument("--window-size=1920x1080")
# options.add_argument("--no-sandbox")
# options.add_argument("--disable-dev-shm-usage")
# options.add_argument("--disable-gpu")
# options.add_argument("--headless")
options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246")

CHROMEDRIVERLOC = "./chromedriver_mac64_arm64/chromedriver" # https://chromedriver.chromium.org/downloads
service = Service(executable_path=CHROMEDRIVERLOC)
driver = webdriver.Chrome(service=service, options=options)
# driver = webdriver.Chrome(options=options, executable_path=CHROMEDRIVERLOC)
driver.get(source[0])
########################################################################################

def name_feed():
    rules_list = []
    # WebDriverWait(driver,30).until(EC.presence_of_element_located((By.XPATH, "/html/body/main/div[2]/section/div/div[2]/div[1]/div[1]/div/div/div/div[2]")))
    # driver.implicitly_wait(10)

    time.sleep(5)
    cyborg_user = os.getenv("CYBORG_USER", "analyst@cti-nexus.local")
    cyborg_pass = os.getenv("CYBORG_PASS", "")
    username = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/ng-component/div/main/div/div/div/div/div/ng-component/form/input[1]").send_keys(cyborg_user)
    password = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/ng-component/div/main/div/div/div/div/div/ng-component/form/input[2]").send_keys(cyborg_pass)

    sign_in_process = driver.find_element(By.XPATH, "/html/body/app-cyborg/div/div/ng-component/div/main/div/div/div/div/div/ng-component/form/div[1]/button").click()
    time.sleep(10)

    print(driver.get_cookies())

    # for i in range(0,61):
    # for i in range(0,11):
    # for i in range(0,2):
    driver.get(f"https://hunter.cyborgsecurity.io/research/search?state=(compatible:!f,filters:(),library:!(cyborg_usecases),page:0,size:600,sort:relevance,term:!(),touched:!t)")
    time.sleep(30)

    element = driver.find_element(By.XPATH, "/html/body/app-cyborg/div/footer/div/div/div/div[1]/div/img")
    driver.execute_script("arguments[0].scrollIntoView();", element)

    time.sleep(10)
    count = 1
    for j in range(2,608):
        print(count)
        print(j)
        print("Title")
        try:
            title_rules = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/header/ng-component/ng-component/div/main/div/div/div/ng-component/cyborg-section/div/div[{j}]/hunt-package/div/kendo-card/kendo-card-header/div/div[2]/package-header/header-title/cyborg-trial-lock-unlock/a").text
        except selenium.common.exceptions.NoSuchElementException:
            try:
                title_rules = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/header/ng-component/ng-component/div/main/div/div/div/ng-component/cyborg-section/div/div[{j}]/hunt-package/div/kendo-card/kendo-card-header/div/div[2]/package-header/header-title/cyborg-trial-lock-unlock/button").text
            except selenium.common.exceptions.NoSuchElementException:
                break

        print(title_rules)
        print('')

        print("Desc")
        # desc_rules = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/header/ng-component/ng-component/div/main/div/div/div/ng-component/cyborg-section/div/div[{j}]/hunt-package/div/kendo-card/kendo-card-header/div/div[2]/package-description").text.split("\n")

        desc_rules = driver.find_element(By.XPATH, f"/html/body/app-cyborg/div/div/header/ng-component/ng-component/div/main/div/div/div/ng-component/cyborg-section/div/div[{j}]/hunt-package/div/kendo-card/kendo-card-header/div/div[2]/package-description").text
        print(desc_rules)

        json_data = {
            "title" : title_rules,
            "desc" : desc_rules
        }
        rules_list.append(json_data)
        count += 1
    # try:
    #     with open("huntingNotes.txt", 'r') as indata:
    #         raw_offset_data = indata.readlines()
    # except FileNotFoundError:
    #     open("huntingNotes.txt", 'w+')
    #     with open("huntingNotes.txt", 'r') as indata:
    #         raw_offset_data = indata.readlines()

    output_file = open('huntingNotes_11-20.json', "w+")
    json.dump(rules_list, output_file, indent=4)
    # with open('huntingNotes.txt', 'a') as offset_data_output:
    #     offset_data_output.write(str(string_output)+ "\n")

name_feed()
driver.quit()

# https://hunter.cyborgsecurity.io/research/search?state=(compatible:!f,filters:(),library:!(cyborg_usecases),page:0,size:10,sort:relevance,term:!(),touched:!t)

# https://hunter.cyborgsecurity.io/research/search?state=(compatible:!f,filters:(),library:!(cyborg_usecases),page:1,size:10,sort:relevance,term:!(),touched:!t)

# https://hunter.cyborgsecurity.io/research/search?state=(compatible:!f,filters:(),library:!(cyborg_usecases),page:60,size:10,sort:relevance,term:!(),touched:!t)