import imaplib, email, re, requests
# from email.header import decode_header
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from lxml import html
from bs4 import BeautifulSoup
import re

options = Options()
# options.add_argument("--window-size=1920x1080")
options.add_argument("--no-sandbox")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--headless")

CHROMEDRIVERLOC = "./chromedriver_mac64_arm64/chromedriver" # https://chromedriver.chromium.org/downloads
service = Service(executable_path=CHROMEDRIVERLOC)
driver = webdriver.Chrome(service=service, options=options)
# driver = webdriver.Chrome(options=options, executable_path=CHROMEDRIVERLOC)

imap_server = imaplib.IMAP4_SSL(host='imap.gmail.com',port=993)
imap_server.login('email', 'pass')
list_inbox = imap_server.list()
# for cat in list_inbox:
#     print(cat)

offset_data = []
message_data = []

def clean(text):
    return "".join(c if c.isalnum() else "_" for c in text)

status, messages = imap_server.select('CyberThreatIntel')
N = 50
messages = int(messages[0])
for i in range(messages, messages-N, -1):
    if i == 0:
        break
    res, msg = imap_server.fetch(str(i), "(RFC822)")
    for response in msg:
        if isinstance(response, tuple):
            msg = email.message_from_bytes(response[1])
            if msg.is_multipart():
                for part in msg.walk():
                    email_items = part.items()
                    for i in range(len(email_items)):
                        if email_items[i][0] == "Message-ID" or email_items[i][0] == "Message-Id":
                            email_id = email_items[i][1]

                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    try:
                        body = part.get_payload(decode=True).decode()
                    except:
                        pass
                    if content_type == "text/plain" and "attachment" not in content_disposition:
                        # print(body)
                        if re.search("@Gerald_Auger", body):
                            try:
                                from_sender = "gerald@simplycyber.io"
                                body = re.split("\*{16,20}",body)
                                
                                end_user_raw = body[2]
                                end_user = re.split("\*{10,20}", str(end_user_raw))[0]
                                end_user = re.sub(r'Hear my live analysis of this story here \(\s*(.*?)\s*\).',"",end_user)
                                end_user = re.sub(r'Get the CISO Series full article here \(\s*(.*?)\s*\).',"",end_user)
                                end_user = "**********FOR YOUR END-USERS**********" + end_user.replace("\r\n\r\n","\n").replace("\n\n\n","")
                                
                                peers = re.split("\*{10,20}", str(end_user_raw))[2]
                                peers = re.sub(r'Hear my live analysis of this story here \(\s*(.*?)\s*\).',"",peers)
                                peers = re.sub(r'Get the CISO Series full article here \(\s*(.*?)\s*\).',"",peers)
                                peers = "**********FOR YOUR PEERS**********\n" + peers.replace("\r\n\r\n","\n").replace("\n\n\n","")
                                
                                executive = body[4]
                                executive = re.sub(r'Hear my live analysis of this story here \(\s*(.*?)\s*\).',"",executive)
                                executive = re.sub(r'Get the CISO Series full article here \(\s*(.*?)\s*\).',"",executive)
                                executive = "**********FOR YOUR EXECUTIVES**********\n" + executive.replace("\r\n\r\n","\n").replace("\n\n\n","")
                                email_body = end_user + " || " + peers + " || " + executive
                            except IndexError:
                                pass
                        # elif re.search("info@letsdefend.net", body):
                        elif re.search("https://letsdefend.us14", body):
                            from_sender = "info@letsdefend.net"
                            email_body_raw = re.findall("(https://mailchi\.mp/.*)", body)
                            email_body_raw = email_body_raw[0][:-2]

                            driver.get(email_body_raw)
                            WebDriverWait(driver,50).until(EC.presence_of_element_located((By.XPATH, "/html/body/center[1]/table/tbody/tr/td/table/tbody/tr[3]/td/table[2]/tbody/tr/td/table/tbody/tr/td/table/tbody/tr/td/a/span/strong/span")))
                            email_body = ""
                            counter = 2
                            while True:
                                try:
                                    xpath = f"/html/body/center[1]/table/tbody/tr/td/table/tbody/tr[3]/td/table[{counter}]"
                                    article_url = driver.find_element(By.XPATH, xpath + "/tbody/tr/td/table/tbody/tr/td/table/tbody/tr/td/a").get_attribute("href")
                                    article_title = driver.find_element(By.XPATH, xpath + "/tbody/tr/td/table/tbody/tr/td/table/tbody/tr/td/a/span/strong/span").text

                                    email_body = email_body + " || " + f"<a href='{article_url}'>{article_title}</a>"
                                    counter += 1
                                except:
                                    break
                    elif content_type == "text/html" and "attachment" not in content_disposition: 
                        if re.search("CrowdStrike Intelligence Weekly Report", body):
                            soup = BeautifulSoup(body, 'html.parser')

                            sections = soup.find_all(['h2', 'p'])

                            for i in range(len(sections)):
                                if sections[i].name == 'h2':
                                    try:
                                        if sections[i+1] == "h2":
                                            continue
                                    except IndexError:
                                        continue

                                elif sections[i].name == 'p':
                                    if re.search("Access to linked reports", sections[i].text) or re.search("Copyright ©", sections[i].text) or re.search("\d https\[:\]", sections[i].text):
                                        continue
                                    
                                    if sections[i+1].name == "h2":
                                        pass
                                    else:
                                        # print(str(sections[i].text).strip().rstrip().replace("                                                                                                                   ", "").replace("\n", ''))
                                        continue
                            
                        elif re.search("https://substack.com", body):
                            soup = BeautifulSoup(body, 'html.parser')

                            # Extract all parent elements containing both <h2> and <p> tags
                            sections = soup.find_all(['title', 'h4'])
                            
                            email_body = ""
                            for section in sections:
                                from_sender = "metacurity@substack.com"
                                email_body += section.text + "\n\n"
                        elif re.search("https://go.recordedfuture.com", body):
                            soup = BeautifulSoup(body, 'html.parser')
                            sections = soup.find_all(['title', 'h2'])
                    try:
                        json_data = {
                            "from" : from_sender,
                            "body" : email_body,
                            "id" : email_id
                        }
                        message_data.append(json_data)
                    except NameError:
                        pass
                    
for message in message_data:
    try:
        with open("offset/emailnewsThreatOffset.txt", 'r') as indata:
            raw_offset_data = indata.readlines()
    except FileNotFoundError:
        open("offset/emailnewsThreatOffset.txt", 'w+')
        with open("offset/emailnewsThreatOffset.txt", 'r') as indata:
            raw_offset_data = indata.readlines()
        
    for raw_offset in raw_offset_data:
        offset_data.append(raw_offset.strip())

    if message['id'] in offset_data:
        continue

    if message['from'] == "gerald@simplycyber.io":
        email_body = str(message['body']).split(" || ")
        for body in email_body:

            body = body.replace("\r\n\r\n\r\n\r\n\r\n\r\n\u200b\r\n\r\n","")
            featured_message = f"""
    === <b>NEW CYBER NEWSLETTER FROM {message['from']}</b> ===
{body.split("And, as always, please give me feedback on Twitter")[0].split("Also, please share this link,")[0].split("Hear my live analysis on this story here")[0]}
            print(featured_message)
            # send_alert(msg=featured_message)

    elif message['from'] == "info@letsdefend.net":
        email_body = str(message['body']).split(" || ")
        for body in email_body:
            if len(body) != 0:
                featured_message = f"""
    === <b>NEW CYBER NEWSLETTER FROM {message['from']}</b> ===
{body}
                print(featured_message)
                # send_alert(msg=featured_message)

    elif message['from'] == "notifications@crowdstrike.com":
        email_body = str(message['body']).split(" || ")
        cs_body = email_body[0].replace("\r\n\r", "\n")
        cs_body = cs_body.split("\n\n")
        email_title = cs_body[0]

        article = ""
        for i in range(2,50):
            if re.search("-------", cs_body[i]):
                article += cs_body[i] + "\n"

        featured_message = f"""
    === <b>NEW CYBER NEWSLETTER FROM {message['from']}</b> ===
{article.replace("-", "")}
    Check Email to Read More
        # send_alert(msg=featured_message)
        print(featured_message)

    elif message['from'] == "metacurity@substack.com":
        body = message['body'].split("\n")
        for text in body:
            if len(text) == 0 or text == "Closing Thought":
                pass
            else:
                featured_message = f"""
    === <b>NEW CYBER NEWSLETTER FROM {message['from']}</b> ===
{text}
                print(featured_message)
                # send_alert(msg=featured_message)

imap_server.close()
imap_server.logout()