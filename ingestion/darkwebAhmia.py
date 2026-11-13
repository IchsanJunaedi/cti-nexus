from datetime import datetime
from lxml import html
import time, requests
from modules import dbMongo

message_list = []
offset_data = []

def ahmia_feed():
    keyword = [
        "tni-ad.mil.id",
        "kemhan.go.id",
        "ransomware leak",
        "credential dump"
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9",
        "Connection": "keep-alive",
    }

    for word in keyword:
        #page = requests.get(f'https://ahmia.fi/search/?q={word}&d=7')
        page = requests.get(f'https://ahmia.fi/search/?q={word}&d=7', headers=headers,
                timeout=15)
        tree = html.fromstring(page.content)
        link_list = tree.iterlinks()
        
        recent_count = 1
        try:
            for i in range(1,6):
                result_title = tree.xpath(f"/html/body/div/div/div[2]/ol/li[{recent_count}]/h4/a/text()")[0]
                result_desc = tree.xpath(f"/html/body/div/div/div[2]/ol/li[{recent_count}]/p/text()")[0]
                result_link = tree.xpath(f"/html/body/div/div/div[2]/ol/li[{recent_count}]/cite/text()")[0]
                
                if str(result_title).lstrip() + str(result_link).lstrip() not in offset_data:
                    message_data = {
                        "title" : result_title.lstrip().strip(),
                        "url" : result_link.lstrip().strip(),
                        "desc" : result_desc,
                        "posted_on" : datetime.now().date()
                    }

                    message_list.append(message_data)
                recent_count += 1
        except IndexError:
            print("No new results")
            exit()

        for message in message_list:
            
            try:
                with open("offset/darkwebAhmiaOffset.txt", 'r') as indata:
                    raw_offset_data = indata.readlines()
            except FileNotFoundError:
                open("offset/darkwebAhmiaOffset.txt", 'w+')
                with open("offset/darkwebAhmiaOffset.txt", 'r') as indata:
                    raw_offset_data = indata.readlines()

            for raw_offset in raw_offset_data:
                offset_data.append(raw_offset.strip())

            if str(message['title']) + str(message['url']) not in offset_data:
                msg_data = f"""
            === <b>PRIVY FOUND IN DARKWEB LINK</b> ===
    <b>Title</b> : {message['title'].lstrip().strip()}
    <b>Description</b> : {message['desc']}
    <b>Posted On</b> : {message['url'].replace(".", "[.]")}
    """
                print(msg_data)
                dbMongo.upsert_alert("darkweb_ahmia", str(message['title']) + str(message['url']), msg_data.strip(),
                                     source="Ahmia", title=message['title'], url=message['url'])

                with open('offset/darkwebAhmiaOffset.txt', 'a') as offset_data_output:
                    offset_data_output.write(str(message['title']).lstrip() + str(message['url']).lstrip() + "\n")
ahmia_feed()