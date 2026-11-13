from datetime import datetime
from modules.nlp import nlp_scan
from lxml import html
import time, requests

message_list = []
offset_data = []

def intel471_blog_feed():
    page = requests.get('https://www.intel471.com/blog')
    tree = html.fromstring(page.content)
    
    recent_count = 1
    for i in range(1,7):
        article_url_section_recent = tree.xpath(f"/html/body/main/div[2]/div/div/div[1]/div[2]/a[{i}]/@href")[0]
        article_title_section_recent = tree.xpath(f"/html/body/main/div[2]/div/div/div[1]/div[2]/a[{i}]/article/div[2]/h3/text()")[0]
        
        try:
            with open("offset/intel471ThreatOffset.txt", 'r') as indata:
                raw_offset_data = indata.readlines()
        except FileNotFoundError:
            open("offset/intel471ThreatOffset.txt", 'w+')
            with open("offset/intel471ThreatOffset.txt", 'r') as indata:
                raw_offset_data = indata.readlines()
                
        for raw_offset in raw_offset_data:
            offset_data.append(raw_offset.strip())
        
        if str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip() not in offset_data:
            message_data = {
                "title" : article_title_section_recent,
                "url" : article_url_section_recent,
                "posted_on" : datetime.now().date()
            }

            message_list.append(message_data)
        recent_count += 1

    for message in message_list:        
        if str(message['title']) + str(message['url']) not in offset_data:
            msg_data = f"""
        === <b>NEW ARTICLE FROM INTEL471</b> ===
<b>Title</b> : {message['title']}
<b>Posted On</b> : {message['posted_on']}
<b>Link</b> : <a href="{message['url']}">Read Now</a>
"""
            nlp_scan(message, "NEW ARTICLE FROM INTEL471")

            time.sleep(3)

            with open('offset/intel471ThreatOffset.txt', 'a') as offset_data_output:
                offset_data_output.write(str(message['title']).lstrip() + str(message['url']).lstrip() + "\n")

def intel471_whitepaper_feed():
    page = requests.get('https://intel471.com/resources/whitepapers')
    tree = html.fromstring(page.content)
    print(page.content)
    
    recent_count = 1
    for i in range(1,7):
        article_url_section_recent = tree.xpath(f"/html/body/main/div[2]/div/div[2]/a[{i}]/@href")[0]
        
        article_title_section_recent = tree.xpath(f"/html/body/main/div[2]/div/div[2]/a[{i}]/article/div[2]/div[2]/h3/text()")[0] 

        try:
            with open("offset/intel471ThreatOffset.txt", 'r') as indata:
                raw_offset_data = indata.readlines()
        except FileNotFoundError:
            open("offset/intel471ThreatOffset.txt", 'w+')
            with open("offset/intel471ThreatOffset.txt", 'r') as indata:
                raw_offset_data = indata.readlines()
                
        for raw_offset in raw_offset_data:
            offset_data.append(raw_offset.strip())
        
        if str(article_title_section_recent).lstrip() + str(article_url_section_recent).lstrip() not in offset_data:
            message_data = {
                "title" : article_title_section_recent,
                "url" : "https://intel471.com" + article_url_section_recent,
                "posted_on" : datetime.now().date()
            }

            message_list.append(message_data)
        recent_count += 1

    for message in message_list:        
        if str(message['title']) + str(message['url']) not in offset_data:
            msg_data = f"""
        === <b>NEW WHITE PAPERS FROM INTEL471</b> ===
<b>Title</b> : {message['title']}
<b>Posted On</b> : {message['posted_on']}
<b>Link</b> : <a href="{message['url']}">Read Now</a>
"""
            nlp_scan(message, "NEW WHITE PAPERS FROM INTEL471")
            time.sleep(3)

            with open('offset/intel471ThreatOffset.txt', 'a') as offset_data_output:
                offset_data_output.write(str(message['title']).lstrip() + str(message['url']).lstrip() + "\n")

# intel471_whitepaper_feed()
intel471_blog_feed()