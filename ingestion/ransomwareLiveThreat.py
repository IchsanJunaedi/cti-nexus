from datetime import datetime
from modules.graylogLogging import sendLogGraylog
from modules import dbMongo
import requests
import os
import pycountry, yaml

from modules.offsetStore import is_new_and_mark
current_file = os.path.basename(__file__).split(".")[0]

with open("config/config.yml", "r") as config_data:
    cfg = yaml.safe_load(config_data)

asia_pacific_countries = [
    "AF", "AU", "BD", "BN", "BT", "KH", "CN", "FJ", "IN", "ID", "JP", "KZ", "KR", "LA", "MY",
    "MV", "MN", "MM", "NP", "NZ", "PK", "PG", "PH", "SG", "LK", "TH", "TL", "VN", "VU"
]

# Pre-load existing offset keys from MongoDB (replaces offset file)
existing_keys = dbMongo.get_existing_ransomware_keys()
print(f"Loaded {len(existing_keys)} existing ransomware victim keys from DB")

now_year = str(datetime.now().year)
now_month = str(datetime.now().month)

headers = {
    "X-API-KEY": cfg['ransomware_live']['api_token']
}

request_data = requests.get(f"https://api-pro.ransomware.live/victims/?month={now_month}&year={now_year}", verify=False, headers=headers)

for data in request_data.json()['victims']:
    country_obj = pycountry.countries.get(alpha_2=str(data.get('country', '')).upper())

    group_name  = data.get('group', '')
    victim_name = data.get('victim', '')
    attack_date = str(data.get('attackdate', '')).split('T')[0]

    offset_string = f"{group_name}:{victim_name}:{data.get('country', '')}:{data.get('activity', '')}:{attack_date}"

    if offset_string in existing_keys:
        continue

    try:
        post_url = data['claim_url'] if data.get('claim_url') else "Unknown"
    except TypeError:
        post_url = "Unknown"

    try:
        country_name = country_obj.name
    except AttributeError:
        country_name = str(data.get('country', ''))

    victim_doc = {
        "group_name":   group_name,
        "victim":       victim_name,
        "domain":       data.get('domain', ''),
        "description":  data.get('description', ''),
        "country":      country_name,
        "country_code": str(data.get('country', '')).upper(),
        "industry":     data.get('activity', ''),
        "published":    attack_date,
        "discovered":   str(data.get('discovered', '')).split('T')[0],
        "post_url":     post_url,
        "ransom":       data.get('ransom'),
        "data_size":    data.get('data_size'),
        "screenshot":   data.get('screenshot', ''),
        "offset_key":   offset_string,
        "saved_at":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    dbMongo.upsert_ransomware_victim(victim_doc)

    # sendLogGraylog(
    #     {"group_name": group_name, "country": country_name, "industry": data.get('activity', '')},
    #     "ransomware-group",
    #     "ransom-group-activity",
    # )

    existing_keys.add(offset_string)
