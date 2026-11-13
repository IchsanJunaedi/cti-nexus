import requests
import socket, json, yaml, os

_cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "config.yml")
_cfg = {}
if os.path.exists(_cfg_path):
    with open(_cfg_path) as _f:
        _cfg = yaml.safe_load(_f) or {}

_GRAYLOG_URL = _cfg.get("graylog", {}).get("url", os.getenv("GRAYLOG_URL", "http://localhost:12201/gelf"))


def sendLogGraylog(json_data, source, short_message):
    json_log_data = {
        'version': '1.1',
        'host' : source,
#        'source': source,
        'short_message' : short_message,
        'full_message': json_data,
        # 'level': 5,
    }

    for key, value in json_data.items():
        json_log_data.update({key : value})

    headers = {
        'Content-Type': 'application/json',
    }

    print(json_log_data)
    response = requests.post(_GRAYLOG_URL, headers=headers, json=json_log_data)
    print(response.text)