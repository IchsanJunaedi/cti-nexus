from datetime import datetime
import requests
import json
from modules.graylogLogging import sendLogGraylog

file_path = "supportFile/ThreatActorName.txt"

try:
    with open(file_path, "r", encoding="utf-8") as file:
        lines = file.read().splitlines()

    if not lines:
        print("Warning: The file is empty.")
    
    for line in lines:
        threat_actors = [actor.strip() for actor in line.split("||")]
        
        for threat_actor in set(threat_actors):  # Use set() to remove duplicates in a single line
            if threat_actor: 
                json_data = {
                    "threat_actor": threat_actor,
                }

                sendLogGraylog(json_data, "threat-actor", "threat-actor-activity")

                print(f"Sent to Graylog: {json_data}")

        open(file_path, "w").close()
        print(f"Cleared contents of '{file_path}' after processing.")

except FileNotFoundError:
    print(f"Error: File '{file_path}' not found.")
except Exception as e:
    print(f"An error occurred: {e}")

