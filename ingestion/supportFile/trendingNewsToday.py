# To run use this command "python3 -m supportFile.trendingNewsToday" in ScraperNews folder

from modules.llm_client import get_llm_client, store_param
import json, yaml, requests, shutil
from datetime import datetime, timedelta

datenow = datetime.now().strftime("%Y-%m-%d")

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

# def usageChecker():
#     headers = {
#         'Authorization': f"Bearer {cfg['openai']['token_usage']}",
#         'Content-Type': 'application/json',
#     }

#     params = {
#         'start_time': int((datetime.now() - timedelta(days=30)).timestamp()),
#         'limit': '30',
#         "project_ids": [cfg['openai']['project_id']]
#     }

#     response = requests.get('https://api.openai.com/v1/organization/costs', params=params, headers=headers).json()

#     usage_cost = 0
#     for data in response['data']:
#         try:
#             usage_cost += data['results'][0]['amount']['value']
#         except IndexError:
#             continue

#     usage_cost = round(usage_cost, 2)
#     if usage_cost >= 9:
#         return False
#     else:
#         return True

list_file_titles = [
    "supportFile/GLOBAL.txt",
    "supportFile/APAC.txt"
]

for filename in list_file_titles:
    result = ""

    log_filename = f"supportFile/logFile/{filename.replace('.txt', '').replace('supportFile', '')}_{datenow}.txt"
    logging_file = open(log_filename, "w+", encoding="utf-8")

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            title = line.split(" || ")[0].strip()
            result += title + "\n"
            logging_file.write(line)

    # open_ai_status = usageChecker()
    open_ai_status = True

    if open_ai_status == True:
#         prompt_text = """"
# Can you identify the most mentioned 5 topics in the following cybersecurity news titles that will benefit threat intelligence analysts to determine the current threat landscape?

# Return the result in **JSON only** with no additional explanation, no markdown formatting, and no extra text. The format must be exactly:

# [{"topic_name": "name_of_the_topic", "reference_title": ["list_of_title_relevant_to_topic"]}]
# """

        prompt_text = """
Analyze these security news headlines and group them into threat intelligence topics with maximum 8 topics. Output ONLY valid JSON, no other text.

Format: [{"topic_name": "topic", "reference_title": ["headline1", "headline2"]}]

Categories: vulnerabilities, threat actors, malware, data breaches, policy/compliance, infrastructure attacks, supply chain.

Output JSON only.
"""

        _llm = cfg['llm']
        _provider = _llm['provider']
        client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
        completion = client.chat.completions.create(model=model_name,
        messages=[
            {"role": "system", "content": prompt_text},
            {"role": "user", "content": result}
        ], temperature=0, n=1, **store_param(_provider))

        print(model_name)
        print(f"Prompt tokens: {completion.usage.prompt_tokens}") # Tokens used in your input (messages list).
        print(f"Completion tokens: {completion.usage.completion_tokens}") # Tokens used in the response (output).
        print(f"Total tokens: {completion.usage.total_tokens}") # Sum of both (prompt_tokens + completion_tokens).

        # curr_token = int(completion.usage.total_tokens)

        print("")
        gpt_response = completion.choices[0].message.json()

        json_string = gpt_response.replace("\n", "").replace("```", "").replace("json", "")

        outer_json = json.loads(json_string)['content']
        print(outer_json)
        json_data = json.loads(outer_json)
        print(json_data)

        now_date = datetime.now().strftime("%d-%m-%Y")
        list_of_url = open(filename, 'r').readlines()

        string = f"""
<b>=== TOP 5 HOT TOPIC {filename.replace('supportFile/', '').replace('.txt', '')} NEWS TODAY ===</b>
Here is the list of top topic mentioned today"""
        
        json_filename = f"Top_News_{filename.replace('supportFile/', '').replace('.txt', '')}_{now_date}.json"

        json_final_list = []
        for topic in json_data:
            json_dict = {}
            json_dict[topic['topic_name']] = []
            # string += f"\nTopic: {topic['topic_name']}\n"

            for title in topic['reference_title']:
                for url in list_of_url:
                    if title == url.split(" || ")[0]:
                        # string += f"""    - <a href="{url.split(' || ')[1]}">{title}</a>\n"""
                        title_dict = {
                            "title": title,
                            "url": url.split(' || ')[1].strip()
                        }
                        json_dict[topic['topic_name']].append(title_dict)
                        break
            json_final_list.append(json_dict)

        json.dump(json_final_list, open(f"supportFile/{json_filename}", "w+"), indent=4)
        # string = string[:-1]

        shutil.move(f"supportFile/{json_filename}", f"supportFile/logFile/{json_filename}")

        with open(filename, "w", encoding="utf-8") as file:
            file.write("")
    else:
        print("=== OPENAI USAGE REMINDER === If you see this message, you need to recharge the OpenAI Credit")