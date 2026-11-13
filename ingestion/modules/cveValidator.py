# to validate if CVE is related to orgs or not
from modules.llm_client import get_llm_client, store_param
from modules.techstackStore import get_tech_list
import json, yaml, requests, re
from datetime import datetime, timedelta

datenow = datetime.now().strftime("%Y-%m-%d")

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

def checkCVE(cve_id):
    list_of_tech = get_tech_list()

    cve_prod_req = requests.get(f"https://cveawg.mitre.org/api/cve/{cve_id}").json()
        
    vendor_name = ""
    
    try:
        for data in cve_prod_req['containers']['adp']:
            for affected in data['affected']:
                for version in affected['versions']:
                    vendor_name = str(affected['vendor']).lower()
    except Exception as e:
        pass

    try:
        for affected in cve_prod_req['containers']['cna']['affected']:
            for version in affected['versions']:
                if len(vendor_name) == 0 or vendor_name == "n/a":
                    vendor_name = affected['vendor']
    except Exception as e:
        print("neither")
        pass

    if len(vendor_name) == 0:
        vendor_name = "Unknown"

    applicable_status = False
    for tech in list_of_tech:
        if re.search(f"{str(tech).lower().strip()}", str(vendor_name).lower()):
            # applicable_status = "[<b>Might Applicable to Organization!</b>]"
            applicable_status = True
            break

    return applicable_status

def checkTechStack(tech_name):
    list_of_tech = get_tech_list()

    applicable_status = False
    for tech in list_of_tech:
        if re.search(f"{str(tech).lower().strip()}", str(tech_name).lower()):
            applicable_status = True
            break
    
    return applicable_status

def llmCveValidator(cve_data):
    prompt_text = """
        You are a Cyber Threat Intelligence manager with 7+ years of expertise.

        Analyze the CVE data and return ONLY a valid JSON object with these additional fields. Do not include the original CVE data in your response.

        Return ONLY these new fields in JSON format (no markdown, no code blocks):

        {
        "product_name": "The possible impacted product name",
        "summary": "Max 50 words describing what attackers can do or what data is exposed",
        "executive_summary": "2-3 sentences for non-technical leadership",
        "risk_context": "1-2 paragraphs (narrative prose, no lists) describing the risks and consequences if the vulnerability is NOT patched. Cover: business impact (financial loss, data breach consequences, competitive damage), compliance violations and penalties, and exploitation likelihood (attack complexity, threat actor behavior, time-based risk escalation). Focus on what COULD HAPPEN, not what to do.",
        "primary_remediation_action": [
            {
                "version_branch": "The affected version branch (e.g., '9.1', '10.x', 'all versions')",
                "fixed_version": "The safe version to upgrade to (e.g., '9.1.41.07 or above', 'Patch pending - monitor vendor advisory')"
            }
        ]
        "affected_version": "version [X] or below is affected BASED ON 'affected' key of provided json"
        "alternative_remediation_action": [
            "5-7 compensating controls if patching delayed",
            "Each item max 30 words",
            "Include: access restrictions, monitoring, forensics, segmentation, authentication, feature disabling"
        ],
        "attack_complexity": "Parse from cvss_vector AC: (Low/High)",
        "impact": "The impact if CVE exploited",
        "recommended_timeline": "Based on cve_severity: CRITICAL (24-48h), HIGH (7 days), MEDIUM (30 days), LOW (90 days)",
        "analysis_timestamp": "Current timestamp in ISO 8601 format"
        }

        CRITICAL: Return ONLY the JSON object with new fields. Start with { and end with }. No other text.
    """
    
    _llm = cfg['llm']
    _provider = _llm['provider']
    client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
    completion = client.chat.completions.create(model=model_name,
    messages=[
        {"role": "system", "content": prompt_text},
        {"role": "user", "content": str(cve_data)}
    ], temperature=0, n=1, **store_param(_provider))

    llm_response = completion.choices[0].message.content
    # print(llm_response)
    json_data = json.loads(llm_response)
    return json_data
    
def dedupMitigation(mitigation_list):
    prompt_text = """
        You are a Cyber Threat Intelligence manager with 7+ years of expertise.

        Analyze the CVE data and return ONLY a valid JSON object with these additional fields. Do not include the original CVE data in your response.

        Return ONLY these new fields in JSON format (no markdown, no code blocks):

        {
        "alternative_remediation_action": [
            "Provide EXACTLY 7 unique, non-overlapping compensating controls if patching is delayed",
            "Each item must be 20-30 words and actionable",
            "NO DUPLICATES - each control must address a different security layer",
            "Be specific with technical details - avoid generic phrases like 'implement security measures'"
        ],
        }

        CRITICAL: Return ONLY the JSON object with new fields. Start with { and end with }. No other text.
    """
    _llm = cfg['llm']
    _provider = _llm['provider']
    client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
    completion = client.chat.completions.create(model=model_name,
    messages=[
        {"role": "system", "content": prompt_text},
        {"role": "user", "content": str(mitigation_list)}
    ], temperature=0, n=1, **store_param(_provider))

    llm_response = completion.choices[0].message.content

    json_data = json.loads(llm_response)
    return json_data
    
def dedupRiskContext(riskContext):
    prompt_text = """
    You are a Cyber Threat Intelligence analyst writing impact assessments for vulnerability reports. 

    Generate a concise impact statement (maximum 100 words) that covers:
    1. Direct technical impact (what can attackers achieve)
    2. Business consequences (data breach, financial loss, operational disruption)
    3. Likelihood of exploitation based on attack complexity and public availability
    4. Time-sensitive risk factors
    5. Bold/Highlight important key points

    CRITICAL: Eliminate redundant phrasing.
    """
    
    _llm = cfg['llm']
    _provider = _llm['provider']
    client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
    completion = client.chat.completions.create(model=model_name,
    messages=[
        {"role": "system", "content": prompt_text},
        {"role": "user", "content": str(riskContext)}
    ], temperature=0, n=1, **store_param(_provider))

    llm_response = completion.choices[0].message.content

    # json_data = json.loads(llm_response)
    return llm_response
   