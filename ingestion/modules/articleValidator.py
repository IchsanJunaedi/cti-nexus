# To run use this command "python3 -m supportFile.trendingNewsToday" in ScraperNews folder

from openai import RateLimitError
from modules.llm_client import get_llm_client, store_param
import json, yaml, requests
from datetime import datetime, timedelta


class OpenAIQuotaExhausted(RuntimeError):
    """Raised when OpenAI billing quota / credit is empty."""


class EmptyLLMResponse(RuntimeError):
    """Raised when the LLM API returns zero choices (e.g. content filter, provider glitch)."""

datenow = datetime.now().strftime("%Y-%m-%d")

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

def articleValidator(title):
    prompt_text = """
        As a Threat Intelligence analyst, determine whether the following article title provides meaningful insight into the cybersecurity threat landscape.

        Classification Instructions:

        1. Cyber Threat Relevance:
        - Classify as {"related_cyber": true} if the title discusses or implies:
        - Cybersecurity incidents
        - Threat actor activity
        - Industry- or country-level cyber threat reports
        - Attack trends
        - Cyber-related regulations, risks, or exposure

        - Classify as {"related_cyber": false} if the title is primarily about:
        - Vendor marketing or promotions
        - Product launches or sales
        - Company financials or business operations unrelated to threat intelligence
        - General IT news with no direct link to cybersecurity threats

        - Include a "confidence" score from 0.0 to 1.0 to indicate how strongly the title suggests relevance to threat intelligence.
        - Include a brief "reason" explaining your classification.

        2. Industry Vertical Impact:
        - Identify which industry verticals might be affected using the following list:
        ["Government & Public Sector", "Finance & Insurance", "Healthcare & Life Sciences", "Energy & Utilities", "Telecommunications", "Information Technology & Software", "Critical Infrastructure", "Retail & E-commerce", "Manufacturing & Industrial", "Education & Research", "Legal & Professional Services", "Media & Entertainment", "Transportation & Logistics", "Real Estate & Construction", "Non-profit & NGOs", "Aerospace & Defense Contractors", "Agriculture & Food", "Mining & Natural Resources", "Hospitality & Travel", "General"]

        - Use up to 3 specific industries, or "General" if the title has broad relevance across sectors.
        - Do NOT mix "General" with specific industries.

        3. Security Technology & Best Practices Classification:
        - Classify the title as "security_tech_best_practice": true only if it focuses on:
        - Cybersecurity tools, techniques, or architectures (e.g., SIEM, EDR, IAM, SSO, MFA)
        - Technical implementations (e.g., Zero Trust, network segmentation, threat modeling)
        - Defensive strategies or best practices (e.g., DDoS mitigation, incident response planning)

        - Do NOT classify as "security_tech_best_practice": true if the title:
        - Discusses threat actors, attack campaigns, data breaches, vulnerabilities, or threat trends
        - Is purely promotional, financial, or business-oriented
        - Is a vendor report unless it emphasizes actionable implementation guidance

        4. Country Role Classification:
        - Identify countries or geopolitical entities mentioned in the title and classify each by role:

        - "victim_countries": Countries/regions that were attacked, targeted, breached, or compromised.
            Examples: "Indonesia hit by ransomware" → victim: Indonesia
                    "APT targets Philippine government" → victim: Philippines

        - "actor_countries": Countries/regions attributed as the origin of the threat actor or attack.
            Examples: "China-linked APT attacks Indonesia" → actor: China
                    "North Korean hackers steal crypto" → actor: North Korea

        - Rules:
            - Use full English country names (e.g. "Indonesia" not "Indonesian")
            - If a country is both victim and actor in the same title, include in both lists
            - If role is ambiguous (e.g. bilateral cooperation, general regional report), return empty lists
            - Only include countries explicitly mentioned or strongly implied in the title
            - Return empty lists [] if no country role can be determined from the title alone

        5. Incident Confirmation Classification:
        - Classify as "confirmed_incident": true ONLY if the title indicates a SPECIFIC, CONFIRMED security incident:
            * Names a specific victim organization, government entity, agency, or individual targeted
            * AND/OR explicitly states confirmed impact: data breach occurred, data stolen/exposed, systems encrypted,
            services disrupted, financial loss, system compromise confirmed
            * The incident is presented as having already happened, not predicted or hypothetical

        - Classify as "confirmed_incident": false if the title:
            * Is a general threat landscape report, analysis, forecast, or prediction
            * Discloses a CVE/vulnerability without confirmed exploitation against a named victim
            * Discusses a threat actor's general capabilities without referencing a named incident
            * Is a vendor advisory, best practices guide, or educational/research content
            * Uses speculative language: "could", "may", "researchers warn", "risk of"

        - "incident_confidence": 0.0-1.0 — confidence in the confirmed_incident classification:
            * 0.9-1.0: Named victim + confirmed impact + active/recent language
            * 0.7-0.9: Named victim present OR confirmed impact stated (but not both)
            * 0.4-0.7: Implicit victim or ambiguous impact language
            * 0.0-0.4: Weak signal, mostly analytical or predictive

        - "incident_indicators": list of signals found, from:
            ["named_victim", "confirmed_breach", "ransomware_deployment", "data_exfiltration",
            "service_disruption", "financial_loss", "government_disclosure", "vendor_disclosure",
            "active_campaign", "zero_day_exploitation"]
            Return [] if confirmed_incident is false.

        6. Victim Name Extraction:
        - Extract the named victim organization, company, agency, or individual targeted in the incident.
        - "victim_name": string or null
            * Set to the organization/entity name if the title names a specific victim (e.g. "MGM Resorts", "Change Healthcare", "Philippine National Police")
            * Set to null if no specific victim is named (general reports, vendor advisories, threat actor profiles, vulnerability disclosures without a named target)
            * Use the exact name as it appears in the title — do not abbreviate or expand
            * If multiple victims are named, return the first/most prominent one

        Respond strictly in the following JSON format:
        {
        "title": "Your Title Here",
        "related_cyber": true/false,
        "confidence": 0.0-1.0,
        "reason": "Brief explanation",
        "industries_impacted": ["list", "of", "industries"],
        "security_tech_best_practice": true/false,
        "victim_countries": ["list", "of", "victim", "countries"],
        "actor_countries": ["list", "of", "actor", "origin", "countries"],
        "confirmed_incident": true/false,
        "incident_confidence": 0.0-1.0,
        "incident_indicators": ["list", "of", "signals"],
        "victim_name": "Organization Name or null"
        }
    """
    
    _llm = cfg['llm']
    _provider = _llm['provider']
    client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
    try:
        completion = client.chat.completions.create(model=model_name,
        messages=[
            {"role": "system", "content": prompt_text},
            {"role": "user", "content": title}
        ], temperature=0, n=1, **store_param(_provider))
    except RateLimitError as e:
        if any(code in str(e) for code in ("insufficient_funds", "billing_hard_limit_reached", "exceeded your current quota")):
            raise OpenAIQuotaExhausted(f"OpenAI credit exhausted: {e}") from e
        raise

    if not completion.choices:
        raise EmptyLLMResponse(f"articleValidator: LLM returned 0 choices for title={title!r}")

    llm_response = completion.choices[0].message.json()
    # print(llm_response)
    json_string = llm_response.replace("\n", "").replace("```", "").replace("json", "")
    outer_json = json.loads(json_string)
    outer_json = outer_json['content'].replace("\n", "").replace("True", "true").replace("False", "false")
    json_data = json.loads(outer_json)

    if json_data['related_cyber'] == True:
        return json_data
    else:
        return json_data

def extractTTPs(summary: str) -> dict:
    """Extract MITRE ATT&CK TTPs from a pre-computed article summary (replaces BERT + separate ttpValidator call).

    Receives the truncated LSA summary already computed in nlp.py — no extra HTTP
    request, no PyTorch, and token cost is controlled by the caller's truncation.
    """
            
    _TTP_SYSTEM_PROMPT = """Based on the provided article summary, identify the top 5 most relevant MITRE ATT\u0026CK techniques. For each technique return:
    The technique name, the technique ID (e.g. "T1566.001"), and the specific string or sentence from the input that led to the identification (evidence). If the content is not related to a threat campaign, set "has_techniques" to false.

    Respond ONLY with a valid JSON object:
    {
    "has_techniques": true/false,
    "techniques": [
        {"technique_name": "text", "technique_id": "text", "evidence": "exact phrase from input"}
    ]
    }
    """

    _llm = cfg['llm']
    _provider = _llm['provider']
    client, model_name = get_llm_client(_provider, _llm['api_key'], _llm.get('model', ''))
    try:
        completion = client.chat.completions.create(
            model=model_name,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": _TTP_SYSTEM_PROMPT},
                {"role": "user", "content": summary},
            ],
            max_tokens=1000,
            n=1,
            temperature=0,
            **store_param(_provider),
        )
    except RateLimitError as e:
        if any(code in str(e) for code in ("insufficient_funds", "billing_hard_limit_reached", "exceeded your current quota")):
            raise OpenAIQuotaExhausted(f"OpenAI credit exhausted: {e}") from e
        raise
    if not completion.choices:
        raise EmptyLLMResponse(f"extractTTPs: LLM returned 0 choices for summary={summary[:80]!r}")

    print(f"extractTTPs — prompt: {completion.usage.prompt_tokens}, completion: {completion.usage.completion_tokens}")
    return json.loads(completion.choices[0].message.content)
