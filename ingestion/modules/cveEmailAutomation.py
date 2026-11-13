from jinja2 import Environment, FileSystemLoader, Template
from datetime import datetime, timedelta
from typing import List, Dict
from modules.cveValidator import llmCveValidator, dedupMitigation, dedupRiskContext
from modules.O365Module import downloadFileFromSharepoint, uploadFileToSharepoint
from openpyxl import load_workbook
import os, json, yaml, requests, msal

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)
    
client_id = cfg['azure']['client_id']
client_secret = cfg['azure']['client_secret']
tenant_id = cfg['azure']['tenant_id']
user_email = os.getenv('ALERT_SENDER_EMAIL', 'soc-team@cti-nexus.local')
scope = ['https://graph.microsoft.com/.default']

def get_access_token():
    authority = f'https://login.microsoftonline.com/{tenant_id}'
    app = msal.ConfidentialClientApplication(client_id, authority=authority, client_credential=client_secret)

    token_response = app.acquire_token_for_client(scopes=scope)
    if 'access_token' in token_response:
        return token_response['access_token']
    else:
        print('Failed to obtain token')
        print(token_response)
        return None


def _calculateSLA(severity: str) -> int:
    sla_mapping = {     # Calculate SLA days based on severity
        'CRITICAL': 7,
        'HIGH': 30,
        'MEDIUM': 60,
        'LOW': 90
    }
    return sla_mapping.get(severity.upper(), 90)

def _getHighestSeverity(cves: List[Dict]) -> str:
    severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] # Get the highest severity from list of CVEs
    for severity in severity_order:
        if any(cve['severity'].upper() == severity for cve in cves):
            return severity
    return 'LOW'

def _generateCveEmail(cve_data: Dict) -> str:
    env = Environment(loader=FileSystemLoader('.'))  # or specify your template directory
    template = env.get_template('supportFile/cveHtml/template.html')
    
    today = datetime.now()
    highest_severity = _getHighestSeverity(cve_data['cves'])
    remediation_days = _calculateSLA(highest_severity)

    # print(cve_data['remediation_fixes'])

    dedup_mitigations = dedupMitigation(cve_data['mitigations'])['alternative_remediation_action']
    # print(dedup_mitigations)
    
    context = {
        'cve_count': len(cve_data['cves']),
        'product_name': cve_data['product_name'].replace("%20", " ").title(),
        'due_date': (today + timedelta(days=remediation_days)).strftime('%B %d, %Y'),
        'cc_recipients': cve_data.get('cc_recipients', 'Security Operations Team'),
        'email_date': today.strftime('%B %d, %Y'),
        'cves': cve_data['cves'],
        'risk_context': cve_data['risk_context'],
        'remediation_fixes': cve_data['remediation_fixes'],
        'mitigations': dedup_mitigations,
        'vendor_advisory_url': cve_data['vendor_advisory_url'],
        'timeline_actions': cve_data['timeline_actions'],
        'remediation_days': remediation_days,
        'highest_severity': highest_severity,
        'plan_date': (today + timedelta(days=3)).strftime('%B %d, %Y'),
        'tracking_id': cve_data.get('tracking_id', f'CTI-{today.strftime("%Y-%m%d")}-001'),
        'classification': cve_data.get('classification', 'Internal - Confidential')
        # 'upgrade_guide_url': cve_data.get('upgrade_guide_url', '#'),
    }
    
    return template.render(**context)

def cveEmailAutomation(cve_list):
    local_file_path = './supportFile/cveTicket'
    downloadFileFromSharepoint("ITSecurityLibrary", "INTELLIGENCE HUB/Reports/Product Vulnerability (CVE)/CVE Tracker.xlsx", "./", local_file_path)

    wb = load_workbook(filename = local_file_path + ".xlsx")

    now_year = datetime.now().year
    now_month_day = datetime.now().strftime("%m")

    sheet_name = f"CVE Ticket Tracker {now_year}"

    ws = wb[sheet_name]
    row_count = 16

    if ws.cell(row=row_count, column=2).value == None:
        id_value = f'CTI-{now_year}-{now_month_day}-001'
    else:
        last_val = 1
        while True:
            id_value = ws.cell(row=row_count, column=2).value
            cve_value = ws.cell(row=row_count, column=3).value
            if id_value == None and cve_value == None:
                break
            elif id_value == None and cve_value != None:
                row_count += 1
            elif id_value != None and cve_value != None:
                last_val += 1
                row_count += 1
    
        id_value = f'CTI-{now_year}-{now_month_day}-{last_val:03d}'

    prod_name = list(cve_list.keys())[0]

    final_cve_dict = {
        'product_name': prod_name.title(),
        'risk_context': "",
        'cves': [],
        'remediation_fixes': [],
        'mitigations': [],
        'risk_context': [],
        'vendor_advisory_url': [],
        'timeline_actions': [
            {
                'description': 'CTI Team Detect CVE',
                'owner': 'CTI Team',
                'due_date': (datetime.now()).strftime('%b %d, %Y'),
                'critical': False
            },
            {
                'description': 'Acknowledge Receipt',
                'owner': 'Product Owner',
                'due_date': (datetime.now() + timedelta(days=1)).strftime('%b %d, %Y'),
                'critical': False
            },
            {
                'description': 'Submit Remediation Plan',
                'owner': 'Product Owner',
                # 'due_date': (datetime.now() + timedelta(days=2)).strftime('%b %d, %Y'),
                'due_date': "",
                'critical': False
            },
            {
                'description': 'Complete Patching/Remediation',
                'owner': 'Product Owner',
                # 'due_date': (datetime.now() + timedelta(days=60)).strftime('%b %d, %Y'),
                'due_date': "",
                'critical': True
            },
            {
                'description': 'Verification',
                'owner': 'CTI Team',
                'due_date': "Maximum Day + 3 After Complete Patching",
                'critical': False
            }
        ],
        'tracking_id': id_value
    }

    risk_str = ""
    temp_risk = []
    report_list = []
    for cve in cve_list[prod_name]:
        cve_data = llmCveValidator(cve)
        print("CVE DATA:")
        print(cve_data)
        print("")

        # 'cve_data' data
        # {'product_name': 'Microsoft Dynamics 365 (on-premises)', 'summary': 'Unauthorized attackers can disclose sensitive information over a network.', 'executive_summary': 'A vulnerability in Microsoft Dynamics 365 (on-premises) allows unauthorized disclosure of sensitive information. This poses a risk to data confidentiality and could lead to compliance issues.', 'risk_context': 'The vulnerability in Microsoft Dynamics 365 (on-premises) could lead to unauthorized access to sensitive information, impacting business operations and customer trust. Organizations using this software may face compliance violations, particularly under GDPR Article 32, which mandates the protection of personal data. Immediate actions should focus on assessing the exposure and implementing compensating controls to mitigate risks until a patch is available. The lack of a current solution necessitates heightened vigilance and proactive measures to protect sensitive data. Organizations should prioritize understanding the scope of the vulnerability and its potential impact on their operations. This includes evaluating the types of data that could be exposed and the potential consequences of such exposure. Additionally, businesses must consider the legal and reputational implications of a data breach, especially in regulated industries. Implementing robust monitoring and access controls can help detect and prevent unauthorized access, while segmentation and authentication measures can limit the potential damage. It is crucial to maintain open communication with stakeholders and ensure that all relevant parties are aware of the risks and the steps being taken to address them.', 'primary_remediation_action': 'Upgrade to version 9.1.41.07 or above.', 'alternative_remediation_action': ['Restrict network access to trusted IP addresses only.', 'Implement enhanced logging and monitoring for unauthorized access attempts.', 'Conduct regular security audits and forensics analysis.', 'Segment sensitive data from less secure network areas.', 'Enforce multi-factor authentication for all users.', 'Disable unnecessary features that may expose sensitive data.', 'Regularly review and update access permissions.'], 'attack_complexity': 'Low', 'impact': 'Exposure of sensitive information to unauthorized actors.', 'recommended_timeline': 'MEDIUM (30 days)', 'analysis_timestamp': '2023-11-02T12:34:56Z'}

        # 'cve' data
        # {'microsoft%20365': [{'tech': 'microsoft%20365', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-62206', 'id': 'CVE-2025-62206', 'summary': 'Exposure of sensitive information to an unauthorized actor in Microsoft Dynamics 365 (on-premises) allows an unauthorized attacker to disclose information over a network.', 'published': '2025-11-11T17:59:28.307Z', 'reference': [{'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-62206', 'tags': ['vendor-advisory']}], 'affected': [{'Microsoft Dynamics 365 (on-premises) version 9.1': ['< 9.1.41.07']}], 'solutions': 'No solution yet', 'cve_score': 6.5, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C'}]}

        cve_detail = {
            'id': cve['id'],
            'severity': cve['cve_severity'],
            'impact': cve_data['summary'].replace("\xa0", " ")
        }
        final_cve_dict['cves'].append(cve_detail)

        report_list.append(cve)

        final_cve_dict['remediation_fixes'] = cve_data['primary_remediation_action']

        for alt in cve_data['alternative_remediation_action']:
            if alt not in final_cve_dict['mitigations']:
                final_cve_dict['mitigations'].append(alt)

        for ref in cve['reference']:
            tags_string = ""
            for tags in ref['tags']:
                tags_string += f" ({tags.strip()}), "
            
            tags_string = tags_string[:-2]

            if ref['url'] + tags_string not in final_cve_dict['vendor_advisory_url']:
                final_cve_dict['vendor_advisory_url'].append(ref['url'] + tags_string)

        if cve_data['risk_context'] not in temp_risk:
            risk_str += cve_data['risk_context'] + " || "
            temp_risk.append(cve_data['risk_context'])

    risk_str = dedupRiskContext(risk_str[:-3])

    final_cve_dict['risk_context'] = risk_str.replace("**", "\n")

    # "report_list" Data
    # [{'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-27232', 'id': 'CVE-2025-27232', 'summary': 'An authenticated Zabbix Super Admin can exploit the oauth.authorize action to read arbitrary files from the webserver leading to potential confidentiality loss.', 'published': '2025-12-01T12:55:51.722Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27282', 'tags': ''}], 'affected': [{'Zabbix': ['<= 7.4.2']}], 'solutions': 'Update the affected components to their respective fixed versions.', 'cve_score': 6.8, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'}, {'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-49642', 'id': 'CVE-2025-49642', 'summary': 'Library loading on AIX Zabbix Agent builds can be hijacked by local users with write access to the /home/cecuser directory.', 'published': '2025-12-01T13:03:38.752Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27283', 'tags': ''}], 'affected': [{'Zabbix': ['<= 6.0.36', '<= 7.0.5', '< 7.2.1']}], 'solutions': 'Update AIX Zabbix Agent packages to their respective fixed versions.', 'cve_score': 5.8, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N'}, {'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-49643', 'id': 'CVE-2025-49643', 'summary': 'An authenticated Zabbix user (including Guest) is able to cause disproportionate CPU load on the webserver by sending specially crafted parameters to /imgstore.php, leading to potential denial of service.', 'published': '2025-12-01T13:05:33.613Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27284', 'tags': ''}], 'affected': [{'Zabbix': ['<= 6.0.41', '<= 7.0.18', '<= 7.2.12', '<= 7.4.2']}], 'solutions': 'Update the affected components to their respective fixed versions.', 'cve_score': 6, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'}]

    print(report_list)
    while True:
        try:
            ws.cell(row=row_count, column=2).value = id_value
            break
        except AttributeError:
            row_count += 1
            continue

    affected_prod_str = ""
    affected_prod_temp = {}

    affected_ver_str = ""
    affected_ver_temp = {}

    total_row = row_count
    while True:
        try:
            ws.cell(row=total_row, column=2).value = id_value
            break
        except AttributeError:
            total_row += 1
            continue
    
    for cve in report_list:
        cve_id = cve['id']
        reported_date = datetime.strptime(cve['published'].split(".")[0], "%Y-%m-%dT%H:%M:%S").strftime("%H:%M:%S %m-%d-%Y")
        severity = cve['cve_severity']
        score = cve['cve_score']

        for data in cve['affected']:
            for prod_name, version_affect in data.items():
                for ver in version_affect:
                    if ver not in affected_ver_temp:
                        affected_ver_str += ver + " || "
                        affected_ver_temp[ver] = "1"

                if prod_name not in affected_prod_temp:
                    affected_prod_str += prod_name + " || "
                    affected_prod_temp[prod_name] = "1"

        try:
            ws.cell(row=total_row, column=2).value = id_value
            ws.cell(row=total_row, column=3).value = cve_id
            ws.cell(row=total_row, column=4).value = reported_date
            ws.cell(row=total_row, column=5).value = severity
            ws.cell(row=total_row, column=6).value = score
            ws.cell(row=total_row, column=7).value = affected_prod_str[:-4]
            ws.cell(row=total_row, column=8).value = affected_ver_str[:-4]
            ws.cell(row=total_row, column=9).value = cve['solutions']
        except AttributeError:
            total_row += 1
            continue
        
        affected_prod_str = ""
        affected_ver_str = ""
        
        total_row += 1

    ws.merge_cells(f"B{row_count}:B{total_row - 1}")

    wb.save("CVE Tracker.xlsx")

    uploadFileToSharepoint("ITSecurityLibrary", f"INTELLIGENCE%20HUB/Reports/Product%20Vulnerability%20(CVE)", f"CVE Tracker.xlsx")

    html_output = _generateCveEmail(final_cve_dict)
    
    with open('cve_notification_email.html', 'w', encoding='utf-8') as f:
        f.write(html_output)

    token = get_access_token()
    if token:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

    url = f'https://graph.microsoft.com/v1.0/users/{user_email}/messages'

    month_name = datetime.now().strftime("%B")

    email_data = {
        "subject":f"[ACTION REQUIRED] {len(final_cve_dict['cves'])} CVE(s) in {final_cve_dict['product_name'].title().replace('%20', ' ')}",
        "body": {
            "contentType": "html",
            "content": html_output
        },
        "ccRecipients": [
        {
            "emailAddress": {
                "address": "soc-analyst@cti-nexus.local"
            }
        }
    ]
    }

    response = requests.post(url, headers=headers, data=json.dumps(email_data))

    if response.status_code == 201:
        print("Draft created successfully.")
        draft_id = response.json()['id']
        print("Draft ID:", draft_id)
    
# data = {'nagios': [{'tech': 'nagios', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2024-13997', 'id': 'CVE-2024-13997', 'summary': 'Nagios XI versions prior to\xa02024R1.1.3\xa0contain a privilege escalation vulnerability in\xa0which an authenticated administrator could leverage the Migrate Server feature to obtain root privileges on the underlying XI host. By abusing the migration workflow, an admin-level attacker could execute actions outside the intended security scope of the application, resulting in full control of the operating system.', 'published': '2025-11-03T21:55:48.197Z', 'reference': [{'url': 'https://www.nagios.com/products/security/#nagios-xi', 'tags': ['vendor-advisory', 'patch']}, {'url': 'https://www.nagios.com/changelog/nagios-xi/', 'tags': ['release-notes', 'patch']}, {'url': 'https://www.vulncheck.com/advisories/nagios-xi-privilege-escalation-via-migrate-server-feature-to-root-on-host', 'tags': ['third-party-advisory']}], 'affected': [{'XI': []}], 'solutions': 'Nagios addresses this vulnerability as "Nagios XI was vulnerable to a privilege escalation wherein an administrator using the Migrate Server feature could become root on the XI server."', 'cve_score': 9.4, 'cve_severity': 'CRITICAL', 'cvss_vector': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'}, {'tech': 'nagios', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2024-13998', 'id': 'CVE-2024-13998', 'summary': 'Nagios XI versions prior to\xa02024R1.1.3, under certain circumstances, disclose sensitive user account information (including API keys and hashed passwords) to authenticated users who should not have access to that data. Exposure of API keys or password hashes could lead to account compromise, abuse of API privileges, or offline cracking attempts.\xa0CVE-2024-13995 addresses a similar vulnerability with a potentially incomplete fix for the underlying problem in earlier versions.', 'published': '2025-11-03T21:53:51.223Z', 'reference': [{'url': 'https://www.nagios.com/products/security/#nagios-xi', 'tags': ['vendor-advisory', 'patch']}, {'url': 'https://www.nagios.com/changelog/nagios-xi/', 'tags': ['release-notes', 'patch']}, {'url': 'https://www.vulncheck.com/advisories/nagios-xi-api-keys-and-hashed-password-authenticated-information-disclosure-2', 'tags': ['third-party-advisory']}], 'affected': [{'XI': []}], 'solutions': 'Nagios addresses this vulnerability as "Nagios XI could, under certain circumstances, leak other users\' API tokens or hashed passwords to other authenticated users."', 'cve_score': 6, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'}]}

# cveEmailAutomation(data)
