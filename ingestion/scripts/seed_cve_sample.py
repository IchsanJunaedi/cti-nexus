"""Seed script: insert sample CVE records into news_db.cve_tracker for UI testing."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pymongo import MongoClient, UpdateOne
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

nc  = cfg['news_db']
uri = f"mongodb://{nc['user']}:{nc['pass']}@{nc['ip']}/?authSource={nc['db']}"
client = MongoClient(uri)
col    = client[nc['db']]['cve_tracker']
col.create_index("cve_id", unique=True, background=True)

SAMPLES = [
    {
        "cve_id":       "CVE-2025-0282",
        "tech":         "palo alto networks",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
        "summary":      "A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, "
                        "Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways "
                        "before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.",
        "published":    "2025-01-08T17:15:35.000",
        "reference":    [{"url": "https://forums.ivanti.com/s/article/CVE-2025-0282", "tags": ["Vendor Advisory"]}],
        "affected":     [{"Ivanti Connect Secure": ["< 22.7R2.5"]}],
        "solutions":    "Upgrade to Ivanti Connect Secure 22.7R2.5 or later.",
        "cve_score":    9.0,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2025-01-09",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/rapid7/metasploit-framework/pull/19434", "source": "GitHub", "type": "metasploit_module"},
        ],
    },
    {
        "cve_id":       "CVE-2024-55591",
        "tech":         "fortigate",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-55591",
        "summary":      "An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] "
                        "affecting FortiOS version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through "
                        "7.0.19 and 7.2.0 through 7.2.12 allows a remote attacker to gain super-admin privileges "
                        "via crafted requests to Node.js websocket module.",
        "published":    "2025-01-14T14:15:30.000",
        "reference":    [{"url": "https://fortiguard.fortinet.com/psirt/FG-IR-24-535", "tags": ["Vendor Advisory"]}],
        "affected":     [{"FortiOS": ["< 7.0.17"]}, {"FortiProxy": ["< 7.2.13"]}],
        "solutions":    "Upgrade to FortiOS 7.0.17 or later. Apply workaround by disabling HTTP/HTTPS management.",
        "cve_score":    9.6,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "last_updated": "2025-01-15",
        "poc_available": False,
        "pocs": [],
    },
    {
        "cve_id":       "CVE-2024-47575",
        "tech":         "fortigate",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-47575",
        "summary":      "A missing authentication for critical function vulnerability [CWE-306] in FortiManager "
                        "fgfmd daemon allows a remote unauthenticated attacker to execute arbitrary code or commands "
                        "via specially crafted requests.",
        "published":    "2024-10-23T18:15:00.000",
        "reference":    [{"url": "https://fortiguard.fortinet.com/psirt/FG-IR-24-423", "tags": ["Vendor Advisory"]}],
        "affected":     [{"FortiManager": ["< 7.6.1"]}],
        "solutions":    "Upgrade to FortiManager 7.6.1 or later. Apply IP allow-list workaround.",
        "cve_score":    9.8,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2024-10-24",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/exploit-db/exploitdb/blob/main/exploits/multiple/remote/51905.py", "source": "ExploitDB", "type": "exploit"},
        ],
    },
    {
        "cve_id":       "CVE-2025-21293",
        "tech":         "microsoft 365",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2025-21293",
        "summary":      "Active Directory Domain Services Elevation of Privilege Vulnerability. An attacker who "
                        "successfully exploited this vulnerability could gain SYSTEM privileges.",
        "published":    "2025-01-14T18:15:00.000",
        "reference":    [{"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293", "tags": ["Patch", "Vendor Advisory"]}],
        "affected":     [{"Windows Server": ["<= 2025"]}],
        "solutions":    "Apply Microsoft January 2025 Patch Tuesday updates.",
        "cve_score":    8.8,
        "cve_severity": "HIGH",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2025-01-15",
        "poc_available": False,
        "pocs": [],
    },
    {
        "cve_id":       "CVE-2024-43451",
        "tech":         "microsoft 365",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-43451",
        "summary":      "NTLM Hash Disclosure Spoofing Vulnerability. An attacker can steal NTLMv2 hashes by "
                        "tricking the user into interacting with a malicious file in Windows Explorer.",
        "published":    "2024-11-12T18:15:00.000",
        "reference":    [{"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43451", "tags": ["Patch", "Vendor Advisory"]}],
        "affected":     [{"Windows": ["<= 11 23H2"]}],
        "solutions":    "Apply Microsoft November 2024 Patch Tuesday updates.",
        "cve_score":    6.5,
        "cve_severity": "MEDIUM",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "last_updated": "2024-11-13",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/BlackAngel-00/CVE-2024-43451", "source": "GitHub", "type": "poc"},
        ],
    },
    {
        "cve_id":       "CVE-2024-6387",
        "tech":         "wazuh",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
        "summary":      "A signal handler race condition was found in OpenSSH's server (sshd) in glibc-based Linux "
                        "systems. This allows unauthenticated remote code execution as root on vulnerable systems. "
                        "The vulnerability is dubbed 'regreSSHion'.",
        "published":    "2024-07-01T13:15:00.000",
        "reference":    [
            {"url": "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt", "tags": ["Exploit", "Technical Description"]},
            {"url": "https://www.openssh.com/security.html", "tags": ["Vendor Advisory"]},
        ],
        "affected":     [{"OpenSSH": ["< 9.8p1"]}],
        "solutions":    "Upgrade OpenSSH to version 9.8p1 or apply vendor mitigations.",
        "cve_score":    8.1,
        "cve_severity": "HIGH",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2024-07-02",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/zgzhang/cve-2024-6387-poc", "source": "GitHub", "type": "poc"},
            {"url": "https://github.com/rapid7/metasploit-framework/pull/19049", "source": "GitHub", "type": "metasploit_module"},
        ],
    },
    {
        "cve_id":       "CVE-2024-21413",
        "tech":         "outlook",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-21413",
        "summary":      "Microsoft Outlook Remote Code Execution Vulnerability. The vulnerability allows an attacker "
                        "to bypass the Protected View and execute code in edit mode via a specially crafted email. "
                        "Also known as MonikerLink bug.",
        "published":    "2024-02-13T18:02:00.000",
        "reference":    [{"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413", "tags": ["Patch", "Vendor Advisory"]}],
        "affected":     [{"Microsoft Outlook": ["< 2402"]}],
        "solutions":    "Apply Microsoft February 2024 Patch Tuesday updates.",
        "cve_score":    9.8,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2024-02-14",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability", "source": "GitHub", "type": "exploit"},
        ],
    },
    {
        "cve_id":       "CVE-2024-38094",
        "tech":         "microsoft 365",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-38094",
        "summary":      "Microsoft SharePoint Remote Code Execution Vulnerability. An authenticated attacker with "
                        "Site Owner permissions can use the vulnerability to inject arbitrary code and execute this "
                        "code in the context of SharePoint Server.",
        "published":    "2024-07-09T17:15:00.000",
        "reference":    [{"url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38094", "tags": ["Patch", "Vendor Advisory"]}],
        "affected":     [{"Microsoft SharePoint Server": ["<= 2019"]}],
        "solutions":    "Apply Microsoft July 2024 Patch Tuesday updates.",
        "cve_score":    7.2,
        "cve_severity": "HIGH",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2024-07-10",
        "poc_available": False,
        "pocs": [],
    },
    {
        "cve_id":       "CVE-2024-3400",
        "tech":         "palo alto networks",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
        "summary":      "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks "
                        "PAN-OS software for specific PAN-OS versions and distinct feature configurations may "
                        "enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "published":    "2024-04-12T08:15:00.000",
        "reference":    [{"url": "https://security.paloaltonetworks.com/CVE-2024-3400", "tags": ["Vendor Advisory"]}],
        "affected":     [{"PAN-OS": ["< 11.1.2-h3"]}],
        "solutions":    "Upgrade to PAN-OS 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3. Disable GlobalProtect if not required.",
        "cve_score":    10.0,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "last_updated": "2024-04-13",
        "poc_available": True,
        "pocs": [
            {"url": "https://github.com/ihebski/CVE-2024-3400", "source": "GitHub", "type": "poc"},
            {"url": "https://github.com/rapid7/metasploit-framework/pull/19049", "source": "GitHub", "type": "metasploit_module"},
        ],
    },
    {
        "cve_id":       "CVE-2025-23006",
        "tech":         "nessus",
        "link":         "https://nvd.nist.gov/vuln/detail/CVE-2025-23006",
        "summary":      "Pre-authentication deserialization of untrusted data vulnerability in SMA1000 series "
                        "Appliance Management Console (AMC) and Central Management Console (CMC). This vulnerability "
                        "has been possibly exploited in the wild.",
        "published":    "2025-01-22T10:15:00.000",
        "reference":    [{"url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0002", "tags": ["Vendor Advisory"]}],
        "affected":     [{"SonicWall SMA1000": ["<= 12.4.3-02804"]}],
        "solutions":    "Upgrade to firmware version 12.4.3-02854 or higher.",
        "cve_score":    9.8,
        "cve_severity": "CRITICAL",
        "cvss_vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "last_updated": "2025-01-23",
        "poc_available": False,
        "pocs": [],
    },
]

ops = [UpdateOne({"cve_id": s["cve_id"]}, {"$setOnInsert": s}, upsert=True) for s in SAMPLES]
result = col.bulk_write(ops, ordered=False)
client.close()

print(f"Inserted {result.upserted_count} new | matched {result.matched_count} existing out of {len(SAMPLES)} samples.")
