from datetime import datetime, timedelta
from modules.techstackStore import get_tech_list
from modules.jobQueue import push_job
from modules.offsetStore import is_new_and_mark
import requests, re, os

current_file = os.path.basename(__file__).split(".")[0]
list_of_tech = get_tech_list()

def cisa_catalog_feed():
    vuln_list = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json').json()
    now_date = datetime.strftime(datetime.now(), '%Y-%m-%d')
    last_day_date = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')

    for vuln in vuln_list['vulnerabilities']:
        if vuln['dateAdded'] == now_date or vuln['dateAdded'] == last_day_date:
            cve_id = vuln['cveID']
            raw_link = re.findall("https:\/\/[a-zA-Z0-9\-._~:\/?#\[\]@!$&\'()*+,;=%]+" , vuln['notes'])

            cve_link = ""
            for link in raw_link:
                cve_link += link + " || "
            cve_link = cve_link[:-3]

            key = cve_id + str(vuln['dateAdded'])
            if is_new_and_mark(current_file, key):
                vendor_name = vuln['vendorProject']
                product_name = vuln['product']
                cve_name = vuln['vulnerabilityName']
                cve_desc = vuln['shortDescription']
                cve_mitigation = vuln['requiredAction']

                related_tech_stack = False
                for tech in list_of_tech:
                    if re.search(f"{str(tech).lower().strip()}", str(vendor_name).lower()):
                        vendor_name += " [<b>Might Applicable to Organization!</b>]"
                        related_tech_stack = True
                        break

                if related_tech_stack:
                    push_job({
                        'title': cve_id,
                        'url': cve_link,
                        'posted_on': datetime.now().date()
                    }, "NEW CISA CATALOG VULNERABILITY FROM CISA (RELATED)")
                else:
                    push_job({
                        'title': cve_id,
                        'url': cve_link,
                        'posted_on': datetime.now().date()
                    }, "NEW CISA CATALOG VULNERABILITY FROM CISA")
        else: continue

cisa_catalog_feed()
