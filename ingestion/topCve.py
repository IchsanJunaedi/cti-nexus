import requests, time, re
from datetime import datetime
from modules import dbMongo
from modules.techstackStore import get_tech_list

curr_month = datetime.today().strftime("%Y-%m")

cve_docs = dbMongo.get_cve_mentions(curr_month)
list_of_tech = get_tech_list()

# Sort by counter descending
cve_list = sorted(cve_docs, key=lambda d: d.get('counter', 0), reverse=True)

msg_data = f"""
    === <b>TOP 10 MOST MENTIONED CVE IN THE LAST 7 DAYS</b> ===
<blockquote>"""

send_status = False
counter_cve = 0

for cve_doc in cve_list:
    cve_id = cve_doc['cve_id']
    update_time = cve_doc.get('update_time', '')
    counter = cve_doc.get('counter', 0)

    try:
        days_since = int((datetime.today() - datetime.strptime(update_time, "%Y-%m-%d")).days)
    except Exception:
        continue

    if days_since > 7:
        continue
    if counter_cve == 10:
        break
    if counter == 0:
        continue

    cve_prod_req = requests.get(f"https://cveawg.mitre.org/api/cve/{str(cve_id).upper()}").json()
    try:
        if cve_prod_req['message'] == "The cve record for the cve id does not exist.":
            continue
    except Exception:
        pass

    base_score = 0
    try:
        for cvss in cve_prod_req['containers']['cna']['metrics']:
            for key in dict(cvss).keys():
                if key in ("scenarios", "format"):
                    continue
                if base_score <= cvss[key]['baseScore']:
                    base_score = cvss[key]['baseScore']
    except KeyError:
        try:
            for adp in cve_prod_req['containers']['adp']:
                for cvss in adp['metrics']:
                    for key in dict(cvss).keys():
                        if key in ("scenarios", "format", "other"):
                            continue
                        if base_score <= cvss[key]['baseScore']:
                            base_score = cvss[key]['baseScore']
        except KeyError:
            base_score = "N/A"

    product_name = ""
    vendor_name = ""
    temp_product_name = []

    try:
        for data in cve_prod_req['containers']['adp']:
            for affected in data['affected']:
                for version in affected['versions']:
                    if version['status'] == "affected":
                        if str(affected['product']).lower() in temp_product_name or str(affected['product']).lower() == "n/a":
                            continue
                        product_name += f"{affected['product']} || "
                        temp_product_name.append(str(affected['product']).lower())
                    vendor_name = str(affected['vendor']).lower()
    except Exception:
        pass

    try:
        for affected in cve_prod_req['containers']['cna']['affected']:
            for version in affected['versions']:
                if version['status'] == "affected":
                    if str(affected['product']).lower() in temp_product_name or str(affected['product']).lower() == "n/a":
                        continue
                    product_name += f"{affected['product']} || "
                    temp_product_name.append(str(affected['product']).lower())
                if len(vendor_name) == 0 or vendor_name == "n/a":
                    vendor_name = affected['vendor']
    except Exception:
        pass

    if len(product_name) == 0 and len(vendor_name) == 0:
        product_name = "Unknown"
        vendor_name = "Unknown"
    else:
        product_name = product_name[:-4] if product_name.endswith(" || ") else product_name

    applicable_status = ""
    for tech in list_of_tech:
        if re.search(f"{str(tech).lower().strip()}", str(vendor_name).lower()):
            applicable_status = "[<b>Might Applicable to Organization!</b>]"
            break

    score_cat = "None"
    try:
        score = float(base_score)
        if 0.13 <= score <= 3.9:
            score_cat = "Low"
        elif 4.0 <= score <= 6.9:
            score_cat = "Medium"
        elif 7.0 <= score <= 8.9:
            score_cat = "High"
        elif score >= 9.0:
            score_cat = "Critical"
    except (ValueError, TypeError):
        score_cat = "None"

    msg_data += (
        f"\n    - <code>{str(cve_id).upper()}</code> ({base_score} <b>{score_cat}</b>), "
        f"Total Mentioned: {counter}\n"
        f"        Product Name: {product_name}\n"
        f"        Vendor Name: {vendor_name} {applicable_status}\n"
    )

    # Reset counter after including in weekly report
    dbMongo.reset_cve_counter(curr_month, cve_id)

    send_status = True
    counter_cve += 1

if not send_status:
    exit()

msg_data += "</blockquote>"
print(msg_data)
dbMongo.upsert_alert("top_cve_weekly", datetime.today().strftime("%Y-%m-%d"), msg_data.strip(), source="Top CVE")
