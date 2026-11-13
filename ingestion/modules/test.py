from openpyxl import load_workbook
from datetime import datetime


local_file_path = './supportFile/cveTicket'

wb = load_workbook(filename = local_file_path + ".xlsx")

now_year = datetime.now().year
now_month_day = datetime.now().strftime("%m")

sheet_name = f"CVE Ticket Tracker {now_year}"

ws = wb[sheet_name]
row_count = 8

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
json_data = [{'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-27232', 'id': 'CVE-2025-27232', 'summary': 'An authenticated Zabbix Super Admin can exploit the oauth.authorize action to read arbitrary files from the webserver leading to potential confidentiality loss.', 'published': '2025-12-01T12:55:51.722Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27282', 'tags': ''}], 'affected': [{'Zabbix': ['<= 7.4.2']}], 'solutions': 'Update the affected components to their respective fixed versions.', 'cve_score': 6.8, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'}, {'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-49642', 'id': 'CVE-2025-49642', 'summary': 'Library loading on AIX Zabbix Agent builds can be hijacked by local users with write access to the /home/cecuser directory.', 'published': '2025-12-01T13:03:38.752Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27283', 'tags': ''}], 'affected': [{'Zabbix': ['<= 6.0.36', '<= 7.0.5', '< 7.2.1']}], 'solutions': 'Update AIX Zabbix Agent packages to their respective fixed versions.', 'cve_score': 5.8, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:H/VA:H/SC:N/SI:N/SA:N'}, {'tech': 'zabbix', 'link': 'https://nvd.nist.gov/vuln/detail/CVE-2025-49643', 'id': 'CVE-2025-49643', 'summary': 'An authenticated Zabbix user (including Guest) is able to cause disproportionate CPU load on the webserver by sending specially crafted parameters to /imgstore.php, leading to potential denial of service.', 'published': '2025-12-01T13:05:33.613Z', 'reference': [{'url': 'https://support.zabbix.com/browse/ZBX-27284', 'tags': ''}], 'affected': [{'Zabbix': ['<= 6.0.41', '<= 7.0.18', '<= 7.2.12', '<= 7.4.2']}], 'solutions': 'Update the affected components to their respective fixed versions.', 'cve_score': 6, 'cve_severity': 'MEDIUM', 'cvss_vector': 'CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N'}]

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

for cve in json_data:
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

    total_row += 1

ws.merge_cells(f"B{row_count}:B{total_row - 1}")

wb.save(local_file_path + ".xlsx")

# print(id_value)