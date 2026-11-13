import requests,re,asyncio,os,json,html
from datetime import datetime
from packaging.version import Version
from modules import dbMongo

def extract_date(date_string):
    # Convert to datetime object and format it to 'YYYY-MM-DD'
    try:
        date_obj = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%fZ')
    except ValueError:
        # Fallback if no fractional seconds are present
        date_obj = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%SZ')
    return date_obj.strftime('%Y-%m-%d')

def create_offset_data(lib_system, lib_name, advisory_id, modified_date):
    return {
        "LibrarySystem": lib_system,
        "LibraryName": lib_name,
        "AdvisoryID": advisory_id,
        "ModifiedDate": modified_date
    }

def save_to_txt(filename, content):
    with open(filename, 'w') as file:
        file.write(json.dumps(content, indent=4))

def read_from_txt(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            return json.load(file)
    return []

def update_offset_data(lib_system, lib_name, advisory_id, formatted_modified):
    folder_name = 'offset'
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    
    filename = os.path.join(folder_name, 'techstack_pypi_offset.txt')
    offset_data = create_offset_data(lib_system, lib_name, advisory_id, formatted_modified)
    saved_data = read_from_txt(filename)
    
    # Check for duplicates
    for entry in saved_data:
        if entry['AdvisoryID'] == advisory_id and entry['ModifiedDate'] == formatted_modified:
            return None
    
    saved_data.append(offset_data)
    save_to_txt(filename, saved_data)
    return offset_data

# List of packages
package_list = [
    "requests",
    "selenium",
    "pandas"
]

def normalize_version(version):
    return re.sub(r'[^0-9.]+', '', version)

# Iterate through each package in the list
for package in package_list:
    # Send a GET request to PYPI API for the package
    url = requests.get(f'https://api.deps.dev/v3/systems/pypi/packages/{package}').json()

    # Get and sort the versions
    versions = sorted([normalize_version(v['versionKey']['version']) for v in url['versions']], key=Version, reverse=True)

    # Loop through the versions and process advisories
    for raw_json in url['versions'][:5]:
        version = raw_json['versionKey']['version']
        # print(f"Package: {package}, Version: {version}")

        # Send a GET request for each version of the package
        url_package_version = requests.get(f'https://api.deps.dev/v3/systems/pypi/packages/{package}/versions/{version}').json()

        # If the version has advisory keys, process them
        if len(url_package_version["advisoryKeys"]) != 0:
            for advisory_id in url_package_version['advisoryKeys']:
                advisory_id_value = advisory_id['id']

                # Send a GET request to fetch the advisory details
                url_advisory = requests.get(f'https://api.osv.dev/v1/vulns/{advisory_id_value}').json()

                for affected_item in url_advisory['affected']:
                    # Check if 'last_known_affected_version_range' exists in 'database_specific'
                    if 'last_known_affected_version_range' in affected_item['database_specific']:
                        last_known_affected_version_range = affected_item['database_specific']['last_known_affected_version_range']
                        # Convert HTML-encoded entities to plain text
                        last_known_affected_version_range = html.unescape(last_known_affected_version_range)
                        # Remove '<' and '<=' from the string
                        last_known_affected_version_range = last_known_affected_version_range.replace("<=", "").replace("<", "").strip()
                        # print(last_known_affected_version_range)

                # Convert the 'published' and 'modified' fields to 'YYYY-MM-DD'
                formatted_published = extract_date(url_advisory['published'])
                formatted_modified = extract_date(url_advisory['modified'])

                advisory_package_data = {
                    "Id": url_advisory['id'],
                    "Details": url_advisory['details'],
                    "Aliases": url_advisory.get('aliases', []),
                    "Modified": formatted_modified,
                    "Published": formatted_published,
                    "References": url_advisory.get('references', []),
                    # "Affected": last_known_affected_version_range
                }
                # Print the advisory package data
                # print(json.dumps(advisory_package_data, indent=4))
        
                # Send the alert
                json_library = {
                    "lib_sytem" : raw_json['versionKey']['system'],
                    "lib_name" : raw_json['versionKey']['name'],
                    "version" : raw_json['versionKey']['version'],
                    "advisory" : {
                        "id" : url_advisory['id'],
                        "desc" : url_advisory['details'],
                        "publish" : url_advisory['published'],
                        "modified" : url_advisory['modified'],
                        "remediation" : [],
                        "alias" : url_advisory.get('aliases', []),
                        # "fixed" : url_advisory['affected']['ranges']['events']['fixed'],
                        # "affect" : "<= latest version == affected"
                    }
                }
                # print(url_advisory['affected']['ranges']['events']['fixed'])

                # Extract and print the latest "fixed" version
                latest_fixed_version = None  # Initialize as None

                for affected_entry in url_advisory['affected']:
                    for range_entry in affected_entry.get('ranges', []):
                        for event in range_entry.get('events', []):
                            if 'fixed' in event:
                                fixed_version = event['fixed']
                                
                                # Update if it's the latest version
                                if latest_fixed_version is None or fixed_version > latest_fixed_version:
                                    latest_fixed_version = fixed_version

                msg_data = f"""
    === <b>NEW ADVISORYS UPDATE FOR PYPI</b> ===
<b>Name</b> : {json_library['lib_name']}
<b>Advisory ID</b> : {json_library['advisory']['id']}
<b>Details</b> : {json_library['advisory']['desc'][:150]}
<b>Aliases</b> : {json_library['advisory']['alias']}
<b>Published</b> :{formatted_published}
<b>Modified</b> : {formatted_modified}
<b>Fixed Version</b> : {latest_fixed_version}
<b>Affected Version</b> : Lower than {latest_fixed_version} Version
    """

                # Save the offset data
                if update_offset_data(json_library['lib_sytem'], json_library['lib_name'], json_library['advisory']['id'], formatted_modified):
                    print(msg_data)
                    dbMongo.upsert_alert("tech_stack_advisory",
                                         f"{json_library['lib_sytem']}:{json_library['lib_name']}:{json_library['advisory']['id']}:{formatted_modified}",
                                         msg_data.strip(), source="PYPI", title=json_library['lib_name'])
