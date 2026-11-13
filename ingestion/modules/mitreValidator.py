import requests, json
from datetime import datetime, timedelta


def mitreJsonURL(url):
    raw_json_data = requests.get(url).json()

    curr_date = datetime.now()
    count = 0
    final_json = {}

    whitelist_type = [
        "x-mitre-data-component"
    ]

    for data in raw_json_data['objects']:
        try:
            if data['revoked' ] == True:
                continue
        except KeyError:
            pass

        data_created_time = datetime.strptime(data['created'], "%Y-%m-%dT%H:%M:%S.%fZ")
        if (curr_date - data_created_time).days <= 7:
            if data['type'] in whitelist_type:
                continue

            try:
                final_json[data['type']]
            except KeyError:
                final_json[data['type']] = []
            
            if data['type'] == "attack-pattern":
                tech_name = data['name']
                tech_desc = data['description']

                kill_chain_phase_string = ""
                for phase in data['kill_chain_phases']:
                    if phase["kill_chain_name"] == "mitre-attack":
                        kill_chain_phase_string += phase['phase_name'] + " || "
                kill_chain_phase_string = kill_chain_phase_string[:-4]        

                affected_platforms_string = ""
                try:
                    for platform in data['x_mitre_platforms']:
                        affected_platforms_string += platform + " || "
                    affected_platforms_string = affected_platforms_string[:-4]
                except KeyError:
                    affected_platforms_string = ""

                data_sources_string = ""
                try:
                    for ds in data['x_mitre_data_sources']:
                        data_sources_string += ds + " || "
                    data_sources_string = data_sources_string[:-4]
                except KeyError:
                    data_sources_string = ""

                ttp_domain = ""
                for domain in data['x_mitre_domains']:
                    ttp_domain += domain + " || "
                ttp_domain = ttp_domain[:-4]

                tech_id = ""
                tech_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        tech_id = ref['external_id']
                        tech_url = ref['url']

                parent_technique_id = ""
                parent_technique_name = ""
                parent_technique_url = ""
                parent_technique_desc = ""
                if data['x_mitre_is_subtechnique'] == True:
                    parent_technique_id = str(tech_id).split(".")[0]
                    for data2 in raw_json_data['objects']:
                        if data2['type'] == "attack-pattern":
                            for ref in data2['external_references']:
                                if ref["source_name"] == "mitre-attack" and ref['external_id'] == parent_technique_id:
                                    parent_technique_name = data2['name']
                                    parent_technique_desc = data2['description']
                                    parent_technique_url = ref['url']

                json_data = {
                    "tech_id": tech_id,
                    "tech_name": tech_name,
                    "tech_url": tech_url,
                    "tech_desc": tech_desc,
                    "parent_technique_id": parent_technique_id,
                    "parent_technique_name": parent_technique_name,
                    "parent_technique_url": parent_technique_url,
                    "parent_technique_desc": parent_technique_desc,
                    "kill_chain" : kill_chain_phase_string,
                    "affected_platform": affected_platforms_string,
                    "data_sources": data_sources_string,
                    "ttp_domain": ttp_domain,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

            elif data['type'] == "malware":
                software_name = data['name']
                software_desc = data['description']

                software_id = ""
                software_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        software_id = ref['external_id']
                        software_url = ref['url']

                affected_platforms_string = ""
                try:
                    for platform in data['x_mitre_platforms']:
                        affected_platforms_string += platform + " || "
                    affected_platforms_string = affected_platforms_string[:-4]
                except KeyError:
                    pass

                software_domain = ""
                for domain in data['x_mitre_domains']:
                    software_domain += domain + " || "
                software_domain = software_domain[:-4]

                software_aliases = ""
                try:
                    for alias in data['x_mitre_aliases']:
                        software_aliases += alias + " || "
                    software_aliases = software_aliases[:-4]
                except KeyError:
                    pass

                json_data = {
                    "software_name": software_name,
                    "software_id": software_id,
                    "software_url": software_url,
                    "software_desc": software_desc,
                    "affected_platform": affected_platforms_string,
                    "software_domain": software_domain,
                    "software_aliases": software_aliases,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

            elif data['type'] == "intrusion-set":
                group_name = data['name']
                group_desc = data['description']

                group_id = ""
                group_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        group_id = ref['external_id']
                        group_url = ref['url']

                group_aliases = ""
                try:
                    for alias in data['aliases']:
                        group_aliases += alias + " || "
                    group_aliases = group_aliases[:-4]
                except KeyError:
                    pass

                group_domain = ""
                for domain in data['x_mitre_domains']:
                    group_domain += domain + " || "
                group_domain = group_domain[:-4]

                json_data = {
                    "group_name": group_name,
                    "group_id": group_id,
                    "group_url": group_url,
                    "group_desc": group_desc,
                    "group_domain": group_domain,
                    "group_aliases": group_aliases,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

            elif data['type'] == "campaign":
                campaign_name = data['name']
                campaign_desc = data['description']

                campaign_id = ""
                campaign_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        campaign_id = ref['external_id']
                        campaign_url = ref['url']

                campaign_domain = ""
                for domain in data['x_mitre_domains']:
                    campaign_domain += domain + " || "
                campaign_domain = campaign_domain[:-4]

                campaign_aliases = ""
                try:
                    for alias in data['aliases']:
                        campaign_aliases += alias + " || "
                    campaign_aliases = campaign_aliases[:-4]
                except KeyError:
                    pass

                campaign_first_seen = data['first_seen']
                campaign_last_seen = data['last_seen']

                json_data = {
                    "campaign_name": campaign_name,
                    "campaign_desc": campaign_desc,
                    "campaign_first_seen": campaign_first_seen,
                    "campaign_last_seen": campaign_last_seen,
                    "campaign_url": campaign_url,
                    "campaign_id": campaign_id,
                    "campaign_domain": campaign_domain,
                    "campaign_aliases": campaign_aliases,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1
                
            elif data['type'] == "tool":
                software_name = data['name']
                software_desc = data['description']

                software_id = ""
                software_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        software_id = ref['external_id']
                        software_url = ref['url']

                affected_platforms_string = ""
                try:
                    for platform in data['x_mitre_platforms']:
                        affected_platforms_string += platform + " || "
                    affected_platforms_string = affected_platforms_string[:-4]
                except KeyError:
                    pass

                software_domain = ""
                for domain in data['x_mitre_domains']:
                    software_domain += domain + " || "
                software_domain = software_domain[:-4]

                software_aliases = ""
                try:
                    for alias in data['x_mitre_aliases']:
                        software_aliases += alias + " || "
                    software_aliases = software_aliases[:-4]
                except KeyError:
                    pass

                json_data = {
                    "software_name": software_name,
                    "software_id": software_id,
                    "software_url": software_url,
                    "software_desc": software_desc,
                    "affected_platform": affected_platforms_string,
                    "software_domain": software_domain,
                    "software_aliases": software_aliases,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

            elif data['type'] == "x-mitre-tactic":
                tactic_name = data['name']
                tactic_desc = data['description']

                tactic_id = ""
                tactic_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        tactic_id = ref['external_id']
                        tactic_url = ref['url']

                tactic_domain = ""
                for domain in data['x_mitre_domains']:
                    tactic_domain += domain + " || "
                tactic_domain = tactic_domain[:-4]

                json_data = {
                    "tactic_name": tactic_name,
                    "tactic_desc": tactic_desc,
                    "tactic_url": tactic_url,
                    "tactic_id": tactic_id,
                    "tactic_domain": tactic_domain,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1
            
            elif data['type'] == "course-of-action":
                mitigation_name = data['name']
                mitigation_desc = data['description']

                mitigation_id = ""
                mitigation_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        mitigation_id = ref['external_id']
                        mitigation_url = ref['url']
                
                mitigation_domain = ""
                for domain in data['x_mitre_domains']:
                    mitigation_domain += domain + " || "
                mitigation_domain = mitigation_domain[:-4]

                json_data = {
                    "mitigation_name": mitigation_name,
                    "mitigation_desc": mitigation_desc,
                    "mitigation_url": mitigation_url,
                    "mitigation_id": mitigation_id,
                    "mitigation_domain": mitigation_domain,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1
            
            elif data['type'] == "x-mitre-data-source":
                data_source_name = data['name']
                data_source_desc = data['description']

                data_source_id = ""
                data_source_url = ""
                for ref in data['external_references']:
                    if ref["source_name"] == "mitre-attack":
                        data_source_id = ref['external_id']
                        data_source_url = ref['url']

                data_source_platforms_string = ""
                try:
                    for platform in data['x_mitre_platforms']:
                        data_source_platforms_string += platform + " || "
                    data_source_platforms_string = data_source_platforms_string[:-4]
                except KeyError:
                    pass

                data_source_domain = ""
                for domain in data['x_mitre_domains']:
                    data_source_domain += domain + " || "
                data_source_domain = data_source_domain[:-4]

                collection_layers = ""
                for domain in data['x_mitre_collection_layers']:
                    collection_layers += domain + " || "
                collection_layers = collection_layers[:-4]

                json_data = {
                    "data_source_name": data_source_name,
                    "data_source_desc": data_source_desc,
                    "data_source_id": data_source_id,
                    "data_source_url": data_source_url,
                    "data_source_platforms_string": data_source_platforms_string,
                    "data_source_domain": data_source_domain,
                    "collection_layers": collection_layers,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

            elif data['type'] == "relationship":
                source_ref_id = data['source_ref']
                source_ref_name = ""

                target_ref_id = data['target_ref']
                target_ref_name = ""
                relationship_type = data['relationship_type']

                desc = data['description']

                for data2 in raw_json_data['objects']:
                    if data2['id'] == source_ref_id:
                        source_ref_name = data2['name']

                    if data2['id'] == target_ref_id:
                        target_ref_name = data2['name']
                
                json_data = {
                    "source_ref_id": source_ref_id,
                    "source_ref_name": source_ref_name,
                    "target_ref_id": target_ref_id,
                    "target_ref_name": target_ref_name,
                    "relationship_type": relationship_type,
                    "desc": desc,
                    "created_time": data_created_time.strftime("%d-%m-%Y %H:%M%:%S")
                }
                final_json[data['type']].append(json_data)
                count += 1

    # final_json['total_changes'] = count
    return final_json

def _format_course_of_action(items):
    paragraphs = []
    for item in items:
        para = (
            f"----- {item['mitigation_name']} ({item['mitigation_id']}) -----\n"
            f"{item['mitigation_url']}\n"
            f"{item['mitigation_desc']}\n\n"
            f"This mitigation applicable in:\n{item['mitigation_domain']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_malware(items):
    paragraphs = []
    for item in items:
        para = (
            f"----- {item['software_name']} ({item['software_aliases']}/{item['software_id']}) -----\n"
            f"{item['software_url']}\n"
            f"{item['software_desc']}\n\n"
            f"Affected plaftorm of this Malware is:\n{item['affected_platform']}\n\n"
            f"This Malware applicable in:\n{item['software_domain']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_tool(items):
    paragraphs = []
    for item in items:
        para = (
            f"----- {item['software_name']} ({item['software_aliases']}/{item['software_id']}) -----\n"
            f"{item['software_url']}\n"
            f"{item['software_desc']}\n\n"
            f"Affected plaftorm of this Tool is:\n{item['affected_platform']}\n\n"
            f"This Tool applicable in:\n{item['software_domain']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_attack_pattern(items):
    paragraphs = []
    for item in items:
        parent_info = (
            f"\n\nThis technique has a parent, {item['parent_tech_name']} ({item['parent_tech_id']}) "
            f"https://attack.mitre.org/techniques/{item['parent_tech_id'].replace('.', '/')}"
        ) if item.get('parent_tech_id') and item.get('parent_tech_name') else ""

        para = (
            f"----- {item['tech_name']} ({item['tech_id']}) -----\n"
            f"https://attack.mitre.org/techniques/{item['tech_id'].replace('.', '/')}\n"
            f"{item['tech_desc']}\n\n"
            f"This technique's attack chain is:\n{item['kill_chain']}\n\n"
            f"Affected plaftorm of this techniques is:\n{item['affected_platform']}\n\n"
            f"This technique applicable in:\n{item['ttp_domain']}\n\n"
            f"To detect this technique, consider to logging from {item['data_sources']}{parent_info}\n\n"
            f"This technique has a parent: {item['parent_technique_name']} ({item['parent_technique_id']})\n"
            f"{item['parent_technique_url']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_campaign(items):
    paragraphs = []
    for item in items:
        first_seen = datetime.strptime(item['campaign_first_seen'], "%Y-%m-%dT%H:%M:%S.%fZ")
        last_seen = datetime.strptime(item['campaign_last_seen'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S")
        last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S")

        para = (
            f"----- {item['campaign_name']} ({item['campaign_aliases']}/{item['campaign_id']}) -----\n"
            f"{item['campaign_url']}\n"
            f"{item['campaign_desc']}\n\n"
            f"This campaign first seen in {first_seen_str}\n"
            f"This campaign last seen in {last_seen_str}\n\n"
            f"This campaign applicable in:\n{item['campaign_domain']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_intrusion_set(items):
    paragraphs = []
    for item in items:
        para = (
            f"----- {item['group_name']} ({item['group_aliases']}/{item['group_id']}) -----\n"
            f"{item['group_url']}\n"
            f"{item['group_desc']}\n\n"
            f"This intrusion group applicable in:\n{item['group_domain']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def _format_relationships(items):
    paragraphs = []
    for item in items:
        para = (
            f"----- {item['source_ref_name']} ({item['source_ref_id']}) -----\n"
            f"{item['desc']}\n\n"
            f"Have relation with : {item['target_ref_name']} ({item['target_ref_id']})\n"
            f"Relation type : {item['relationship_type']}\n"
        )
        paragraphs.append(para)
    return paragraphs

def mitreUpdateLog(mitre_json, filename):
    formatters = {
    "course-of-action": _format_course_of_action,
    "malware": _format_malware,
    "tool": _format_tool,
    "attack-pattern": _format_attack_pattern,
    "campaign": _format_campaign,
    "intrusion-set": _format_intrusion_set,
    "relationship": _format_relationships,
    }

    mitre_data = mitre_json

    output_lines = []

    course_count = len(mitre_data.get("course-of-action", []))
    malware_count = len(mitre_data.get("malware", []))
    tool_count = len(mitre_data.get("tool", []))
    attack_pattern_count = len(mitre_data.get("attack-pattern", []))
    campaign_count = len(mitre_data.get("campaign", []))
    intrusion_set_count = len(mitre_data.get("intrusion-set", []))
    relationship_count = len(mitre_data.get("relationship", []))

    for section, entries in mitre_data.items():
        output_lines.append(f"\n{'='*80}\n{section.upper()} ({len(entries)} entries)\n{'='*80}\n")
        formatter = formatters.get(section)
        if formatter:
            paragraphs = formatter(entries)
            for para in paragraphs:
                output_lines.append(para + "\n")
        else:
            output_lines.append("No formatter defined for this section.\n")

    with open(filename, 'w+', encoding='utf-8') as out_file:
        out_file.write("\n".join(output_lines))

    msg_data = f"""<b>Changelog</b>:
    <b>Course of Action</b>: {course_count} entries
    <b>Malware</b>: {malware_count} entries
    <b>Tool</b>: {tool_count} entries
    <b>Attack Pattern</b>: {attack_pattern_count} entries
    <b>Campaign</b>: {campaign_count} entries
    <b>Intrusion Set</b>: {intrusion_set_count} entries
    <b>Relationship</b>: {relationship_count} entries
    <b>Total Entries</b>: {course_count + malware_count + tool_count + attack_pattern_count +  campaign_count + intrusion_set_count + relationship_count}"""
    
    return msg_data
