"""Seed script: insert all global countries into the 'global-country' collection.

Run from repo root:
    python scripts/seed_global_countries.py

Skips countries already present (upsert by name).
Does NOT modify the existing 'apac-country' collection.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pymongo import MongoClient, UpdateOne
import yaml

with open("config/config.yml", 'r') as f:
    cfg = yaml.safe_load(f)

mc  = cfg['mongodb']
uri = (
    f"mongodb://{mc['user']}:{mc['pass']}@{mc['ip']}/"
    f"?authSource={mc['cluster']}&authMechanism=SCRAM-SHA-256"
)
client = MongoClient(uri)
col    = client[mc['collection']]['global-country']
col.create_index("name", unique=True, background=True)

COUNTRIES = [
    # Africa
    "Algeria", "Angola", "Benin", "Botswana", "Burkina Faso", "Burundi",
    "Cabo Verde", "Cameroon", "Central African Republic", "Chad", "Comoros",
    "Congo", "Democratic Republic of the Congo", "Djibouti", "Egypt",
    "Equatorial Guinea", "Eritrea", "Eswatini", "Ethiopia", "Gabon", "Gambia",
    "Ghana", "Guinea", "Guinea-Bissau", "Ivory Coast", "Kenya", "Lesotho",
    "Liberia", "Libya", "Madagascar", "Malawi", "Mali", "Mauritania",
    "Mauritius", "Morocco", "Mozambique", "Namibia", "Niger", "Nigeria",
    "Rwanda", "Sao Tome and Principe", "Senegal", "Seychelles", "Sierra Leone",
    "Somalia", "South Africa", "South Sudan", "Sudan", "Tanzania", "Togo",
    "Tunisia", "Uganda", "Zambia", "Zimbabwe",
    # Americas
    "Antigua and Barbuda", "Argentina", "Bahamas", "Barbados", "Belize",
    "Bolivia", "Brazil", "Canada", "Chile", "Colombia", "Costa Rica", "Cuba",
    "Dominica", "Dominican Republic", "Ecuador", "El Salvador", "Grenada",
    "Guatemala", "Guyana", "Haiti", "Honduras", "Jamaica", "Mexico",
    "Nicaragua", "Panama", "Paraguay", "Peru", "Saint Kitts and Nevis",
    "Saint Lucia", "Saint Vincent and the Grenadines", "Suriname",
    "Trinidad and Tobago", "United States", "Uruguay", "Venezuela",
    # Asia (APAC already in apac-country; included here for completeness)
    "Afghanistan", "Armenia", "Azerbaijan", "Bahrain", "Bangladesh", "Bhutan",
    "Brunei", "Cambodia", "China", "Cyprus", "Georgia", "India", "Indonesia",
    "Iran", "Iraq", "Israel", "Japan", "Jordan", "Kazakhstan", "Kuwait",
    "Kyrgyzstan", "Laos", "Lebanon", "Malaysia", "Maldives", "Mongolia",
    "Myanmar", "Nepal", "North Korea", "Oman", "Pakistan", "Palestine",
    "Philippines", "Qatar", "Saudi Arabia", "Singapore", "South Korea",
    "Sri Lanka", "Syria", "Taiwan", "Tajikistan", "Thailand", "Timor-Leste",
    "Turkmenistan", "United Arab Emirates", "Uzbekistan", "Vietnam", "Yemen",
    # Europe
    "Albania", "Andorra", "Austria", "Belarus", "Belgium", "Bosnia and Herzegovina",
    "Bulgaria", "Croatia", "Czech Republic", "Denmark", "Estonia", "Finland",
    "France", "Germany", "Greece", "Hungary", "Iceland", "Ireland", "Italy",
    "Kosovo", "Latvia", "Liechtenstein", "Lithuania", "Luxembourg", "Malta",
    "Moldova", "Monaco", "Montenegro", "Netherlands", "North Macedonia",
    "Norway", "Poland", "Portugal", "Romania", "Russia", "San Marino",
    "Serbia", "Slovakia", "Slovenia", "Spain", "Sweden", "Switzerland",
    "Turkey", "Ukraine", "United Kingdom", "Vatican City",
    # Oceania
    "Australia", "Fiji", "Kiribati", "Marshall Islands", "Micronesia", "Nauru",
    "New Zealand", "Palau", "Papua New Guinea", "Samoa", "Solomon Islands",
    "Tonga", "Tuvalu", "Vanuatu",
]

ops = [
    UpdateOne({"name": c}, {"$setOnInsert": {"name": c}}, upsert=True)
    for c in COUNTRIES
]
result = col.bulk_write(ops, ordered=False)
client.close()

print(
    f"global-country: {result.upserted_count} inserted | "
    f"{result.matched_count} already existed | "
    f"{len(COUNTRIES)} total"
)
