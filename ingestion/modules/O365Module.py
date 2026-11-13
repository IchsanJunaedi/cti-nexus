from O365 import Account
import yaml, requests, os, base64

with open("config/config.yml", 'r') as config_data:
    cfg = yaml.safe_load(config_data)

TENANT_ID = cfg['azure']['tenant_id']
CLIENT_ID = cfg['azure']['client_id']
CLIENT_SECRET = cfg['azure']['client_secret']

credentials = (CLIENT_ID, CLIENT_SECRET)

account = Account(credentials, auth_flow_type="credentials", tenant_id=TENANT_ID)

if not account.is_authenticated:
    account.authenticate()

def uploadFileToSharepoint(sites_name, folder_path, file_name):
    sharepoint = account.sharepoint()

    site_domain = os.getenv("SHAREPOINT_DOMAIN", "contoso.sharepoint.com")
    site = sharepoint.get_site(site_domain, f"sites/{sites_name}")

    drive = site.get_default_document_library()

    items = drive.get_item_by_path(folder_path).upload_file(item=file_name)
    try:
        print(items.web_url)
    except requests.exceptions.ConnectionError:
        print("Failed to upload")

def downloadFileFromSharepoint(sites_name, file_path, output_path, output_filename):
    sharepoint = account.sharepoint()

    site_domain = os.getenv("SHAREPOINT_DOMAIN", "contoso.sharepoint.com")
    site = sharepoint.get_site(site_domain, f"sites/{sites_name}")
    drive = site.get_default_document_library()
    items = drive.get_item_by_path(file_path).download(to_path=output_path)

    output_filename = output_filename + "." + file_path.split(".")[-1]

    source_file = output_path + file_path.split("/")[-1]
    os.rename(source_file, output_filename)

def listFileFromSharepoint(sites_name, file_path):
    sharepoint = account.sharepoint()

    site_domain = os.getenv("SHAREPOINT_DOMAIN", "contoso.sharepoint.com")
    site = sharepoint.get_site(site_domain, f"sites/{sites_name}")
    drive = site.get_default_document_library()
    items = drive.get_item_by_path(file_path).get_items()

    json_list = []
    for file in items:
        file_name = file.name
        file_created_by = str(file.created_by)
        file_created = str(file.created)
        file_modified = file.modified
        file_modified_by = file.modified_by

        json_data = {
            "file_name": file_name,
            "file_created_by": file_created_by,
            "file_created": file_created,
            "file_modified": file_modified,
            "file_modified_by": file_modified_by,
            "file_url": file_path + file_name
        }
        json_list.append(json_data)
    
    return json_list

def createFolderSharepoint(sites_name, file_path, folder_name):
    sharepoint = account.sharepoint()

    site_domain = os.getenv("SHAREPOINT_DOMAIN", "contoso.sharepoint.com")
    site = sharepoint.get_site(site_domain, f"sites/{sites_name}")
    drive = site.get_default_document_library()
    items = drive.get_item_by_path(file_path).create_child_folder(name=folder_name)

    print(items)

def downloadFileFromOneDrive(email, file_path, output_path, output_filename):
    storage = account.storage(resource=email)
    drive = storage.get_default_drive()

    if file_path.startswith("/"):
        file_path = file_path[1:]

    item = drive.get_item_by_path(file_path)
    item.download(to_path=output_path)

    output_filename = output_filename + "." + file_path.split(".")[-1]

    source_file = output_path + file_path.split("/")[-1]
    os.rename(source_file, output_filename)

def downloadFileFromSharelink(share_link, local_file_path):
    credentials = ('client_id', 'client_secret')
    account = Account(credentials, auth_flow_type="credentials", tenant_id=TENANT_ID)

    if not account.is_authenticated:
        account.authenticate()

    con = account.con

    encoded = base64.urlsafe_b64encode(share_link.encode("utf-8")).decode("utf-8").rstrip("=")
    url = f"https://graph.microsoft.com/v1.0/shares/u!{encoded}/driveItem"

    resp = con.get(url)
    resp.raise_for_status()
    item = resp.json()

    download_url = item["@microsoft.graph.downloadUrl"]
    file_bytes = con.session.get(download_url).content

    with open(local_file_path, "wb") as f:
        f.write(file_bytes)

# downloadFileFromSharelink("https://contoso-my.sharepoint.com/:x:/r/personal/soc_team/Documents/Sample.xlsx", "./sample.xlsx")
# downloadFileFromOneDrive("operator@cti-nexus.local", "Documents/CTILifecycle.drawio.png", "./", "lifecycle")

# data = listFileFromSharepoint("SOC-Teams", "/Indicator of Compromise (IoC)/Data/") # Example list all file from a folder

# downloadFileFromSharepoint("SOC-Teams", "/Indicator of Compromise (IoC)/Data/tunneling.json", "./", "data_tunnel") # Example download from folder
