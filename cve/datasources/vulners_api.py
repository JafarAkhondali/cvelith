import io
import json
import zipfile
from django.db import connection

from vulners import VulnersApi
from cve.datasources.db_importers import insert_kev
from cve.utils.textprocess import extract_cves
from cvevibes import settings

VULNERSCOM_TOKEN = settings.VULNERSCOM_TOKEN
if not VULNERSCOM_TOKEN:
    raise ValueError("VULNERSCOM_TOKEN not set")

# Initialize Vulners SDK client
vulners_client = VulnersApi(api_key=VULNERSCOM_TOKEN)

def download_attackerkb_dump():
    # Get archive metadata via SDK
    return vulners_client.archive.fetch_collection("attackerkb")

def insert_attackerkb_kev():
    exploited = set()
    for item in download_attackerkb_dump():
        if not item.get('wildExploited', False):
            continue

        cve_list = extract_cves(item.get('title', ''))
        if len(cve_list) > 0:
            exploited.update(set(cve_list[0:1]))

    with connection.cursor() as cursor:
        for cve_id in exploited:
            insert_kev(cursor, cve_id, {'date_added': None,'organizer':'AttackerKB'})
