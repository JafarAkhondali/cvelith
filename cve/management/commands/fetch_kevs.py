import sys

import requests
from django.core.management.base import BaseCommand
from django.utils import timezone
from tqdm import tqdm
from cve.models import CVE, POC, Star, Fork, Watch, CVEPOCMapping
from cve.datasources import ssvc_api
import vulncheck_sdk
from cve.datasources.github_api import GitHubAPI
from cve.utils.textprocess import extract_cves
from cvevibes.settings import MAX_CVES_PER_REPO, VULNCHECK_TOKEN
from django.db import connection


def import_cisa_kev():
    KEV_BASE_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kevs = requests.get(KEV_BASE_URL).json()
    with connection.cursor() as cursor:
        for kev in kevs["vulnerabilities"]:
            ssvc_api.insert_kev(cursor, kev['cveID'], {
                "date_added": kev['dateAdded'],
                "organizer": "CISA",
            })


def import_vulncheck_kev():
    def process_vulncheck_kev(advisory):
        for cve_id in advisory.cve:
            with connection.cursor() as cursor:
                ssvc_api.insert_kev(cursor, cve_id, {
                    "date_added": advisory.date_added,
                    "organizer": "VulnCheck",
                })

    VULNCHECK_HOST = "https://api.vulncheck.com"
    VULNCHECK_API = VULNCHECK_HOST + "/v3"
    configuration = vulncheck_sdk.Configuration(host=VULNCHECK_API)
    configuration.api_key["Bearer"] = VULNCHECK_TOKEN
    with vulncheck_sdk.ApiClient(configuration) as api_client:
        indices_client = vulncheck_sdk.IndicesApi(api_client)
        api_response = indices_client.index_vulncheck_kev_get(
            start_cursor="true",
            limit=500
        )
        for advisory in api_response.data:
            process_vulncheck_kev(advisory)
        while api_response.meta.next_cursor is not None:
            api_response = indices_client.index_vulncheck_kev_get(
                cursor=api_response.meta.next_cursor
            )
            for advisory in api_response.data:
                process_vulncheck_kev(advisory)

#
# def import_attackerkb_kev():
#     vulners_api.insert_attackerkb_kev()


def import_kevs():
    print("[*] Importing CISA KEVs...")
    import_cisa_kev()
    print("[*] Importing Vulncheck KEVs...")
    import_vulncheck_kev()
    # print("[*] Importing AttackerKB KEVs...")
    # import_attackerkb_kev()



class Command(BaseCommand):
    help = "Fetch and update Known Exploited Vulnerabilities list."

    def handle(self, *args, **options):
        import_kevs()
        self.stdout.write("[*] Finished processing KEVs!")