from django.core.management.base import BaseCommand
from django.db import connection
from tqdm import tqdm

from cve.datasources.db_importers import insert_msf
from cve.datasources import msf_importer

class Command(BaseCommand):
    help = "Fetch and update CVE exploits available in Metasploit"

    def handle(self, *args, **options):
        cves = msf_importer.get_metasploit_cves()
        with connection.cursor() as cursor:
            try:
                for cve in tqdm(cves):
                    insert_msf(cursor, cve)
            except Exception as e:
                print(f"Error inserting {cve}: {e}")
        self.stdout.write("Finished processing CVEs!")

