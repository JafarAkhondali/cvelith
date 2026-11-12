from django.core.management.base import BaseCommand
from django.db import connection
from tqdm import tqdm

from cve.datasources.db_importers import insert_nuclei
from cve.datasources import nuclei_importer


class Command(BaseCommand):
    help = "Fetch and update CVE exploits available in Nuclei templates"

    def handle(self, *args, **options):
        cves = nuclei_importer.get_nuclei_cves()
        with connection.cursor() as cursor:
            try:
                for cve in tqdm(cves):
                    insert_nuclei(cursor, cve)
            except Exception as e:
                print(f"Error inserting {cve}: {e}")
        self.stdout.write("Finished processing CVEs!")

