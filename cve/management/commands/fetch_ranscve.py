from django.core.management.base import BaseCommand
from django.db import connection
from tqdm import tqdm


from cve.datasources.db_importers import insert_ranscve
from cve.datasources import ranscve_importer

class Command(BaseCommand):
    help = "Fetch and update CVE exploits used in ransomware groups"

    def handle(self, *args, **options):
        cves = ranscve_importer.get_ransomware_vulnerability_data()
        with connection.cursor() as cursor:
            try:
                for cve_and_metadata in tqdm(cves):
                    insert_ranscve(cursor, cve_and_metadata['cve_id'])
            except Exception as e:
                print(f"Error inserting {cve_and_metadata}: {e}")
        self.stdout.write("Finished processing CVEs!")

