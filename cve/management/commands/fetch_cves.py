import sys

from django.core.management.base import BaseCommand
from django.utils import timezone
from tqdm import tqdm
from cve.models import CVE, POC, Star, Fork, Watch, CVEPOCMapping
from cve.datasources import ssvc_api
from cve.datasources.github_api import GitHubAPI
from cve.datasources import nvd_api
from cve.utils.textprocess import extract_cves
from cvevibes.settings import MAX_CVES_PER_REPO

class Command(BaseCommand):
    help = "Fetch and update CVEs and their description, references, etc, using NVD dumps"

    def add_arguments(self, parser):
        parser.add_argument('start_year', type=int, help="Start year for CVE search pattern")
        parser.add_argument('end_year', type=int, help="End year for CVE search pattern")

    def handle(self, *args, **options):
        start_year = options['start_year']
        end_year = options['end_year']

        # First fill CWE table to prevent foreign key errors
        ssvc_api.import_cwes()



        if start_year < 2002:
            print("Warning: Year 2001 and before are not available in NVD dataset")
        nvd_api.import_cves(max(2002, start_year), end_year)

        # SSVC must always come in second place, the reason is the richer format(e.g. CVE reject status, reserver date)
        ssvc_api.import_cves(start_year, end_year)

        self.stdout.write("Finished processing CVEs!")

