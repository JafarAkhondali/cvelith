from django.core.management.base import BaseCommand
from django.db import connection
import os
from subprocess import call
class Command(BaseCommand):
    help = "Fetch and update EPSS historical data"

    def handle(self, *args, **options):
        call(["bash", "./cve/scripts/init_epss.sh"])
        csv_path = './cve/tmpstorage/epss-data/epss_combined.csv'

        # Validate CSV file
        if not os.path.exists(csv_path):
            self.stderr.write(f"Error: CSV file not found at {csv_path}")
            return

        self.stdout.write("Deleting existing EPSS data...")
        self.clear_table()

        self.stdout.write("Inserting new EPSS data using PostgreSQL COPY...")
        self.load_csv_into_database(csv_path)

        self.stdout.write("Finished processing CVEs!")

    def clear_table(self):
        """
        Deletes all data from the EPSS table.
        """
        with connection.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE cve_epss RESTART IDENTITY;")
            self.stdout.write("Existing data cleared.")

    def load_csv_into_database(self, csv_path):
        """
        Efficiently loads the CSV data into the database using PostgreSQL COPY.
        :param csv_path: Path to the CSV file
        """
        with connection.cursor() as cursor:
            try:
                connection.autocommit = False  # Disable autocommit
                with open(csv_path, 'r') as csv_file:
                    cursor.copy_expert(
                        "COPY cve_epss(cve, epss, date) FROM STDIN WITH CSV HEADER", csv_file
                    )
                connection.commit()  # Commit after copying all data

            finally:
                connection.autocommit = False  # Disable autocommit

    def handle_corrupted_data(self, csv_path):
        """
        Handles rows that failed to import due to data inconsistencies.
        :param csv_path: Path to the CSV file
        """
        with connection.cursor() as cursor, open(csv_path, 'r') as file:
            header = next(file)  # Skip the header
            for line_number, row in enumerate(file, start=2):  # Start at 2 since header is line 1
                if row.strip():  # Skip empty lines
                    try:
                        cursor.copy_expert("COPY tmp_epss FROM STDIN WITH CSV", row)
                    except Exception as e:
                        self.stderr.write(f"Skipped malformed row {line_number}: {row.strip()} due to: {e}")
