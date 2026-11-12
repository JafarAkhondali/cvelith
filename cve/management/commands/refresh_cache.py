from django.core.management.base import BaseCommand
from django.db import connection

MATERIALIZED_VIEWS = [
    "ghp_with_time",
    "cve_cvss_max",
    "interaction_counts",
]

class Command(BaseCommand):
    help = "Refresh PostgreSQL materialized views safely."

    def handle(self, *args, **options):
        with connection.cursor() as cursor:
            for mv in MATERIALIZED_VIEWS:
                self.stdout.write(self.style.NOTICE(f"Refreshing {mv}..."))

                try:
                    cursor.execute(f"REFRESH MATERIALIZED VIEW {mv};")
                    self.stdout.write(self.style.SUCCESS(f"✔ Refreshed {mv} "))
                except Exception as e:
                    # If concurrent refresh fails (because MV has no unique index)
                    if "cannot refresh materialized view" in str(e).lower():
                        self.stdout.write(self.style.WARNING(
                            f"⚠ {mv} has no unique index. Falling back to NON-concurrent refresh..."
                        ))
                        cursor.execute(f"REFRESH MATERIALIZED VIEW {mv};")
                        self.stdout.write(self.style.SUCCESS(f"✔ Refreshed {mv} (non-concurrent)"))
                    else:
                        self.stdout.write(self.style.ERROR(f"❌ Error refreshing {mv}: {e}"))
                        raise e
