from datetime import date
from django.db import connection, transaction
from django.utils.timezone import now
from cve.models import GpmDashboardCache

SQL_BADGES = r"""
WITH uit as MATERIALIZED (
    SELECT cve_id, interacted_time
    FROM ghp_with_time
),
total_gpm_cves AS (
    select distinct cve_id from interaction_counts
),
     latest_sync AS (
         SELECT MAX(interacted_time)::date AS date_time FROM uit
     ),
     gpm AS (
         SELECT cve_id, total_interactions as gpm from interaction_counts
     ),
     repos AS (
         SELECT COUNT(DISTINCT poc_id) AS repo_count
         FROM cve_cvepocmapping
     )
select jsonb_build_object(
               'total_gpm_cves', (SELECT COUNT(*)::bigint FROM total_gpm_cves),
               'latest_sync',    (SELECT * FROM latest_sync),
               'median_gpm',     (SELECT PERCENTILE_DISC(0.5) WITHIN GROUP (ORDER BY gpm) FROM gpm),
               'avg_gpm',     (SELECT ROUND(AVG(gpm),2) from gpm),
               'repo_count',     (SELECT repo_count FROM repos)
);
"""

@transaction.atomic
def get_or_compute_today_badges():
    # TODO: Maybe convert to a materialized view is better as we need to clear the cache if data is updated.
    today = date.today()
    # 1) Try read
    try:
        row = GpmDashboardCache.objects.get(pk=today)
        return row.badges
    except GpmDashboardCache.DoesNotExist:
        pass

    # 2) Compute once
    with connection.cursor() as cur:
        cur.execute(SQL_BADGES)
        badges = cur.fetchone()[0]  # JSONB

    # 3) Upsert (idempotent if concurrent callers)
    GpmDashboardCache.objects.update_or_create(
        snapshot_date=today,
        defaults={'badges': badges, 'version': 1},
    )
    return badges
