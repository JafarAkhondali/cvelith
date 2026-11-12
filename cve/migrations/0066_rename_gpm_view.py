from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ("cve", "0065_cvss_materialized_views"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            ----------------------------------------------------------
            -- DROP IF EXISTS (safe for re-run)
            ----------------------------------------------------------
            DROP MATERIALIZED VIEW IF EXISTS total_unique_users;

            ----------------------------------------------------------
            -- CREATE MATERIALIZED VIEW
            -- Fast "unique_user_counts" using DISTINCT ON
            ----------------------------------------------------------
            CREATE MATERIALIZED VIEW unique_user_counts AS
            SELECT
                cve_id,
                COUNT(DISTINCT user_id) AS total_unique_users
            FROM ghp_with_time
            GROUP BY cve_id;

            -- Index enables CONCURRENT refresh
            CREATE UNIQUE INDEX total_unique_users_counts_idx
                ON unique_user_counts (cve_id);
            """,

            reverse_sql="""
            DROP MATERIALIZED VIEW IF EXISTS unique_user_counts;
            """
        )
    ]
