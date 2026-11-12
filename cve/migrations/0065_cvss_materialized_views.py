from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ("cve", "0064_materialized_views"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            ----------------------------------------------------------
            -- DROP IF EXISTS (safe for re-run)
            ----------------------------------------------------------
            DROP MATERIALIZED VIEW IF EXISTS cve_cvss_max;

            ----------------------------------------------------------
            -- CREATE MATERIALIZED VIEW
            -- Fast "latest version per CVE" using DISTINCT ON
            ----------------------------------------------------------
            CREATE MATERIALIZED VIEW cve_cvss_max AS
            SELECT DISTINCT ON (cve_id)
                cve_id,
                version,
                base_score,
                base_severity,
                vector_string
            FROM cve_cvss
            ORDER BY
                cve_id,
                CAST(version AS DECIMAL(3,1)) DESC;

            ----------------------------------------------------------
            -- ADD UNIQUE INDEX (required for fast joins and optional CONCURRENT REFRESH)
            ----------------------------------------------------------
            CREATE UNIQUE INDEX cve_cvss_max_cve_id_idx
                ON cve_cvss_max (cve_id);
            """,

            reverse_sql="""
            DROP MATERIALIZED VIEW IF EXISTS cve_cvss_max;
            """
        )
    ]
