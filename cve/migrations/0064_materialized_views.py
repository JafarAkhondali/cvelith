from django.db import migrations

class Migration(migrations.Migration):

    dependencies = [
        ("cve", "0063_cvss_cve_id_version"),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
            -------------------------------------------------------------
            -- 1. DROP OLD VIEWS (if they exist)
            -------------------------------------------------------------
            DROP VIEW IF EXISTS ghp_with_time CASCADE;
            DROP VIEW IF EXISTS total_unique_users CASCADE;

            -------------------------------------------------------------
            -- 2. CREATE MATERIALIZED VIEW: ghp_with_time
            -------------------------------------------------------------
            CREATE MATERIALIZED VIEW ghp_with_time AS
            WITH filtered_mappings AS (
                SELECT
                    cve_cvepocmapping.cve_id,
                    cve_cvepocmapping.poc_id
                FROM cve_cvepocmapping
                JOIN cve_poc ON cve_poc.id = cve_cvepocmapping.poc_id
                JOIN cve_cve ON cve_cve.id = cve_cvepocmapping.cve_id
                WHERE
                    cve_poc.cve_count = 1
                    AND cve_poc.repo_created_at >= COALESCE(cve_cve.date_reserved, cve_poc.repo_created_at)
            ),
            user_interactions_with_time AS (
                SELECT DISTINCT m.cve_id, star.user_id, star.starred_at AS interacted_time
                FROM filtered_mappings m
                JOIN cve_star star ON star.poc_id = m.poc_id

                UNION ALL

                SELECT DISTINCT m.cve_id, fork.user_id, fork.forked_at AS interacted_time
                FROM filtered_mappings m
                JOIN cve_fork fork ON fork.poc_id = m.poc_id

                UNION ALL

                SELECT DISTINCT m.cve_id, watch.user_id, watch.watched_at AS interacted_time
                FROM filtered_mappings m
                JOIN cve_watch watch ON watch.poc_id = m.poc_id

                UNION ALL

                SELECT DISTINCT m.cve_id, '-1'::varchar(200) AS user_id, poc.repo_created_at AS interacted_time
                FROM filtered_mappings m
                JOIN cve_poc poc ON poc.id = m.poc_id
            )
            SELECT
                cve_id,
                user_id,
                interacted_time
            FROM user_interactions_with_time;

            -- Indexes for faster refresh + queries
            CREATE INDEX ghp_with_time_cve_interacted_idx
                ON ghp_with_time (cve_id, interacted_time);

            CREATE INDEX ghp_with_time_interacted_idx
                ON ghp_with_time (interacted_time);

            -------------------------------------------------------------
            -- 3. CREATE MATERIALIZED VIEW: total_unique_users
            -------------------------------------------------------------
            CREATE MATERIALIZED VIEW total_unique_users AS
            SELECT
                cve_id,
                COUNT(DISTINCT user_id) AS total_unique_users
            FROM ghp_with_time
            GROUP BY cve_id;

            -- Index enables CONCURRENT refresh
            CREATE UNIQUE INDEX total_unique_users_cve_idx
                ON total_unique_users (cve_id);
            """,

            reverse_sql="""
            DROP MATERIALIZED VIEW IF EXISTS total_unique_users;
            DROP MATERIALIZED VIEW IF EXISTS ghp_with_time;
            """
        )
    ]
