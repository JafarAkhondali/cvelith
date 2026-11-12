"""
Remove all GitHub user identifiers from the dataset.

- Drops Star.user_id, Fork.user_id, Watch.user_id and Fork.link (fork URLs contain usernames).
- GPM can no longer count distinct users, so it becomes a count of interactions
  (stars + forks + watches + one per PoC repo for its creation).
- `unique_user_counts` is replaced by `interaction_counts` (column `total_interactions`).
- The legacy `ghp_with_time_v2` / `unique_user_counts_v2` views (from 0058) are dropped.

The distinct-user GPM scores computed before this migration are frozen in the
`gpm_score_snapshot` table. This migration cannot restore the removed data on reverse.
"""
from django.db import migrations


DROP_GPM_VIEWS = """
DROP VIEW IF EXISTS unique_user_counts_v2;
DROP VIEW IF EXISTS ghp_with_time_v2;
DROP MATERIALIZED VIEW IF EXISTS unique_user_counts;
DROP MATERIALIZED VIEW IF EXISTS interaction_counts;
DROP MATERIALIZED VIEW IF EXISTS ghp_with_time;
"""

CREATE_GPM_VIEWS = """
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
)
SELECT m.cve_id, m.poc_id, 'star'::varchar(8) AS interaction_type, star.starred_at AS interacted_time
FROM filtered_mappings m
JOIN cve_star star ON star.poc_id = m.poc_id

UNION ALL

SELECT m.cve_id, m.poc_id, 'fork'::varchar(8), fork.forked_at
FROM filtered_mappings m
JOIN cve_fork fork ON fork.poc_id = m.poc_id

UNION ALL

SELECT m.cve_id, m.poc_id, 'watch'::varchar(8), watch.watched_at
FROM filtered_mappings m
JOIN cve_watch watch ON watch.poc_id = m.poc_id

UNION ALL

SELECT m.cve_id, m.poc_id, 'poc'::varchar(8), poc.repo_created_at
FROM filtered_mappings m
JOIN cve_poc poc ON poc.id = m.poc_id;

CREATE INDEX ghp_with_time_cve_interacted_idx ON ghp_with_time (cve_id, interacted_time);
CREATE INDEX ghp_with_time_interacted_idx ON ghp_with_time (interacted_time);

CREATE MATERIALIZED VIEW interaction_counts AS
SELECT cve_id, COUNT(*) AS total_interactions
FROM ghp_with_time
GROUP BY cve_id;

CREATE UNIQUE INDEX interaction_counts_cve_idx ON interaction_counts (cve_id);
"""


class Migration(migrations.Migration):

    dependencies = [
        ("cve", "0068_fix_uuc_view"),
    ]

    operations = [
        # Views depend on the user_id columns, so drop them first.
        migrations.RunSQL(sql=DROP_GPM_VIEWS, reverse_sql=migrations.RunSQL.noop),

        migrations.RemoveConstraint(model_name="star", name="unique_poc_user"),
        migrations.RemoveField(model_name="star", name="user_id"),
        migrations.RemoveField(model_name="fork", name="user_id"),
        migrations.RemoveField(model_name="fork", name="link"),
        migrations.RemoveField(model_name="watch", name="user_id"),

        migrations.RunSQL(sql=CREATE_GPM_VIEWS, reverse_sql=DROP_GPM_VIEWS),
    ]
