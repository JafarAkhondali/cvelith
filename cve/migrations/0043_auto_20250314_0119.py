from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cve', '0042_msf_nuclei'),
    ]

    operations = [
        migrations.RunSQL(
            """
CREATE OR REPLACE VIEW ghp_with_time AS
WITH user_interactions_with_time AS (
    WITH filtered_mappings AS (
        SELECT cve_cvepocmapping.cve_id, cve_cvepocmapping.poc_id AS poc_id
        FROM cve_cvepocmapping, cve_poc , cve_cve
        where
            cve_cvepocmapping.cve_id = cve_cve.id
          AND
            cve_cvepocmapping.poc_id = cve_poc.id
          AND
            cve_count = 1
          AND
            cve_poc.repo_created_at >= COALESCE(cve_cve.date_reserved, cve_poc.repo_created_at)
    )
    SELECT DISTINCT m.cve_id, star.user_id, star.starred_at AS interacted_time
    FROM filtered_mappings m
             JOIN cve_star star ON m.poc_id = star.poc_id
    
    UNION ALL
    
        SELECT DISTINCT m.cve_id, fork.user_id, fork.forked_at AS interacted_time
    FROM filtered_mappings m
             JOIN cve_fork fork ON m.poc_id = fork.poc_id
    
    UNION ALL
    
        SELECT DISTINCT m.cve_id, watch.user_id, watch.watched_at AS interacted_time
    FROM filtered_mappings m
             JOIN cve_watch watch ON m.poc_id = watch.poc_id
    UNION ALL
        SELECT DISTINCT filtered_mappings.cve_id,
        '-1'::varchar(200) as user_id,
        cve_poc.repo_created_at AS interacted_time
        from filtered_mappings, cve_poc
        where cve_poc.id = filtered_mappings.poc_id
                                         )
    SELECT cve_id,
           user_id,
           interacted_time
    FROM user_interactions_with_time 
""",
            reverse_sql="DROP VIEW IF EXISTS ghp_with_time;"
        ),
    ]
