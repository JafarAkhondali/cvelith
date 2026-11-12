from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cve', '0040_auto_20250312_1235'),
    ]

    operations = [
        migrations.RunSQL(
            """
            DROP VIEW IF EXISTS unique_user_counts;
            CREATE OR REPLACE VIEW unique_user_counts AS (
            SELECT cve_id, count(DISTINCT user_id) AS total_unique_users
            FROM ghp_with_time
            GROUP BY cve_id)
""",
            reverse_sql="DROP VIEW IF EXISTS unique_user_counts;"
        ),
    ]